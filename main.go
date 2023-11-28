package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/term"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

func main() {
	var useMem bool
	var passEncrypt bool
	var passDecrypt bool
	flag.BoolVar(&useMem, "use-mem", false, "use a memory bucket to calculate MD5s")
	flag.BoolVar(&passEncrypt, "encrypt", false, "encrypt the data with the given key")
	flag.BoolVar(&passDecrypt, "decrypt", false, "decrypt the data with the given key")
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatal("src and dst arguments are required")
	}
	var bytesEncrypt []byte
	var bytesDecrypt []byte
	if passEncrypt {
		bytesEncrypt = getAuthentication()
		useMem = true
	}
	if passDecrypt {
		bytesDecrypt = getAuthentication()
		useMem = true
	}

	src := flag.Arg(0)
	dst := flag.Arg(1)

	ctx := context.Background()
	sbkt, err := blob.OpenBucket(ctx, src)
	if err != nil {
		log.Fatal(err)
	}
	defer sbkt.Close()

	dbkt, err := blob.OpenBucket(ctx, dst)
	if err != nil {
		log.Fatal(err)
	}
	defer dbkt.Close()

	if err := mirror(ctx, sbkt, dbkt, useMem, bytesEncrypt, bytesDecrypt); err != nil {
		log.Fatal(err)
	}
}

// copies all objects from src to dst.
func mirror(ctx context.Context, sbkt, dbkt *blob.Bucket, useMem bool, bytesEncrypt, bytesDecrypt []byte) error {
	tmpBkt, err := blob.OpenBucket(ctx, "mem://")
	if err != nil {
		return err
	}
	iter := sbkt.List(nil)
	// it won't run on the last iteration, but that's fine.
	cleanloop := func() {}
	for {
		cleanloop()
		obj, err := iter.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		sattrs, err := sbkt.Attributes(ctx, obj.Key)
		if err != nil {
			return err
		}
		// if we're using a memory bucket, first copy the object to the memory bucket
		// and this will calculate the MD5 for us.
		// csbkt and sattrs will be updated to point to the temporary bucket in that case.
		csbkt := sbkt
		objKey := obj.Key
		if useMem {
			log.Println("loading to memory", obj.Key)
			_, newKey, err := copyObj(ctx, sbkt, tmpBkt, obj.Key, bytesEncrypt, bytesDecrypt)
			if err != nil {
				return err
			}
			csbkt = tmpBkt
			sattrs, _ = csbkt.Attributes(ctx, newKey)
			objKey = newKey
			cleanloop = func() {
				log.Println("unloading from memory", obj.Key)
				if err := tmpBkt.Delete(ctx, newKey); err != nil {
					log.Println("error deleting", obj.Key, "from memory bucket:", err)
				}
			}
		}
		log.Println("done copying to memory")

		// check if file exists in the destination
		exists, err := dbkt.Exists(ctx, objKey)
		if err != nil {
			return err
		}
		// if it exists, check if the md5 matches
		if exists {
			dattrs, err := dbkt.Attributes(ctx, objKey)
			if err != nil {
				return err
			}
			if matchMD5(sattrs.MD5, dattrs.MD5) {
				continue
			}
		}
		// either it doesn't exist, or the MD5 doesn't match. copy it.
		log.Printf("copying to destination %s [%s] size %d\n", obj.Key, objKey, sattrs.Size)
		n, _, err := copyObj(ctx, csbkt, dbkt, objKey, []byte{}, []byte{})
		if err != nil {
			return err
		}
		log.Printf("copied to destination %s [%s] size %d\n", obj.Key, objKey, n)
	}
	return nil
}

// matchMD5 returns true if md51 and md52 are equal.
func matchMD5(md51, md52 []byte) bool {
	if len(md51) != len(md52) {
		return false
	}
	for i := range md51 {
		if md51[i] != md52[i] {
			return false
		}
	}
	return true
}

// copy object refereced by key from src to dst buckets.
func copyObj(ctx context.Context, src, dst *blob.Bucket, key string, bytesEncrypt, bytesDecrypt []byte) (int, string, error) {
	newKey := makeKey(key, bytesEncrypt, bytesDecrypt)
	srcr, err := src.NewReader(ctx, key, nil)
	if err != nil {
		return 0, "", err
	}
	defer srcr.Close()

	beforeText, err := io.ReadAll(srcr)
	if err != nil {
		return 0, "", err
	}
	newText := encrypt(beforeText, bytesEncrypt)
	newText = decrypt(newText, bytesDecrypt)

	dstw, err := dst.NewWriter(ctx, newKey, nil)
	if err != nil {
		return 0, "", err
	}

	n, err := dstw.Write(newText)
	if err != nil {
		return 0, "", err
	}
	return n, newKey, dstw.Close()
}

func encrypt(text []byte, key []byte) []byte {
	if len(key) == 0 {
		return text
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}
	// this is not secure.
	// doing this so we have a consistent hash and filename for the same input
	md5sum := md5.Sum(text)
	nonce := md5sum[:gcm.NonceSize()]
	return gcm.Seal(nonce, nonce, text, nil)
}

func decrypt(cyphertext []byte, key []byte) []byte {
	if len(key) == 0 {
		return cyphertext
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}
	nonceSize := gcm.NonceSize()
	nonce, cyphertext := cyphertext[:nonceSize], cyphertext[nonceSize:]
	text, err := gcm.Open(nil, nonce, cyphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return text
}

func makeKey(oldKey string, bytesEncrypt, bytesDecrypt []byte) string {
	newKey := oldKey
	if len(bytesEncrypt) != 0 {
		encryptedKey := encrypt([]byte(newKey), bytesEncrypt)
		newKey = base64.URLEncoding.EncodeToString(encryptedKey)
	}
	if len(bytesDecrypt) != 0 {
		decodedKey, err := base64.URLEncoding.DecodeString(newKey)
		if err != nil {
			log.Fatal(err)
		}
		decryptedKey := decrypt(decodedKey, bytesDecrypt)
		newKey = string(decryptedKey)
	}
	return newKey
}

func getAuthentication() []byte {
	pass, ok := os.LookupEnv("BLOBCOPY_ENCRYPTION_PASSWORD")
	if !ok {
		fmt.Println("Enter Password:")
		bytepass1, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal(err)
		}
		pass1 := string(bytepass1)
		fmt.Println("Enter it one more time:")
		bytepass2, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal(err)
		}
		pass2 := string(bytepass2)
		if pass1 != pass2 {
			log.Fatal("passwords don't match")
		}
		pass = string(pass1)
	}
	md5sum := md5.Sum([]byte(pass))
	md5sum2 := md5.Sum(md5sum[:])
	return append(md5sum2[:], md5sum[:]...)
}
