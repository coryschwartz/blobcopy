package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"gocloud.dev/gcerrors"

	"golang.org/x/term"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

var (
	ErrPasswordMismatch = errors.New("passwords do not match")
	errLogger           = log.New(os.Stderr, "", log.Flags())
	logger              = log.New(os.Stdout, "", log.Flags())
)

func main() {
	var useTmp string
	var passEncrypt bool
	var passDecrypt bool
	var useSafety bool
	var genSafety bool
	var skipN int
	flag.StringVar(&useTmp, "tmp-bkt", "", "use a temporary bucket -- can be useful for calculating md5s")
	flag.IntVar(&skipN, "skip", 0, "skip the first N files")
	flag.BoolVar(&passEncrypt, "encrypt", false, "encrypt the data with the given key")
	flag.BoolVar(&passDecrypt, "decrypt", false, "decrypt the data with the given key")
	flag.BoolVar(&useSafety, "safety", false, "enable safety check")
	flag.BoolVar(&genSafety, "gen-safety", false, "enable safety check")
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatal("src and dst arguments are required")
	}
	var bytesAuth []byte
	var bytesEncrypt []byte
	var bytesDecrypt []byte
	if passEncrypt || passDecrypt {
		if useTmp == "" {
			useTmp = "mem://"
		}
		var err error
		bytesAuth, err = getAuthentication()
		if err != nil {
			os.Exit(1)
		}
	}
	if passEncrypt {
		bytesEncrypt = bytesAuth
	}
	if passDecrypt {
		bytesDecrypt = bytesAuth
	}

	src := flag.Arg(0)
	dst := flag.Arg(1)

	start := time.Now()
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
	if useSafety {
		pass, err := safetyCheck(ctx, dbkt, bytesEncrypt)
		if err != nil {
			log.Fatal(err)
		}
		if !pass {
			log.Printf("safety check failed.")
			if !genSafety {
				log.Printf("use --gen-safety to generate a safety check with this password.")
				os.Exit(1)
			}
			log.Printf("generating safety check.")
			err = enableSafetyCheck(ctx, dbkt, bytesEncrypt)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	var tmpBkt *blob.Bucket
	if useTmp != "" {
		tmpBkt, err = blob.OpenBucket(ctx, useTmp)
	}
	if err != nil {
		log.Fatal(err)
	}

	errs := make(chan error)
	errsN := 0
	stopErrs := make(chan bool)
	errsStopped := make(chan bool)
	go func() {
		for {
			select {
			case err := <-errs:
				errLogger.Println(err)
				errsN++
			case <-stopErrs:
				close(errsStopped)
				return
			}
		}
	}()

	n := mirror(ctx, sbkt, dbkt, tmpBkt, bytesEncrypt, bytesDecrypt, skipN, errs)
	close(stopErrs)
	<-errsStopped
	logger.Printf("copied %d objects. %d errors. duration: %v\n", n, errsN, time.Since(start))
}

// copies all objects from src to dst.
func mirror(ctx context.Context, sbkt, dbkt, tmpBkt *blob.Bucket, bytesEncrypt, bytesDecrypt []byte, skipN int, errs chan error) int {
	iter := sbkt.List(nil)
	// cleanloop won't run on the last iteration, but that's fine.
	cleanloop := func() {}
	loopN := 0
	addedN := 0
	for {
		cleanloop()
		loopN++
		obj, err := iter.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			errs <- fmt.Errorf("error iterating: %w", err)
			continue
		}
		if loopN <= skipN {
			continue
		}

		sattrs, err := sbkt.Attributes(ctx, obj.Key)
		if err != nil {
			errs <- fmt.Errorf("unable to get attributes for %s: %w", obj.Key, err)
			continue
		}
		// if we're using a memory bucket, first copy the object to the memory bucket
		// and this will calculate the MD5 for us.
		// csbkt and sattrs will be updated to point to the temporary bucket in that case.
		csbkt := sbkt
		objKey := obj.Key
		if tmpBkt != nil {
			logger.Printf("[%d] loading to temporary bucket %s\n", loopN, obj.Key)
			_, newKey, err := copyObj(ctx, sbkt, tmpBkt, obj.Key, bytesEncrypt, bytesDecrypt)
			if err != nil {
				errs <- fmt.Errorf("error copying object to tmp bucket %s: %w", obj.Key, err)
				continue
			}
			csbkt = tmpBkt
			sattrs, _ = csbkt.Attributes(ctx, newKey)
			objKey = newKey
			cleanloop = func() {
				logger.Printf("[%d] deleting from temporary bucket %s\n", loopN, obj.Key)
				if err := tmpBkt.Delete(ctx, newKey); err != nil {
					errs <- fmt.Errorf("error deleting %s from temporary bucket: %w", obj.Key, err)
				}
			}
		}

		// check if file exists in the destination
		exists, err := dbkt.Exists(ctx, objKey)
		if err != nil {
			errs <- fmt.Errorf("error checking if %s exists in destination: %w", obj.Key, err)
			continue
		}
		// if it exists, check if the md5 matches
		if exists {
			dattrs, err := dbkt.Attributes(ctx, objKey)
			if err != nil {
				errs <- fmt.Errorf("error getting attributes for %s in destination: %w", obj.Key, err)
				continue
			}
			if string(sattrs.MD5) == string(dattrs.MD5) {
				continue
			}
		}
		// either it doesn't exist, or the MD5 doesn't match. copy it.
		logger.Printf("[%d] copying to destination %s [%s] size %d\n", loopN, obj.Key, objKey, sattrs.Size)
		n, _, err := copyObj(ctx, csbkt, dbkt, objKey, []byte{}, []byte{})
		if err != nil {
			errs <- fmt.Errorf("error copying object to destination %s: %w", obj.Key, err)
			continue
		}
		addedN++
		logger.Printf("[%d] copied to destination %s [%s] size %d\n", loopN, obj.Key, objKey, n)
	}
	return addedN
}

// copy object refereced by key from src to dst buckets.
func copyObj(ctx context.Context, src, dst *blob.Bucket, key string, bytesEncrypt, bytesDecrypt []byte) (int, string, error) {
	newKey, err := makeKey(key, bytesEncrypt, bytesDecrypt)
	if err != nil {
		return 0, "", err
	}

	srcr, err := src.NewReader(ctx, key, nil)
	if err != nil {
		return 0, "", err
	}
	defer srcr.Close()

	beforeText, err := io.ReadAll(srcr)
	if err != nil {
		return 0, "", err
	}

	newText, err := encrypt(beforeText, bytesEncrypt)
	if err != nil {
		return 0, "", err
	}

	newText, err = decrypt(newText, bytesDecrypt)
	if err != nil {
		return 0, "", err
	}

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

func encrypt(text []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return text, nil
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	// this is not secure.
	// doing this so we have a consistent hash and filename for the same input
	md5sum := md5.Sum(text)
	nonce := md5sum[:gcm.NonceSize()]
	return gcm.Seal(nonce, nonce, text, nil), nil
}

func decrypt(cyphertext []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return cyphertext, nil
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, cyphertext := cyphertext[:nonceSize], cyphertext[nonceSize:]
	return gcm.Open(nil, nonce, cyphertext, nil)
}

func makeKey(oldKey string, bytesEncrypt, bytesDecrypt []byte) (string, error) {
	newKey := oldKey
	if len(bytesEncrypt) != 0 {
		encryptedKey, err := encrypt([]byte(newKey), bytesEncrypt)
		if err != nil {
			return "", err
		}
		newKey = base64.URLEncoding.EncodeToString(encryptedKey)
	}
	if len(bytesDecrypt) != 0 {
		decodedKey, err := base64.URLEncoding.DecodeString(newKey)
		if err != nil {
			return "", err
		}
		decryptedKey, err := decrypt(decodedKey, bytesDecrypt)
		if err != nil {
			return "", err
		}
		newKey = string(decryptedKey)
	}
	return newKey, nil
}

func getAuthentication() ([]byte, error) {
	pass, ok := os.LookupEnv("BLOBCOPY_ENCRYPTION_PASSWORD")
	if !ok {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		defer func() {
			err := term.Restore(int(os.Stdin.Fd()), oldState)
			if err != nil {
				errLogger.Println("error restoring terminal state. log output may be weird.", err)
			}
		}()

		terminal := term.NewTerminal(os.Stdin, "")
		_, _ = terminal.Write([]byte("Enter encryption password: "))
		bytepass1, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = terminal.Write([]byte("\n"))
		if err != nil {
			return nil, err
		}
		pass1 := string(bytepass1)
		_, _ = terminal.Write([]byte("Enter encryption password (verify): "))
		bytepass2, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = terminal.Write([]byte("\n"))
		if err != nil {
			return nil, err
		}
		pass2 := string(bytepass2)
		if pass1 != pass2 {
			_, _ = terminal.Write([]byte("Passwords do not match\n"))
			return nil, ErrPasswordMismatch
		}
		pass = string(pass1)
	}
	md5sum := md5.Sum([]byte(pass))
	md5sum2 := md5.Sum(md5sum[:])
	return append(md5sum2[:], md5sum[:]...), nil
}

// returns (unencrypted, encrypted) key names
func safetyName(encKey []byte) (string, string, error) {
	keySum := md5.Sum(encKey)
	keyName := "_blobcopy_safety_" + string(keySum[:])
	encKeyName, err := makeKey(keyName, encKey, nil)
	if err != nil {
		return "", "", err
	}
	return keyName, encKeyName, nil
}

func enableSafetyCheck(ctx context.Context, bkt *blob.Bucket, encKey []byte) error {
	// a predictable key name that will be different for every encryption key
	_, encKeyName, err := safetyName(encKey)
	if err != nil {
		return err
	}
	wtr, err := bkt.NewWriter(ctx, encKeyName, nil)
	if err != nil {
		return err
	}
	encContent, err := encrypt([]byte(encKeyName), encKey)
	if err != nil {
		return err
	}
	_, err = wtr.Write(encContent)
	if err != nil {
		return err
	}
	return wtr.Close()
}

func safetyCheck(ctx context.Context, bkt *blob.Bucket, encKey []byte) (bool, error) {
	_, encKeyName, err := safetyName(encKey)
	if err != nil {
		return false, err
	}
	expectedContent, err := encrypt([]byte(encKeyName), encKey)
	if err != nil {
		return false, err
	}
	rdr, err := bkt.NewReader(ctx, encKeyName, nil)
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return false, nil
	case gcerrors.OK:
		break
	default:
		return false, err
	}
	actualContent, err := io.ReadAll(rdr)
	if err != nil {
		return false, err
	}
	return string(expectedContent) == string(actualContent), nil
}
