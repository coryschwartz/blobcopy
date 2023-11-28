package main

import (
	"context"
	"crypto/rand"
	"strconv"
	"testing"

	"gocloud.dev/blob"
)

func testRandomData(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 1024)
	_, err := rand.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func testAuthentication(t *testing.T) []byte {
	t.Helper()
	return testRandomData(t)[:32]
}

func TestEncryptEecryptOpposite(t *testing.T) {
	text := make([]byte, 1024)
	_, err := rand.Read(text)
	if err != nil {
		t.Fatal(err)
	}
	encKey := testAuthentication(t)

	cypherText, err := encrypt(text, encKey)
	if err != nil {
		t.Fatal(err)
	}
	// decrypt
	plainText, err := decrypt(cypherText, encKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(plainText) != string(text) {
		t.Fatal("decrypted not equal to src")
	}
}

// basic mirror, no options
// tests that all the files are mirrored
func TestMirror(t *testing.T) {
	ctx := context.Background()
	bkt1, err := blob.OpenBucket(ctx, "mem://")
	if err != nil {
		t.Fatal(err)
	}
	defer bkt1.Close()

	bkt2, err := blob.OpenBucket(ctx, "mem://")
	if err != nil {
		t.Fatal(err)
	}
	defer bkt2.Close()

	nfiles := 10
	for i := 0; i < nfiles; i++ {
		file := testRandomData(t)
		wtr, err := bkt1.NewWriter(ctx, "file"+strconv.Itoa(i), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = wtr.Write(file)
		if err != nil {
			t.Fatal(err)
		}
		err = wtr.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	n, err := mirror(ctx, bkt1, bkt2, nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != nfiles {
		t.Fatalf("unexpected number of objects copied. expected %d, got %d", nfiles, n)
	}
}

// encrypted mirror.
// mirror+encrypt into a bucket,
// mirror+decrypt into another bucket
// test that the decrypted files are the same as the original
func TestEncryptBucket(t *testing.T) {
	ctx := context.Background()
	text := testRandomData(t)
	encKey := testAuthentication(t)
	fileName := "file"

	initialBkt, err := blob.OpenBucket(ctx, "mem://")
	if err != nil {
		t.Fatal(err)
	}
	defer initialBkt.Close()
	wtr, err := initialBkt.NewWriter(ctx, fileName, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = wtr.Write(text)
	if err != nil {
		t.Fatal(err)
	}
	wtr.Close()

	encryptedBkt, err := blob.OpenBucket(ctx, "mem://")
	if err != nil {
		t.Fatal(err)
	}
	defer encryptedBkt.Close()

	_, err = mirror(ctx, initialBkt, encryptedBkt, nil, encKey, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	decryptedBkt, err := blob.OpenBucket(ctx, "mem://")
	if err != nil {
		t.Fatal(err)
	}
	defer decryptedBkt.Close()

	_, err = mirror(ctx, encryptedBkt, decryptedBkt, nil, nil, encKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	rdr, err := decryptedBkt.NewReader(ctx, fileName, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rdr.Close()
	decryptedText := make([]byte, len(text))
	_, err = rdr.Read(decryptedText)
	if err != nil {
		t.Fatal(err)
	}

	if string(decryptedText) != string(text) {
		t.Fatal("decrypted text not equal to original")
	}
}
