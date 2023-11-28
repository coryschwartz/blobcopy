package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

func main() {
	var useMem bool
	flag.BoolVar(&useMem, "use-mem", false, "use a memory bucket to calculate MD5s")
	flag.Parse()
	if len(flag.Args()) != 2 {
		usage()
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

	if err := mirror(ctx, sbkt, dbkt, useMem); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [flags] <src> <dst>\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "consider using --mem to calculate local md5s using an in-memory blob prior to copy\n")
	fmt.Fprintf(os.Stderr, "example: %s --mem file:///tmp/foo gs://my-bucket/bar\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "undocumented driver-specific flags can be passed to the urlstring\n")
	fmt.Fprintf(os.Stderr, "example: %s gs://my-bucket/bar 'file:////restore/to/foo?no_tmp_dir=1&create_dir=1'\n", os.Args[0])
	os.Exit(2)
}

// copies all objects from src to dst.
func mirror(ctx context.Context, sbkt, dbkt *blob.Bucket, useMem bool) error {
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
		if sattrs.MD5 == nil && useMem {
			log.Println("loading to memory", obj.Key)
			_, err := copyObj(ctx, sbkt, tmpBkt, obj.Key)
			if err != nil {
				return err
			}
			csbkt = tmpBkt
			sattrs, _ = csbkt.Attributes(ctx, obj.Key)
			cleanloop = func() {
				log.Println("unloading from memory", obj.Key)
				if err := tmpBkt.Delete(ctx, obj.Key); err != nil {
					log.Println("error deleting", obj.Key, "from memory bucket:", err)
				}
			}
		}

		// check if file exists in the destination
		exists, err := dbkt.Exists(ctx, obj.Key)
		if err != nil {
			return err
		}
		// if it exists, check if the md5 matches
		if exists {
			dattrs, err := dbkt.Attributes(ctx, obj.Key)
			if err != nil {
				return err
			}
			if matchMD5(sattrs.MD5, dattrs.MD5) {
				continue
			}
		}
		// either it doesn't exist, or the MD5 doesn't match. copy it.
		log.Println("copying to destination", obj.Key, "size", obj.Size)
		n, err := copyObj(ctx, csbkt, dbkt, obj.Key)
		if err != nil {
			return err
		}
		log.Println("copied to destination", obj.Key, "size", n)
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
func copyObj(ctx context.Context, src, dst *blob.Bucket, key string) (int64, error) {
	srcr, err := src.NewReader(ctx, key, nil)
	if err != nil {
		return 0, err
	}
	defer srcr.Close()

	dstw, err := dst.NewWriter(ctx, key, nil)
	if err != nil {
		return 0, err
	}
	defer dstw.Close()

	n, err := dstw.ReadFrom(srcr)
	if err != nil {
		return 0, err
	}
	return n, nil
}
