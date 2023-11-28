# blobcopy

copy objects between blobstores.


This is bad code. It's written bad, it uses bad crypto practices. You should not use it.


# usage:

basic copy from one blob store to another

```
blobcopy gs://googleblobstore azure://azureblobstore
```


copy with an intermediate blob store. This is useful so we can use an intermediate blobstore implementation
to calculate attributes, e.g. MD5 and size. This example will copy files from a bare directory into an in-memory
blobstore, and then efficiently copy them to the destination if necessary.

```
blobcopy --use-tmp 'mem://' file:///home/user/folder aws://bucket
```

Encryption.
This will always use a temporary bucket. If one is not provided, it will use a memory bucket.

by the way, did I mention the URLs have undocumented options passed by URL query parameters?
This example will encrypt files from a local fileblob temporary bucket. The temporary bucket has options
configured that change its behavior. Personally, I find the no_tmp_dir and create_dir options critical
for fileblob that are not in the /tmp directory.

```
blobcopy --use-tmp 'file:///home/user/tmpbkt/?no_tmp_dir=1&create_dir=1' --encrypt aws://plainbucket gcp://cryptobucket
```

```
blobcopy --decrypt gcp://cryptobucket file:///home/user/bucket
```
