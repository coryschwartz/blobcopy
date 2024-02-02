# blobcopy

copy objects between blobstores.

This is bad code. It's written bad, it uses bad crypto practices. You should not use it.

This is similar to rclone in spirit, but worse in every conceivable way.

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

Encryption "safety".
There is a "safety" feature that deserves an explanation. When you clone with encryption, both the filecontent and the filename will be
encrypted. So what happens if you clone a directory with one encryption key, and then later you attempt the same operation with a different
key? Without safety, this would mean all the content would be copied to the destination twice, but encrypted with different keys. This probably
is not what you expect to happen.
That's where "safety" comes in. When `safety` flag is used, we will check for the existence of a special file on the destination before
we do anything else. If this special file exists, and we are able to decrypt it, then we know we are using the same encryption key that has been
used before. If there is no safety file, then we know something has gone wrong. Maybe you forgot the password. Maybe you mis-typed it. Anyway,
it'll throw a warning to let you know that this is probably not what you want.

To make use of safety, you first have to generate the special safety file with the `gen-safety` flag.
The first time you copy files, you should include the gen-safety flag, and then for all subsequent copies, you can leave it off.

Content verification.
By default, it will only check that the destination has a file with the same name, and does not detect content changes.
However, you can change this behavior with the `verify-md5` flag.
