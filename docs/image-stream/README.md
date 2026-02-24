# Image Stream Concept Design

This document describes a proposal for how image streaming could be implemented within zot.

## Background and Problem

Currently, when blobs are downloaded on-demand from zot, zot first pulls the blobs from upstream, commits the image to zot storage, and then replies to the client. For large blobs, this can result in a connection timeout for the client while waiting for blob data.

This can cause issues in environments such as Kubernetes where the image pull may fail multiple times until zot has successfully cached the image in its storage.

## Proposed Solution

With the proposed approach, while zot is downloading the blobs for local storage, it simultaneously makes the data available for clients to download. i.e. the client is allowed to download data for partially copied blobs.

The first client to request a non-existent image would trigger this in-flight download. Other clients which want to download the same blob can join in the download at any time during the download.

## Solution Details and Proof of Concept

The fundamental concept is that the blob is broken up into chunks of a fixed chunk size. Chunk size can be configurable as part of zot config. Using this chunk size, zot can track how many chunks have been written to disk and can be read by clients.

### Assumptions

The size of a blob MUST be available beforehand to calculate the total number of chunks.
This size is available in the manifest as shown below:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:4be0d2f67cae5ca4f622fc3deccdd754d8eb5a6d2f9034474a29f01c69470439",
    "size": 2950
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:2937c3216fda91408f3a19648766369102691c9a4d698d12d4a0eb6155c13ef1",
      "size": 52246758
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:2d5283c2546119a67577a6cbf063f0d05f3b491f556f8415bbee461f073b6d04",
      "size": 25630769
    }
  ]
}
```

Sparse storage of OCI images would be supported in zot temp store for storing manifests and partially copied blobs.

### Example blob download flow

1. Client issues a request for a blob `GET https://zothub.io/v2/golang/blobs/sha256:8ec9f1fd1cf4f5152e86d09c28013ce076b8c09d3a9f5850591be40273ff877e`
2. zot checks for the blob locally, but it is not present.
3. Due to on-demand sync, zot creates a `ChunkedImageCopier` that copies the blob from a regclient `blob.Reader` to zot temp storage. regclient has a `BlobGet` method which returns a `blob.Reader` instance. [documentation](https://pkg.go.dev/github.com/regclient/regclient@v0.11.1#RegClient.BlobGet)
4. The `ChunkedImageCopier` calculates the number of chunks and begins the download to zot temp storage.
5. The client (currently open HTTP connection) has an associated `InFlightImageCopier` object that tracks at a per-object level, the number of chunks copied. It opens the temporary file where the image is being written to and registers a channel with the `ChunkedImageCopier` which announces over the go channel, the latest chunk number at the time of registration/subscription and every time a new chunk has been copied to disk.
6. The `InFlightImageCopier` receives the value from the channel and copies `(latestChunkNumber - numChunksCopied) * chunkSize` bytes from the open file descriptor to the connection's `io.Writer` implementation until all the chunks are copied.
7. The `InFlightImageCopier` holds the connection and channel active until all the bytes are copied. If the client connection terminates during the copy, the channel is de-registered and closed.

Any new clients joining in during the copy will follow the same steps from 5 onwards. As many chunks as available would be copied from the disk. Once that is complete, the `InFlightImageCopier` will wait for announcements over the channel to continue copying bytes until all chunks are copied.

### Scaling up to images

For an image with multiple layers, zot can download multiple layers simultaneously and make available, one `ChunkedImageCopier` for each blob being downloaded.
Clients are added on as they request.

For completed blobs, the `ChunkedImageCopier` can announce the final chunk number upon registration.

Manifests are not subject to this flow as they are a pre-requisite for streamed blob downloads. They would follow the usual flow where zot downloads first and then responds to the client.

### Benefits of this design

1. All requests asking for an image that is being streamed follow a single standard flow which makes it easy to reason about.
2. It is relatively easy to keep track of clients as the `InFlightImageCopier` maintains the client state. Clients that disconnect are also handled elegantly as their subscription is terminated if any error is detected during writing to the `io.Writer` implementation.

### Possible Downsides with this design

1. Each client holds an open file descriptor to the temp file where the blob is being written to. If the number of clients are very high, it could result in a too many file descriptors open error.
2. Download speeds for the client would be impacted by the configured chunk size.
3. There are a lot of checks in regclient during image Copy which won't work if zot directly accesses the `blob.Reader`. This may need some discussion to ensure that access to completed image once all the blobs are streamed is sane. 

### Proof of concept

The `main.go` file in this directory has a mock sample of a blob download where characters in a buffer go through a simulated download into a file called `ondiskblob.txt` which represents an OCI blob being written to disk. 2 sample clients are used - 1 writing to a text file `client1.txt` and another writing to stdout.

Running the program with `go run main.go` should result in lorem ipsum text being gradually written to 3 places - the 2 text files and stdout.
