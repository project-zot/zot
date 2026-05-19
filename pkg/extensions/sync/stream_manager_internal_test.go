//go:build sync

package sync

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	rcManifest "github.com/regclient/regclient/types/manifest"
	rcOCIV1 "github.com/regclient/regclient/types/oci/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

type mockStreamTempStore struct {
	blobPathFn func(godigest.Digest) string
}

func (m *mockStreamTempStore) BlobPath(dig godigest.Digest) string {
	if m.blobPathFn != nil {
		return m.blobPathFn(dig)
	}

	return "/nonexistent/dir/" + dig.Encoded()
}

func newTestChunkingStreamManager(dir string) *ChunkingStreamManager {
	logger := log.NewTestLogger()

	return &ChunkingStreamManager{
		tempStore:     NewLocalTempStore(dir, logger),
		activeStreams: map[string]*ChunkedBlobReader{},
		streamingRefs: map[string]rcManifest.Manifest{},
		blobInfoMap:   map[string]descriptor.Descriptor{},
		logger:        logger,
	}
}

func newTestOCIManifestWithBlobs(t *testing.T, configData, layerData []byte) rcManifest.Manifest {
	t.Helper()

	origMan := rcOCIV1.Manifest{
		Versioned: rcOCIV1.ManifestSchemaVersion,
		Config: descriptor.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    godigest.FromBytes(configData),
			Size:      int64(len(configData)),
		},
		Layers: []descriptor.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    godigest.FromBytes(layerData),
				Size:      int64(len(layerData)),
			},
		},
	}

	m, err := rcManifest.New(rcManifest.WithOrig(origMan))
	if err != nil {
		t.Fatalf("failed to create test OCI manifest: %v", err)
	}

	return m
}

func TestChunkingStreamManagerConnectClient(t *testing.T) {
	Convey("ConnectClient", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		Convey("returns ErrBlobNotFoundInActiveStreams when blob is not active", func() {
			digest := "sha256:" + strings.Repeat("a", 64)
			copier, err := sm.ConnectClient(digest, &bytes.Buffer{})
			So(errors.Is(err, zerr.ErrBlobNotFoundInActiveStreams), ShouldBeTrue)
			So(copier, ShouldBeNil)
		})

		Convey("returns error for an unparseable blob digest", func() {
			copier, err := sm.ConnectClient("not-a-valid-digest", &bytes.Buffer{})
			So(err, ShouldNotBeNil)
			So(copier, ShouldBeNil)
		})

		Convey("returns an InFlightBlobCopier for an active blob", func() {
			blobData := []byte("test blob content")
			desc := descriptor.Descriptor{
				Digest:    godigest.FromBytes(blobData),
				Size:      int64(len(blobData)),
				MediaType: "application/octet-stream",
			}

			err := sm.prepareActiveStreamForBlob(desc)
			So(err, ShouldBeNil)

			copier, err := sm.ConnectClient(desc.Digest.String(), &bytes.Buffer{})
			So(err, ShouldBeNil)
			So(copier, ShouldNotBeNil)
		})
	})
}

func TestChunkingStreamManagerCachedBlobInfo(t *testing.T) {
	Convey("CachedBlobInfo", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		Convey("returns ErrBlobNotFound for an unknown blob", func() {
			digest := "sha256:" + strings.Repeat("b", 64)
			size, mt, err := sm.CachedBlobInfo(digest)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
			So(size, ShouldEqual, 0)
			So(mt, ShouldBeEmpty)
		})

		Convey("returns size and media type for a known blob", func() {
			blobData := []byte("cached blob data")
			desc := descriptor.Descriptor{
				Digest:    godigest.FromBytes(blobData),
				Size:      int64(len(blobData)),
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			}

			sm.blobInfoMap[desc.Digest.String()] = desc

			size, mt, err := sm.CachedBlobInfo(desc.Digest.String())
			So(err, ShouldBeNil)
			So(size, ShouldEqual, int64(len(blobData)))
			So(mt, ShouldEqual, "application/vnd.oci.image.layer.v1.tar+gzip")
		})
	})
}

func TestChunkingStreamManagerStreamingBlobReader(t *testing.T) {
	Convey("StreamingBlobReader", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		Convey("returns ErrBlobReaderMissing when blob has no active stream", func() {
			data := []byte("some blob")
			reader := newTestBReader(data)
			result, err := sm.StreamingBlobReader(reader)
			So(errors.Is(err, zerr.ErrBlobReaderMissing), ShouldBeTrue)
			So(result, ShouldBeNil)
		})

		Convey("initialises the chunked reader and returns a wrapped BReader for an active stream", func() {
			data := []byte("streaming blob")
			desc := descriptor.Descriptor{
				Digest:    godigest.FromBytes(data),
				Size:      int64(len(data)),
				MediaType: "application/octet-stream",
			}

			err := sm.prepareActiveStreamForBlob(desc)
			So(err, ShouldBeNil)

			reader := newTestBReader(data)
			result, err := sm.StreamingBlobReader(reader)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)
		})
	})
}

func TestChunkingStreamManagerStoreImageForStreaming(t *testing.T) {
	Convey("StoreImageForStreaming", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		configData := []byte("config-payload")
		layerData := []byte("layer-payload")
		manifest := newTestOCIManifestWithBlobs(t, configData, layerData)

		Convey("stores manifest and prepares active streams for all blobs", func() {
			err := sm.StoreImageForStreaming("myrepo", "v1.0", manifest)
			So(err, ShouldBeNil)

			// Manifest entry should be stored.
			m, ok := sm.StreamingImageManifest("myrepo", "v1.0")
			So(ok, ShouldBeTrue)
			So(m, ShouldEqual, manifest)

			// All three blobs (manifest, config, layer) should be active streams.
			manifestDigest := manifest.GetDescriptor().Digest.String()
			configDigest := godigest.FromBytes(configData).String()
			layerDigest := godigest.FromBytes(layerData).String()

			_, hasManifest := sm.activeStreams[manifestDigest]
			So(hasManifest, ShouldBeTrue)

			_, hasConfig := sm.activeStreams[configDigest]
			So(hasConfig, ShouldBeTrue)

			_, hasLayer := sm.activeStreams[layerDigest]
			So(hasLayer, ShouldBeTrue)
		})

		Convey("storing the same repo:reference is idempotent", func() {
			err := sm.StoreImageForStreaming("myrepo", "v1.0", manifest)
			So(err, ShouldBeNil)

			err = sm.StoreImageForStreaming("myrepo", "v1.0", manifest)
			So(err, ShouldBeNil)

			_, ok := sm.StreamingImageManifest("myrepo", "v1.0")
			So(ok, ShouldBeTrue)
		})

		Convey("propagates error when the temp store cannot create a blob path", func() {
			sm.tempStore = &mockStreamTempStore{
				blobPathFn: func(_ godigest.Digest) string {
					return "/nonexistent/dir/blob"
				},
			}

			err := sm.StoreImageForStreaming("myrepo", "v1.0", manifest)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestChunkingStreamManagerStreamingImageManifest(t *testing.T) {
	Convey("StreamingImageManifest", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		manifest := newTestOCIManifestWithBlobs(t, []byte("cfg"), []byte("lyr"))

		Convey("returns nil and false when no entry exists", func() {
			m, ok := sm.StreamingImageManifest("repo", "tag")
			So(ok, ShouldBeFalse)
			So(m, ShouldBeNil)
		})

		Convey("returns the manifest and true after it has been stored", func() {
			err := sm.StoreImageForStreaming("repo", "tag", manifest)
			So(err, ShouldBeNil)

			m, ok := sm.StreamingImageManifest("repo", "tag")
			So(ok, ShouldBeTrue)
			So(m, ShouldEqual, manifest)
		})
	})
}

func TestChunkingStreamManagerRemoveStreamingImage(t *testing.T) {
	Convey("RemoveStreamingImage", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		Convey("does not panic when no entry exists for the given repo:reference", func() {
			So(func() { sm.RemoveStreamingImage("nothere", "v0") }, ShouldNotPanic)
		})

		Convey("removes manifest and all associated blobs after a successful store", func() {
			configData := []byte("cfg-payload")
			layerData := []byte("lyr-payload")
			manifest := newTestOCIManifestWithBlobs(t, configData, layerData)

			err := sm.StoreImageForStreaming("myrepo", "latest", manifest)
			So(err, ShouldBeNil)

			manifestDigest := manifest.GetDescriptor().Digest.String()
			configDigest := godigest.FromBytes(configData).String()
			layerDigest := godigest.FromBytes(layerData).String()

			// Confirm blobs are active before removal.
			_, ok := sm.activeStreams[manifestDigest]
			So(ok, ShouldBeTrue)

			sm.RemoveStreamingImage("myrepo", "latest")

			// Manifest entry should be gone.
			_, found := sm.StreamingImageManifest("myrepo", "latest")
			So(found, ShouldBeFalse)

			// All active streams should be cleaned up.
			_, stillHasManifest := sm.activeStreams[manifestDigest]
			So(stillHasManifest, ShouldBeFalse)

			_, stillHasConfig := sm.activeStreams[configDigest]
			So(stillHasConfig, ShouldBeFalse)

			_, stillHasLayer := sm.activeStreams[layerDigest]
			So(stillHasLayer, ShouldBeFalse)
		})
	})
}
