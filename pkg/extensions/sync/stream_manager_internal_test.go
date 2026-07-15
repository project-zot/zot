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
		streamingRefs: map[string]*StreamableManifest{},
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

// newTestOCIImageIndex creates an OCI Image Index containing multiple platform-specific manifests.
// Each sub-manifest has a config blob and layer blobs with the provided data.
func newTestOCIImageIndex(t *testing.T, subManifests []rcManifest.Manifest) rcManifest.Manifest {
	t.Helper()

	manifestDescs := make([]descriptor.Descriptor, len(subManifests))
	for i, m := range subManifests {
		desc := m.GetDescriptor()
		manifestDescs[i] = desc
	}

	origIndex := rcOCIV1.Index{
		Manifests: manifestDescs,
	}

	idx, err := rcManifest.New(rcManifest.WithOrig(origIndex))
	if err != nil {
		t.Fatalf("failed to create test OCI Image Index: %v", err)
	}

	return idx
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
			streamableManifest := NewStreamableManifest(manifest, nil)
			err := sm.StoreImageForStreaming("myrepo", "v1.0", streamableManifest)
			So(err, ShouldBeNil)

			// Manifest entry should be stored.
			m, ok := sm.StreamingImageManifest("myrepo", "v1.0")
			So(ok, ShouldBeTrue)
			So(m.referenceManifest, ShouldEqual, manifest)

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
			streamableManifest := NewStreamableManifest(manifest, nil)
			err := sm.StoreImageForStreaming("myrepo", "v1.0", streamableManifest)
			So(err, ShouldBeNil)

			err = sm.StoreImageForStreaming("myrepo", "v1.0", streamableManifest)
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
			streamableManifest := NewStreamableManifest(manifest, nil)
			err := sm.StoreImageForStreaming("myrepo", "v1.0", streamableManifest)
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
			streamableManifest := NewStreamableManifest(manifest, nil)
			err := sm.StoreImageForStreaming("repo", "tag", streamableManifest)
			So(err, ShouldBeNil)

			m, ok := sm.StreamingImageManifest("repo", "tag")
			So(ok, ShouldBeTrue)
			So(m.referenceManifest, ShouldEqual, manifest)
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
			streamableManifest := NewStreamableManifest(manifest, nil)
			err := sm.StoreImageForStreaming("myrepo", "latest", streamableManifest)
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

func TestChunkingStreamManagerMultiArchStoreImageForStreaming(t *testing.T) {
	Convey("StoreImageForStreaming with multi-arch image index", t, func() {
		sm := newTestChunkingStreamManager(t.TempDir())

		// Create two platform-specific sub-manifests.
		amd64Config := []byte("amd64-config-data")
		amd64Layer1 := []byte("amd64-layer-1")
		amd64Manifest := newTestOCIManifestWithBlobs(t, amd64Config, amd64Layer1)

		arm64Config := []byte("arm64-config-data")
		arm64Layer1 := []byte("arm64-layer-1")
		arm64Manifest := newTestOCIManifestWithBlobs(t, arm64Config, arm64Layer1)

		subManifests := []rcManifest.Manifest{amd64Manifest, arm64Manifest}
		index := newTestOCIImageIndex(t, subManifests)

		Convey("stores index manifest and prepares active streams for all platform configs and layers", func() {
			streamableManifest := NewStreamableManifest(index, subManifests)
			err := sm.StoreImageForStreaming("multi-arch-repo", "latest", streamableManifest)
			So(err, ShouldBeNil)

			// Index manifest entry should be stored.
			m, ok := sm.StreamingImageManifest("multi-arch-repo", "latest")
			So(ok, ShouldBeTrue)
			So(m.referenceManifest, ShouldEqual, index)

			// Each sub-manifest, its config, and its layer should be active streams.
			amd64ManifestDigest := amd64Manifest.GetDescriptor().Digest.String()
			arm64ManifestDigest := arm64Manifest.GetDescriptor().Digest.String()
			amd64ConfigDigest := godigest.FromBytes(amd64Config).String()
			arm64ConfigDigest := godigest.FromBytes(arm64Config).String()
			amd64Layer1Digest := godigest.FromBytes(amd64Layer1).String()
			arm64Layer1Digest := godigest.FromBytes(arm64Layer1).String()

			_, hasAmd64Manifest := sm.activeStreams[amd64ManifestDigest]
			So(hasAmd64Manifest, ShouldBeTrue)

			_, hasArm64Manifest := sm.activeStreams[arm64ManifestDigest]
			So(hasArm64Manifest, ShouldBeTrue)

			_, hasAmd64Config := sm.activeStreams[amd64ConfigDigest]
			So(hasAmd64Config, ShouldBeTrue)

			_, hasArm64Config := sm.activeStreams[arm64ConfigDigest]
			So(hasArm64Config, ShouldBeTrue)

			_, hasAmd64Layer1 := sm.activeStreams[amd64Layer1Digest]
			So(hasAmd64Layer1, ShouldBeTrue)

			_, hasArm64Layer1 := sm.activeStreams[arm64Layer1Digest]
			So(hasArm64Layer1, ShouldBeTrue)
		})

		Convey("stores blob info for all platform blobs", func() {
			streamableManifest := NewStreamableManifest(index, subManifests)
			err := sm.StoreImageForStreaming("multi-arch-repo", "v1.0", streamableManifest)
			So(err, ShouldBeNil)

			amd64ConfigDigest := godigest.FromBytes(amd64Config).String()
			arm64Layer1Digest := godigest.FromBytes(arm64Layer1).String()

			// Verify blob info is cached for amd64 config.
			size, mt, err := sm.CachedBlobInfo(amd64ConfigDigest)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, int64(len(amd64Config)))
			So(mt, ShouldNotBeEmpty)

			// Verify blob info is cached for arm64 layer.
			size, mt, err = sm.CachedBlobInfo(arm64Layer1Digest)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, int64(len(arm64Layer1)))
			So(mt, ShouldNotBeEmpty)
		})

		Convey("returns error when preparing a sub-manifest fails due to bad temp store", func() {
			sm.tempStore = &mockStreamTempStore{
				blobPathFn: func(_ godigest.Digest) string {
					return "/nonexistent/dir/blob"
				},
			}
			streamableManifest := NewStreamableManifest(index, subManifests)
			err := sm.StoreImageForStreaming("multi-arch-repo", "latest", streamableManifest)
			So(err, ShouldNotBeNil)
		})
	})
}
