//go:build sync

package stream

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	rcManifest "github.com/regclient/regclient/types/manifest"
	rcOCIV1 "github.com/regclient/regclient/types/oci/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

type mockTempStore struct {
	blobPathFn func(godigest.Digest) string
}

func (m *mockTempStore) BlobPath(dig godigest.Digest) string {
	if m.blobPathFn != nil {
		return m.blobPathFn(dig)
	}

	return "/nonexistent/dir/" + dig.Encoded()
}

func newTestChunkingManager(dir string) *ChunkingManager {
	logger := log.NewTestLogger()

	return &ChunkingManager{
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

func TestChunkingManagerConnectClient(t *testing.T) {
	Convey("ConnectClient", t, func() {
		sm := newTestChunkingManager(t.TempDir())

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

func TestChunkingManagerCachedBlobInfo(t *testing.T) {
	Convey("CachedBlobInfo", t, func() {
		sm := newTestChunkingManager(t.TempDir())

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

func TestChunkingManagerStreamingBlobReader(t *testing.T) {
	Convey("StreamingBlobReader", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		Convey("falls back to the raw upstream reader when blob has no active stream", func() {
			data := []byte("some blob")
			reader := newTestBReader(data)
			result, err := sm.StreamingBlobReader(reader)
			So(err, ShouldBeNil)
			// pass-through: the very same reader is returned unwrapped
			So(result, ShouldEqual, reader)
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

		Convey("Plan A: serves already-complete blob from disk without re-downloading", func() {
			data := []byte("already complete blob data on disk")
			desc := descriptor.Descriptor{
				Digest:    godigest.FromBytes(data),
				Size:      int64(len(data)),
				MediaType: "application/octet-stream",
			}

			// Prepare the active stream — this creates a ChunkedBlobReader.
			err := sm.prepareActiveStreamForBlob(desc)
			So(err, ShouldBeNil)

			// Simulate complete blob already on disk by writing all data to the temp file.
			blobPath := sm.tempStore.BlobPath(desc.Digest)
			writeErr := os.WriteFile(blobPath, data, 0o644)
			So(writeErr, ShouldBeNil)

			// Re-create the ChunkedBlobReader so it detects the existing complete file.
			cbr, cbrErr := NewChunkedBlobReader(blobPath, sm.logger)
			So(cbrErr, ShouldBeNil)
			sm.activeStreams[desc.Digest.String()] = cbr

			// Verify resumeOffset == desc.Size (blob is complete).
			So(cbr.ResumeOffset(), ShouldEqual, desc.Size)

			// Call StreamingBlobReader — it should return a reader over the disk file.
			reader := newTestBReader(data)
			result, err := sm.StreamingBlobReader(reader)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)

			// Read all data from the returned reader — should be the full blob.
			readBuf := make([]byte, desc.Size)
			n, readErr := result.Read(readBuf)
			So(n, ShouldEqual, len(data))
			So(readBuf[:n], ShouldResemble, data)
			// Accept EOF or nil (depends on whether file returns EOF with last read or separately)
			if readErr != nil {
				So(readErr, ShouldEqual, io.EOF)
			}

			// ChunkedBlobReader should report complete.
			cbr.bytesMu.RLock()
			So(cbr.numBytesReadToDisk, ShouldEqual, desc.Size)
			So(cbr.numBytesTotal, ShouldEqual, desc.Size)
			cbr.bytesMu.RUnlock()
		})

		Convey("Plan B: resumes partial blob with MultiReader prefix+suffix", func() {
			// Full blob data: prefix (already on disk) + suffix (from upstream).
			prefix := []byte("AAAAAAAAAA") // 10 bytes already downloaded
			suffix := []byte("BBBBBBBBBB") // 10 bytes remaining
			fullData := append(prefix, suffix...)
			desc := descriptor.Descriptor{
				Digest:    godigest.FromBytes(fullData),
				Size:      int64(len(fullData)),
				MediaType: "application/octet-stream",
			}

			// Prepare the active stream.
			err := sm.prepareActiveStreamForBlob(desc)
			So(err, ShouldBeNil)

			// Write only the prefix to disk (partial download).
			blobPath := sm.tempStore.BlobPath(desc.Digest)
			writeErr := os.WriteFile(blobPath, prefix, 0o644)
			So(writeErr, ShouldBeNil)

			// Re-create the ChunkedBlobReader so it detects the partial file.
			cbr, cbrErr := NewChunkedBlobReader(blobPath, sm.logger)
			So(cbrErr, ShouldBeNil)
			sm.activeStreams[desc.Digest.String()] = cbr

			// Verify resumeOffset == prefix length.
			So(cbr.ResumeOffset(), ShouldEqual, int64(len(prefix)))

			// The upstream reader provides the FULL data (regclient always fetches full).
			reader := newTestBReader(fullData)
			result, err := sm.StreamingBlobReader(reader)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)

			// Read all data through the ChunkedBlobReader (which is wrapped as the result).
			readBuf := make([]byte, desc.Size+10) // extra space
			totalRead := 0
			for {
				n, readErr := result.Read(readBuf[totalRead:])
				totalRead += n
				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)
					break
				}
			}

			So(int64(totalRead), ShouldEqual, desc.Size)
			So(readBuf[:totalRead], ShouldResemble, fullData)

			// On-disk file should now contain the full blob (prefix + suffix appended).
			onDisk, diskErr := os.ReadFile(blobPath)
			So(diskErr, ShouldBeNil)
			So(onDisk, ShouldResemble, fullData)
		})
	})
}

func TestChunkingManagerStoreImageForStreaming(t *testing.T) {
	Convey("StoreImageForStreaming", t, func() {
		sm := newTestChunkingManager(t.TempDir())

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
			sm.tempStore = &mockTempStore{
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

func TestChunkingManagerStreamingImageManifest(t *testing.T) {
	Convey("StreamingImageManifest", t, func() {
		sm := newTestChunkingManager(t.TempDir())

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

func TestChunkingManagerRemoveStreamingImage(t *testing.T) {
	Convey("RemoveStreamingImage", t, func() {
		sm := newTestChunkingManager(t.TempDir())

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

func TestChunkingManagerMultiArchStoreImageForStreaming(t *testing.T) {
	Convey("StoreImageForStreaming with multi-arch image index", t, func() {
		sm := newTestChunkingManager(t.TempDir())

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
			sm.tempStore = &mockTempStore{
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

func TestChunkingManagerStreamingBlobReaderRetry(t *testing.T) {
	Convey("StreamingBlobReader on sync retry", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		prefix := []byte("AAAAAAAAAA") // delivered by the failed first attempt
		suffix := []byte("BBBBBBBBBB")
		fullData := append(append([]byte{}, prefix...), suffix...)
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(fullData),
			Size:      int64(len(fullData)),
			MediaType: "application/octet-stream",
		}

		err := sm.prepareActiveStreamForBlob(desc)
		So(err, ShouldBeNil)

		Convey("re-arms a failed reader in place and resumes appending to disk", func() {
			// First attempt: upstream fails after delivering the prefix.
			failingReader := blob.NewReader(
				blob.WithDesc(desc),
				blob.WithReader(io.MultiReader(
					bytes.NewReader(prefix),
					errReaderFunc(func(p []byte) (int, error) {
						return 0, zerr.ErrSyncUpstreamDownloadFailed
					}),
				)),
			)

			result1, err := sm.StreamingBlobReader(failingReader)
			So(err, ShouldBeNil)

			buf := make([]byte, len(prefix))
			n, readErr := result1.Read(buf)
			So(readErr, ShouldBeNil)
			So(n, ShouldEqual, len(prefix))

			_, readErr = result1.Read(buf)
			So(readErr, ShouldNotBeNil)

			cbr := sm.activeStreams[desc.Digest.String()]
			So(cbr.Failed(), ShouldBeTrue)

			// Retry: the hook is invoked again with a fresh full upstream reader.
			result2, err := sm.StreamingBlobReader(newTestBReader(fullData))
			So(err, ShouldBeNil)
			So(cbr.Failed(), ShouldBeFalse)

			// Reading through the re-armed reader yields the full blob.
			readBuf := make([]byte, desc.Size+10)
			totalRead := 0

			for {
				n, readErr := result2.Read(readBuf[totalRead:])
				totalRead += n

				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)

					break
				}
			}

			So(int64(totalRead), ShouldEqual, desc.Size)
			So(readBuf[:totalRead], ShouldResemble, fullData)

			// The on-disk file contains the full blob with no duplicated prefix.
			onDisk, diskErr := os.ReadFile(sm.tempStore.BlobPath(desc.Digest))
			So(diskErr, ShouldBeNil)
			So(onDisk, ShouldResemble, fullData)
		})

		Convey("serves an already-completed blob from disk on retry", func() {
			// First attempt completes the download.
			result1, err := sm.StreamingBlobReader(newTestBReader(fullData))
			So(err, ShouldBeNil)

			// Slightly larger than the blob so the read loop hits EOF.
			readBuf := make([]byte, desc.Size+10)
			totalRead := 0

			for {
				n, readErr := result1.Read(readBuf[totalRead:])
				totalRead += n

				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)

					break
				}
			}

			So(int64(totalRead), ShouldEqual, desc.Size)

			cbr := sm.activeStreams[desc.Digest.String()]
			So(cbr.Completed(), ShouldBeTrue)

			// Retry (e.g. another blob in the image failed): the hook must serve
			// this blob from disk instead of re-downloading or hanging.
			result2, err := sm.StreamingBlobReader(newTestBReader(fullData))
			So(err, ShouldBeNil)

			onDisk := make([]byte, desc.Size+10)
			totalRead = 0

			for {
				n, readErr := result2.Read(onDisk[totalRead:])
				totalRead += n

				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)

					break
				}
			}

			So(int64(totalRead), ShouldEqual, desc.Size)
			So(onDisk[:totalRead], ShouldResemble, fullData)
		})
	})
}

func TestChunkingManagerRemoveStreamingImageNonBlocking(t *testing.T) {
	Convey("RemoveStreamingImage waits for clients without freezing the manager", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		layerData := bytes.Repeat([]byte("z"), 32)
		configData := []byte("cfg-nb")
		manifest := newTestOCIManifestWithBlobs(t, configData, layerData)
		So(sm.StoreImageForStreaming("r1", "v1", NewStreamableManifest(manifest, nil)), ShouldBeNil)

		layerDigest := godigest.FromBytes(layerData)
		layerDesc := descriptor.Descriptor{
			Digest:    layerDigest,
			Size:      int64(len(layerData)),
			MediaType: "application/octet-stream",
		}

		layerReader := sm.activeStreams[layerDigest.String()]
		So(layerReader, ShouldNotBeNil)
		So(layerReader.InitReader(newTestBReader(layerData), layerDesc), ShouldBeTrue)

		// Connect a client and start copying; it will wait for the download.
		var clientBuf bytes.Buffer
		copier, err := sm.ConnectClient(layerDigest.String(), &clientBuf)
		So(err, ShouldBeNil)

		copyErr := make(chan error, 1)
		go func() { copyErr <- copier.Copy() }()

		// Deliver only the first half so the client stays connected.
		buff := make([]byte, 16)
		_, rerr := layerReader.Read(buff)
		So(rerr, ShouldBeNil)

		// Start the removal; it must detach the entries immediately and then
		// wait for the connected client WITHOUT holding streamLock.
		removeDone := make(chan struct{})
		go func() {
			sm.RemoveStreamingImage("r1", "v1")
			close(removeDone)
		}()

		// Wait until the entries are detached (removal has passed the locked phase).
		detached := false
		for range 100 {
			if _, found := sm.StreamingImageManifest("r1", "v1"); !found {
				detached = true

				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		So(detached, ShouldBeTrue)

		select {
		case <-removeDone:
			t.Fatal("RemoveStreamingImage returned before the client drained")
		default:
		}

		// While the removal is still waiting for the client, other manager
		// operations must complete promptly.
		otherLayer := []byte("other-layer-data")
		otherManifest := newTestOCIManifestWithBlobs(t, []byte("other-cfg"), otherLayer)

		opsDone := make(chan error, 1)
		go func() {
			opsDone <- sm.StoreImageForStreaming("r2", "v2", NewStreamableManifest(otherManifest, nil))
		}()

		select {
		case err := <-opsDone:
			So(err, ShouldBeNil)
		case <-time.After(3 * time.Second):
			t.Fatal("StoreImageForStreaming blocked while RemoveStreamingImage was waiting for clients")
		}

		_, _, infoErr := sm.CachedBlobInfo(godigest.FromBytes(otherLayer).String())
		So(infoErr, ShouldBeNil)

		// Deliver the second half; the client finishes and the removal completes.
		_, rerr = layerReader.Read(buff)
		So(errors.Is(rerr, io.EOF), ShouldBeTrue)

		select {
		case err := <-copyErr:
			So(err, ShouldBeNil)
		case <-time.After(5 * time.Second):
			t.Fatal("client copy did not finish")
		}

		select {
		case <-removeDone:
		case <-time.After(5 * time.Second):
			t.Fatal("RemoveStreamingImage did not finish after the client drained")
		}

		So(clientBuf.Bytes(), ShouldResemble, layerData)

		// The temp file of the layer must be gone.
		_, statErr := os.Stat(sm.tempStore.BlobPath(layerDigest))
		So(os.IsNotExist(statErr), ShouldBeTrue)
	})
}

func TestChunkingManagerAbortStreamingImage(t *testing.T) {
	Convey("AbortStreamingImage", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		layerData := bytes.Repeat([]byte("q"), 32)
		configData := []byte("cfg-abort")
		manifest := newTestOCIManifestWithBlobs(t, configData, layerData)
		So(sm.StoreImageForStreaming("r1", "v1", NewStreamableManifest(manifest, nil)), ShouldBeNil)

		layerDigest := godigest.FromBytes(layerData)
		layerDesc := descriptor.Descriptor{
			Digest:    layerDigest,
			Size:      int64(len(layerData)),
			MediaType: "application/octet-stream",
		}

		layerReader := sm.activeStreams[layerDigest.String()]
		So(layerReader, ShouldNotBeNil)
		So(layerReader.InitReader(newTestBReader(layerData), layerDesc), ShouldBeTrue)

		var clientBuf bytes.Buffer
		copier, err := sm.ConnectClient(layerDigest.String(), &clientBuf)
		So(err, ShouldBeNil)

		copyErr := make(chan error, 1)
		go func() { copyErr <- copier.Copy() }()

		// Deliver only the first half, then abort (terminal sync failure).
		buff := make([]byte, 16)
		_, rerr := layerReader.Read(buff)
		So(rerr, ShouldBeNil)

		sm.AbortStreamingImage("r1", "v1")

		// The connected client fails fast instead of hanging.
		select {
		case err := <-copyErr:
			So(errors.Is(err, zerr.ErrSyncUpstreamDownloadFailed), ShouldBeTrue)
		case <-time.After(5 * time.Second):
			t.Fatal("client copy still hanging after AbortStreamingImage")
		}

		// The stream state is gone.
		_, found := sm.StreamingImageManifest("r1", "v1")
		So(found, ShouldBeFalse)

		_, err = sm.ConnectClient(layerDigest.String(), &clientBuf)
		So(errors.Is(err, zerr.ErrBlobNotFoundInActiveStreams), ShouldBeTrue)

		// The partial temp file is kept for a future resume.
		info, statErr := os.Stat(sm.tempStore.BlobPath(layerDigest))
		So(statErr, ShouldBeNil)
		So(info.Size(), ShouldEqual, int64(16))
	})
}

func TestChunkingManagerDuplicateInFlightSync(t *testing.T) {
	Convey("a duplicate sync of an in-flight blob is served from disk, not upstream", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		data := bytes.Repeat([]byte("d"), 128)
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(data),
			Size:      int64(len(data)),
			MediaType: "application/octet-stream",
		}

		So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)

		// First sync initializes the chunked reader (primary download).
		primary, err := sm.StreamingBlobReader(newTestBReader(data))
		So(err, ShouldBeNil)
		So(primary, ShouldNotBeNil)

		// Second sync arrives while the download is in flight: it must be fed
		// from the in-progress on-disk file instead of upstream.
		duplicate, err := sm.StreamingBlobReader(newTestBReader(data))
		So(err, ShouldBeNil)
		So(duplicate, ShouldNotBeNil)
		So(duplicate, ShouldNotEqual, primary)

		// Drive the primary download to completion.
		primaryDone := make(chan error, 1)
		go func() {
			_, cerr := io.Copy(io.Discard, primary)
			primaryDone <- cerr
		}()

		// The duplicate reader must deliver the exact same bytes.
		gotChan := make(chan []byte, 1)
		dupErr := make(chan error, 1)
		go func() {
			got, derr := io.ReadAll(duplicate)
			gotChan <- got
			dupErr <- derr
		}()

		select {
		case err := <-primaryDone:
			So(err, ShouldBeNil)
		case <-time.After(5 * time.Second):
			t.Fatal("primary download did not finish")
		}

		select {
		case got := <-gotChan:
			So(got, ShouldResemble, data)
			So(<-dupErr, ShouldBeNil)
		case <-time.After(5 * time.Second):
			t.Fatal("duplicate sync reader did not finish")
		}
	})
}

func TestChunkingManagerStreamingImageManifestDigestLookup(t *testing.T) {
	Convey("StreamingImageManifest matches digests of cached indexes and sub-manifests", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		amd64Manifest := newTestOCIManifestWithBlobs(t, []byte("amd64-cfg"), []byte("amd64-layer"))
		arm64Manifest := newTestOCIManifestWithBlobs(t, []byte("arm64-cfg"), []byte("arm64-layer"))
		index := newTestOCIImageIndex(t, []rcManifest.Manifest{amd64Manifest, arm64Manifest})

		streamable := NewStreamableManifest(index, []rcManifest.Manifest{amd64Manifest, arm64Manifest})
		So(sm.StoreImageForStreaming("myrepo", "latest", streamable), ShouldBeNil)

		Convey("exact repo:tag key still matches", func() {
			got, found := sm.StreamingImageManifest("myrepo", "latest")
			So(found, ShouldBeTrue)
			So(got.referenceManifest.GetDescriptor().Digest, ShouldEqual, index.GetDescriptor().Digest)
		})

		Convey("index digest matches the cached entry", func() {
			got, found := sm.StreamingImageManifest("myrepo", index.GetDescriptor().Digest.String())
			So(found, ShouldBeTrue)
			So(got.referenceManifest.GetDescriptor().Digest, ShouldEqual, index.GetDescriptor().Digest)
			// The full streamable manifest (with sub-manifests) is returned.
			So(len(got.subManifests), ShouldEqual, 2)
		})

		Convey("sub-manifest digest matches and returns that sub-manifest", func() {
			for _, sub := range []rcManifest.Manifest{amd64Manifest, arm64Manifest} {
				got, found := sm.StreamingImageManifest("myrepo", sub.GetDescriptor().Digest.String())
				So(found, ShouldBeTrue)
				So(got.referenceManifest.GetDescriptor().Digest, ShouldEqual, sub.GetDescriptor().Digest)
			}
		})

		Convey("unknown digest does not match", func() {
			unknown := godigest.FromBytes([]byte("something else")).String()
			_, found := sm.StreamingImageManifest("myrepo", unknown)
			So(found, ShouldBeFalse)
		})

		Convey("digest of a cached image does not match under a different repo", func() {
			_, found := sm.StreamingImageManifest("otherrepo", index.GetDescriptor().Digest.String())
			So(found, ShouldBeFalse)
		})

		Convey("non-digest references only match the exact key", func() {
			_, found := sm.StreamingImageManifest("myrepo", "someothertag")
			So(found, ShouldBeFalse)
		})
	})
}

func TestChunkingManagerEarlyClientBeforePlanAInit(t *testing.T) {
	Convey("a client that connects before InitReaderComplete still gets the blob", t, func() {
		// Regression: with a leftover complete file in the stream temp store
		// (Plan A), the sync hook calls InitReaderComplete and never Read().
		// A client that subscribed BEFORE the hook ran must still be notified,
		// otherwise it waits forever (docker hangs at "Pulling fs layer").
		sm := newTestChunkingManager(t.TempDir())

		data := bytes.Repeat([]byte("p"), 64)
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(data),
			Size:      int64(len(data)),
			MediaType: "application/octet-stream",
		}

		// Leftover complete file from a previous run.
		blobPath := sm.tempStore.BlobPath(desc.Digest)
		So(os.WriteFile(blobPath, data, 0o600), ShouldBeNil)

		So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)

		// Client connects while the reader is still uninitialized.
		var clientBuf bytes.Buffer
		copier, err := sm.ConnectClient(desc.Digest.String(), &clientBuf)
		So(err, ShouldBeNil)

		copyErr := make(chan error, 1)
		go func() { copyErr <- copier.Copy() }()

		// Give the copier time to block waiting for the descriptor/announcements.
		time.Sleep(100 * time.Millisecond)

		select {
		case err := <-copyErr:
			t.Fatalf("copy finished before init: %v", err)
		default:
		}

		// The sync hook arrives late and takes the Plan A path
		// (blob already complete on disk -> InitReaderComplete).
		wrapped, err := sm.StreamingBlobReader(newTestBReader(data))
		So(err, ShouldBeNil)
		So(wrapped, ShouldNotBeNil)

		select {
		case err := <-copyErr:
			So(err, ShouldBeNil)
		case <-time.After(5 * time.Second):
			t.Fatal("client copy still hanging after InitReaderComplete")
		}

		So(clientBuf.Bytes(), ShouldResemble, data)
	})
}

func TestChunkingManagerClaimBlobStream(t *testing.T) {
	Convey("ClaimBlobStream", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		data := []byte("priority fetched blob data")
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(data),
			Size:      int64(len(data)),
			MediaType: "application/octet-stream",
		}

		Convey("does not claim a blob without an active stream", func() {
			So(sm.NeedsUpstreamData(desc.Digest.String()), ShouldBeFalse)

			wrapped, claimed, err := sm.ClaimBlobStream(newTestBReader(data))
			So(err, ShouldBeNil)
			So(claimed, ShouldBeFalse)
			So(wrapped, ShouldBeNil)
		})

		Convey("claims an uninitialized stream and pumps data to disk and clients", func() {
			So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)
			So(sm.NeedsUpstreamData(desc.Digest.String()), ShouldBeTrue)

			cbr := sm.activeStreams[desc.Digest.String()]
			offsets, _ := cbr.Subscribe()

			wrapped, claimed, err := sm.ClaimBlobStream(newTestBReader(data))
			So(err, ShouldBeNil)
			So(claimed, ShouldBeTrue)
			So(wrapped, ShouldNotBeNil)

			// The claim marks the stream as being fed.
			So(sm.NeedsUpstreamData(desc.Digest.String()), ShouldBeFalse)

			// A concurrent claim of the same blob must fail.
			dupWrapped, dupClaimed, dupErr := sm.ClaimBlobStream(newTestBReader(data))
			So(dupErr, ShouldBeNil)
			So(dupClaimed, ShouldBeFalse)
			So(dupWrapped, ShouldBeNil)

			// Pumping the wrapped reader writes the bytes to the temp file.
			written, copyErr := io.Copy(io.Discard, wrapped)
			So(copyErr, ShouldBeNil)
			So(written, ShouldEqual, desc.Size)

			onDisk, readErr := os.ReadFile(sm.tempStore.BlobPath(desc.Digest))
			So(readErr, ShouldBeNil)
			So(onDisk, ShouldResemble, data)

			// The subscriber received the final on-disk offset.
			So(<-offsets, ShouldEqual, desc.Size)
			So(cbr.Completed(), ShouldBeTrue)
		})

		Convey("does not claim a stream already initialized by the sync hook", func() {
			So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)

			hooked, err := sm.StreamingBlobReader(newTestBReader(data))
			So(err, ShouldBeNil)
			So(hooked, ShouldNotBeNil)

			wrapped, claimed, err := sm.ClaimBlobStream(newTestBReader(data))
			So(err, ShouldBeNil)
			So(claimed, ShouldBeFalse)
			So(wrapped, ShouldBeNil)
		})

		Convey("marks an already-complete on-disk blob complete instead of claiming", func() {
			So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)

			// Simulate a complete file left by a previous attempt, then
			// re-create the chunked reader so it picks up the resume offset.
			blobPath := sm.tempStore.BlobPath(desc.Digest)
			So(os.WriteFile(blobPath, data, 0o644), ShouldBeNil)

			cbr, cbrErr := NewChunkedBlobReader(blobPath, sm.logger)
			So(cbrErr, ShouldBeNil)
			sm.activeStreams[desc.Digest.String()] = cbr

			offsets, _ := cbr.Subscribe()

			wrapped, claimed, err := sm.ClaimBlobStream(newTestBReader(data))
			So(err, ShouldBeNil)
			So(claimed, ShouldBeFalse)
			So(wrapped, ShouldBeNil)

			// Waiting clients were notified that the whole blob is on disk.
			So(<-offsets, ShouldEqual, desc.Size)
			So(cbr.Completed(), ShouldBeTrue)
			So(sm.NeedsUpstreamData(desc.Digest.String()), ShouldBeFalse)
		})

		Convey("does not claim an aborted stream", func() {
			So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)
			sm.activeStreams[desc.Digest.String()].Abort()

			wrapped, claimed, err := sm.ClaimBlobStream(newTestBReader(data))
			So(err, ShouldBeNil)
			So(claimed, ShouldBeFalse)
			So(wrapped, ShouldBeNil)
			So(sm.NeedsUpstreamData(desc.Digest.String()), ShouldBeFalse)
		})
	})
}
