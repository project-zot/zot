//go:build sync

package stream

import (
	"context"
	"os"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/log"
)

// eventually polls the condition until it holds or the timeout elapses.
func eventually(cond func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		if cond() {
			return true
		}

		time.Sleep(5 * time.Millisecond)
	}

	return cond()
}

func TestPriorityFetcher(t *testing.T) {
	Convey("PriorityFetcher", t, func() {
		sm := newTestChunkingManager(t.TempDir())

		data := []byte("priority fetched layer data")
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(data),
			Size:      int64(len(data)),
			MediaType: "application/octet-stream",
		}

		blobData := map[string][]byte{desc.Digest.String(): data}

		opened := make(chan string, 16)
		openBlob := func(_ context.Context, repo string, d descriptor.Descriptor) (*blob.BReader, error) {
			opened <- repo + "@" + d.Digest.String()

			return newTestBReader(blobData[d.Digest.String()]), nil
		}

		fetcher := NewPriorityFetcher(sm, openBlob, 0, log.NewTestLogger())

		Convey("PrioritizeBlob fetches an unfed blob and completes its stream", func() {
			So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)
			cbr := sm.activeStreams[desc.Digest.String()]

			fetcher.PrioritizeBlob("myrepo", desc.Digest)

			So(<-opened, ShouldEqual, "myrepo@"+desc.Digest.String())
			So(eventually(cbr.Completed), ShouldBeTrue)

			onDisk, err := os.ReadFile(sm.tempStore.BlobPath(desc.Digest))
			So(err, ShouldBeNil)
			So(onDisk, ShouldResemble, data)
		})

		Convey("PrioritizeBlob skips blobs already being fed", func() {
			So(sm.prepareActiveStreamForBlob(desc), ShouldBeNil)

			// The sync hook already claimed this blob.
			_, err := sm.StreamingBlobReader(newTestBReader(data))
			So(err, ShouldBeNil)

			fetcher.PrioritizeBlob("myrepo", desc.Digest)
			So(len(opened), ShouldEqual, 0)
		})

		Convey("PrioritizeBlob skips blobs without an active stream", func() {
			fetcher.PrioritizeBlob("myrepo", desc.Digest)
			So(len(opened), ShouldEqual, 0)
		})

		Convey("markInFlight deduplicates per digest", func() {
			So(fetcher.markInFlight("sha256:abc"), ShouldBeTrue)
			So(fetcher.markInFlight("sha256:abc"), ShouldBeFalse)
			So(fetcher.markInFlight("sha256:def"), ShouldBeTrue)

			fetcher.unmarkInFlight("sha256:abc")
			So(fetcher.markInFlight("sha256:abc"), ShouldBeTrue)
		})

		Convey("PrefetchManifestBlobs fetches the config and layers of a platform manifest", func() {
			configData := []byte("config blob data")
			layerData := []byte("layer blob data")
			mfst := newTestOCIManifestWithBlobs(t, configData, layerData)

			configDigest := godigest.FromBytes(configData)
			layerDigest := godigest.FromBytes(layerData)
			blobData[configDigest.String()] = configData
			blobData[layerDigest.String()] = layerData

			for _, d := range []descriptor.Descriptor{
				{Digest: configDigest, Size: int64(len(configData)), MediaType: "application/vnd.oci.image.config.v1+json"},
				{Digest: layerDigest, Size: int64(len(layerData)), MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			} {
				So(sm.prepareActiveStreamForBlob(d), ShouldBeNil)
			}

			fetcher.PrefetchManifestBlobs("myrepo", mfst)

			// Both blobs get fetched. Slots are granted in manifest order, but
			// with free slots the two fetch goroutines may invoke openBlob in
			// either order, so assert on the set rather than the sequence.
			fetched := []string{<-opened, <-opened}
			So(fetched, ShouldContain, "myrepo@"+configDigest.String())
			So(fetched, ShouldContain, "myrepo@"+layerDigest.String())

			So(eventually(sm.activeStreams[configDigest.String()].Completed), ShouldBeTrue)
			So(eventually(sm.activeStreams[layerDigest.String()].Completed), ShouldBeTrue)
		})

		Convey("PrefetchManifestBlobs skips blobs that are already fed or unknown", func() {
			configData := []byte("other config data")
			layerData := []byte("other layer data")
			mfst := newTestOCIManifestWithBlobs(t, configData, layerData)

			// Only the layer has an unfed active stream; the config has none.
			layerDigest := godigest.FromBytes(layerData)
			blobData[layerDigest.String()] = layerData
			So(sm.prepareActiveStreamForBlob(descriptor.Descriptor{
				Digest: layerDigest, Size: int64(len(layerData)), MediaType: "application/octet-stream",
			}), ShouldBeNil)

			fetcher.PrefetchManifestBlobs("myrepo", mfst)

			So(<-opened, ShouldEqual, "myrepo@"+layerDigest.String())
			So(eventually(sm.activeStreams[layerDigest.String()].Completed), ShouldBeTrue)
			So(len(opened), ShouldEqual, 0)
		})
	})
}
