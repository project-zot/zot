package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

// The store here has no cache at all, which is what the blob-ref index looks like to the
// reclaim gate after a recovery from a fresh local root: every lookup is a cache miss, and
// the only evidence that a repository owns a digest is its own manifest graph.
func TestGlobalBlobReclaimChecksOtherRepoManifests(t *testing.T) {
	Convey("the reclaim gate reconstructs ownership from other repositories' manifests", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		rootDir := t.TempDir()

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			local.New(true), nil, nil, nil)

		const (
			owner = "owner"
			other = "other"
		)

		layerContent := []byte("layer-owned-without-a-blob-ref")
		layerDigest := godigest.FromBytes(layerContent)
		_, _, err := store.FullBlobUpload(context.Background(), owner, bytes.NewReader(layerContent), layerDigest)
		So(err, ShouldBeNil)

		_, _, err = store.FullBlobUpload(context.Background(), owner,
			bytes.NewReader(ispec.DescriptorEmptyJSON.Data), ispec.DescriptorEmptyJSON.Digest)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Config:    ispec.DescriptorEmptyJSON,
			Layers: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageLayer, Digest: layerDigest, Size: int64(len(layerContent))},
			},
			SchemaVersion: 2,
		}

		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest, _, err := store.PutImageManifest(context.Background(), owner, "tag",
			ispec.MediaTypeImageManifest, manifestBuf, nil)
		So(err, ShouldBeNil)

		So(store.InitRepo(context.Background(), other), ShouldBeNil)

		Convey("a digest another repository's manifest reaches is still referenced", func() {
			for _, digest := range []godigest.Digest{layerDigest, manifestDigest, ispec.DescriptorEmptyJSON.Digest} {
				referenced, err := imagestore.IsDigestReferencedOutsideRepo(store, other, digest)
				So(err, ShouldBeNil)
				So(referenced, ShouldBeTrue)
			}
		})

		Convey("the repository giving up its reference does not count as an owner", func() {
			referenced, err := imagestore.IsDigestReferencedOutsideRepo(store, owner, layerDigest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("a digest no manifest reaches is not referenced", func() {
			referenced, err := imagestore.IsDigestReferencedOutsideRepo(store, other, godigest.FromString("unowned"))
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("a remembered graph is only ever stale towards keeping the blob", func() {
			imagestore.SetRepoGraphRefsTTL(store, time.Hour)

			referenced, err := imagestore.IsDigestReferencedOutsideRepo(store, other, layerDigest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)

			So(store.DeleteImageManifest(context.Background(), owner, manifestDigest.String(), false), ShouldBeNil)

			referenced, err = imagestore.IsDigestReferencedOutsideRepo(store, other, layerDigest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)

			// Once the index is re-read the dropped reference is seen and the blob may go.
			imagestore.SetRepoGraphRefsTTL(store, 0)

			referenced, err = imagestore.IsDigestReferencedOutsideRepo(store, other, layerDigest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("an unreadable manifest graph fails closed", func() {
			indexPath := path.Join(rootDir, owner, ispec.ImageIndexFile)
			So(os.WriteFile(indexPath, []byte("not json"), 0o600), ShouldBeNil)

			referenced, err := imagestore.IsDigestReferencedOutsideRepo(store, other, godigest.FromString("unowned"))
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)
		})

		Convey("a repository removed after it was listed references nothing", func() {
			imagestore.SetRepoGraphRefsTTL(store, time.Hour)

			referenced, err := imagestore.IsDigestReferencedOutsideRepo(store, other, layerDigest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)

			So(os.RemoveAll(path.Join(rootDir, owner)), ShouldBeNil)
			imagestore.SetRepoGraphRefsTTL(store, 0)

			referenced, err = imagestore.IsDigestReferencedOutsideRepo(store, other, layerDigest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})
	})
}
