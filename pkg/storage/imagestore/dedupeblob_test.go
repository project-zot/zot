package imagestore_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestDedupeBlobOriginWithoutContent(t *testing.T) {
	Convey("A push is not linked to a dedupe origin that has no content", t, func() {
		content := []byte("dedupe-origin-content")
		digest := godigest.FromBytes(content)

		for _, testCase := range []struct {
			name     string
			driver   storageTypes.Driver
			relPaths bool
		}{
			{"remote", &remoteNamedDriver{Driver: local.New(true)}, false},
			{"local", local.New(true), true},
		} {
			Convey(testCase.name, func() {
				dir := t.TempDir()
				log := zlog.NewTestLogger()

				cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: testCase.relPaths,
				}, log)
				So(err, ShouldBeNil)

				imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
					testCase.driver, cacheDriver, nil, nil)

				ctx := context.Background()

				// the cache names an empty copy as the origin: a placeholder whose content was
				// lost, or a corrupt local copy recorded by an older dedupe walk. Another repo
				// shares it: a hardlink locally, a placeholder remotely.
				emptyOrigin := ""

				for _, repo := range []string{"repo-empty", "repo-other"} {
					So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

					blobPath := imgStore.BlobPath(repo, digest)
					So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)

					if emptyOrigin == "" || !testCase.relPaths {
						So(os.WriteFile(blobPath, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
					} else {
						So(os.Link(emptyOrigin, blobPath), ShouldBeNil)
					}

					So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

					if emptyOrigin == "" {
						emptyOrigin = blobPath
					}
				}

				_, size, err := imgStore.FullBlobUpload(ctx, "repo-push", bytes.NewReader(content), digest)
				So(err, ShouldBeNil)
				So(size, ShouldEqual, len(content))

				// the push repaired the origin rather than replacing it, so every repo reads it
				data, err := os.ReadFile(emptyOrigin)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

				for _, repo := range []string{"repo-empty", "repo-other", "repo-push"} {
					ok, blobSize, err := imgStore.CheckBlob(ctx, repo, digest)
					So(err, ShouldBeNil)
					So(ok, ShouldBeTrue)
					So(blobSize, ShouldEqual, len(content))
				}

				record, err := cacheDriver.GetBlob(digest)
				So(err, ShouldBeNil)

				if testCase.relPaths {
					record = path.Join(dir, record)
				}

				So(record, ShouldEqual, emptyOrigin)
				So(cacheDriver.HasBlob(digest, imgStore.BlobPath("repo-push", digest)), ShouldBeTrue)
			})
		}
	})
}

func TestDedupeBlobRepairsSharedContent(t *testing.T) {
	Convey("Pushing a blob again over wrong shared content repairs every copy of it", t, func() {
		// a truncated inode, and one truncated to nothing
		for _, corruptSize := range []int64{3, 0} {
			Convey(fmt.Sprintf("shared content cut to %d bytes", corruptSize), func() {
				testRepairSharedContent(t, corruptSize)
			})
		}
	})
}

// testRepairSharedContent pushes a blob again after cutting the inode two repos share to
// corruptSize bytes, and checks that both copies are repaired.
func testRepairSharedContent(t *testing.T, corruptSize int64) {
	t.Helper()

	dir := t.TempDir()
	log := zlog.NewTestLogger()

	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)
	So(err, ShouldBeNil)

	imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
		local.New(true), cacheDriver, nil, nil)

	storeController := storage.StoreController{DefaultStore: imgStore}

	img := image.CreateRandomImage()
	So(image.WriteImageToFileSystem(img, "repo-a", "tag", storeController), ShouldBeNil)
	So(image.WriteImageToFileSystem(img, "repo-b", "tag", storeController), ShouldBeNil)

	layer := img.Layers[0]
	digest := godigest.FromBytes(layer)
	origin := imgStore.BlobPath("repo-a", digest)
	copyB := imgStore.BlobPath("repo-b", digest)

	// both copies are links to one inode, so truncating it corrupts both
	So(os.Truncate(origin, corruptSize), ShouldBeNil)

	data, err := os.ReadFile(copyB)
	So(err, ShouldBeNil)
	So(data, ShouldHaveLength, corruptSize)

	_, _, err = imgStore.FullBlobUpload(context.Background(), "repo-b", bytes.NewReader(layer), digest)
	So(err, ShouldBeNil)

	// a rename would have repaired only repo-b's path; the origin and its links stay wrong
	for _, blobPath := range []string{origin, copyB} {
		data, err := os.ReadFile(blobPath)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, layer)
	}
}
