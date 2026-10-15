package imagestore_test

import (
	"bytes"
	"context"
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
				// lost, or a corrupt local copy recorded by an older dedupe walk
				So(imgStore.InitRepo(ctx, "repo-empty"), ShouldBeNil)

				emptyOrigin := imgStore.BlobPath("repo-empty", digest)
				So(os.MkdirAll(path.Dir(emptyOrigin), storageConstants.DefaultDirPerms), ShouldBeNil)
				So(os.WriteFile(emptyOrigin, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
				So(cacheDriver.PutBlob(digest, emptyOrigin), ShouldBeNil)

				_, size, err := imgStore.FullBlobUpload(ctx, "repo-push", bytes.NewReader(content), digest)
				So(err, ShouldBeNil)
				So(size, ShouldEqual, len(content))

				pushed := imgStore.BlobPath("repo-push", digest)

				data, err := os.ReadFile(pushed)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

				// the push is now the origin, and still records the empty copy
				record, err := cacheDriver.GetBlob(digest)
				So(err, ShouldBeNil)

				if testCase.relPaths {
					record = path.Join(dir, record)
				}

				So(record, ShouldEqual, pushed)
				So(cacheDriver.HasBlob(digest, emptyOrigin), ShouldBeTrue)

				ok, blobSize, err := imgStore.CheckBlob(ctx, "repo-push", digest)
				So(err, ShouldBeNil)
				So(ok, ShouldBeTrue)
				So(blobSize, ShouldEqual, len(content))
			})
		}
	})
}
