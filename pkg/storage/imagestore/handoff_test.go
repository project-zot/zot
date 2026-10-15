package imagestore_test

import (
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

func TestDeleteDedupeOrigin(t *testing.T) {
	Convey("Deleting the dedupe origin removes it and leaves the next copy readable", t, func() {
		content := []byte("handoff-content")

		for _, testCase := range []struct {
			name      string
			driver    storageTypes.Driver
			relPaths  bool
			digest    godigest.Digest
			origin    []byte
			nextCopy  []byte
			nextAfter []byte
		}{
			{
				// the hand-off moves the origin onto the placeholder, which removes it
				name:   "remote, next copy is a placeholder",
				driver: &remoteNamedDriver{Driver: local.New(true)},
				digest: godigest.FromBytes(content), origin: content, nextCopy: []byte{}, nextAfter: content,
			},
			{
				// the hand-off has nothing to do, so the delete must remove the origin itself
				name:   "remote, next copy already holds the content",
				driver: &remoteNamedDriver{Driver: local.New(true)},
				digest: godigest.FromBytes(content), origin: content, nextCopy: content, nextAfter: content,
			},
			{
				name:   "remote, empty digest",
				driver: &remoteNamedDriver{Driver: local.New(true)},
				digest: godigest.FromBytes(nil), origin: []byte{}, nextCopy: []byte{}, nextAfter: []byte{},
			},
			{
				// older dedupe walks recorded zero-size local copies without repairing them: the
				// origin's content moves onto such a copy instead of being lost with the origin
				name:     "local, next copy is a corrupt zero-size copy",
				driver:   local.New(true),
				relPaths: true,
				digest:   godigest.FromBytes(content), origin: content, nextCopy: []byte{}, nextAfter: content,
			},
			{
				// relative cache paths, as local storage uses
				name:     "local",
				driver:   local.New(true),
				relPaths: true,
				digest:   godigest.FromBytes(content), origin: content, nextCopy: content, nextAfter: content,
			},
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

				plant := func(repo string, body []byte) string {
					So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

					blobPath := imgStore.BlobPath(repo, testCase.digest)
					So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
					So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
					So(cacheDriver.PutBlob(testCase.digest, blobPath), ShouldBeNil)

					return blobPath
				}

				origin := plant("repo-origin", testCase.origin)
				nextCopy := plant("repo-copy", testCase.nextCopy)

				So(imgStore.DeleteBlob("repo-origin", testCase.digest), ShouldBeNil)

				_, err = os.Stat(origin)
				So(os.IsNotExist(err), ShouldBeTrue)

				// the cache no longer records the deleted copy, and points at the next one
				So(cacheDriver.HasBlob(testCase.digest, origin), ShouldBeFalse)

				record, err := cacheDriver.GetBlob(testCase.digest)
				So(err, ShouldBeNil)

				if testCase.relPaths {
					record = path.Join(dir, record)
				}

				So(record, ShouldEqual, nextCopy)

				data, err := os.ReadFile(nextCopy)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, testCase.nextAfter)
			})
		}
	})

	Convey("Deleting the dedupe origin succeeds when the next copy has gone", t, func() {
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

		ctx := context.Background()
		content := []byte("handoff-content")
		digest := godigest.FromBytes(content)

		var copies []string

		for _, repo := range []string{"repo-origin", "repo-copy"} {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, content, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

			copies = append(copies, blobPath)
		}

		// the cache still records the next copy, which is no longer on storage
		So(os.Remove(copies[1]), ShouldBeNil)

		So(imgStore.DeleteBlob("repo-origin", digest), ShouldBeNil)

		_, err = os.Stat(copies[0])
		So(os.IsNotExist(err), ShouldBeTrue)
	})
}
