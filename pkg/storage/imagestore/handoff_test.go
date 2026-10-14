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
)

func TestDeleteDedupeOriginRemoteLifecycle(t *testing.T) {
	Convey("Deleting the dedupe origin of the empty digest removes it, with a copy left behind", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		// absolute cache paths, as remote storage uses: only then does a delete recognise
		// the cache origin and hand its content off to the next copy
		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			&remoteNamedDriver{Driver: local.New(true)}, cacheDriver, nil, nil)

		ctx := context.Background()
		emptyDigest := godigest.FromBytes(nil)

		var copies []string

		for _, repo := range []string{"repo-origin", "repo-copy"} {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, emptyDigest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(cacheDriver.PutBlob(emptyDigest, blobPath), ShouldBeNil)

			copies = append(copies, blobPath)
		}

		So(imgStore.DeleteBlob("repo-origin", emptyDigest), ShouldBeNil)

		_, err = os.Stat(copies[0])
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(copies[1])
		So(err, ShouldBeNil)
	})
}
