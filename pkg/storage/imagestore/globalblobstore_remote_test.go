package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// newRemoteDedupeStoreAt returns a store over dir that takes the remote lifecycle, with dedupe on
// and a BoltDB cache recording absolute paths, as remote storage does.
func newRemoteDedupeStoreAt(dir string) (storageTypes.ImageStore, storageTypes.Cache) {
	log := zlog.NewTestLogger()

	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir: dir,
		Name:    "cache",
	}, log)
	So(err, ShouldBeNil)

	return imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
		&remoteNamedDriver{Driver: local.New(true)}, cacheDriver, nil, nil), cacheDriver
}

func TestRemoteGlobalBlobstore(t *testing.T) {
	content := []byte("remote-global-blobstore-content")
	digest := godigest.FromBytes(content)

	fileSize := func(blobPath string) int64 {
		info, err := os.Stat(blobPath)
		So(err, ShouldBeNil)

		return info.Size()
	}

	Convey("A remote store keeps a pushed payload once, in the global blobstore", t, func() {
		dir := t.TempDir()
		imgStore, cacheDriver := newRemoteDedupeStoreAt(dir)
		ctx := context.Background()

		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		repoA := imgStore.BlobPath("repo-a", digest)

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		Convey("the first push moves the content there, and the repo gets a placeholder", func() {
			data, err := os.ReadFile(globalBlobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
			So(fileSize(repoA), ShouldEqual, 0)

			origin, err := cacheDriver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, globalBlobPath)
		})

		Convey("the repo owns the payload, so no sweep can claim it", func() {
			refs, err := cacheDriver.GetReferences(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldResemble, []string{repoA})

			_, err = cacheDriver.ClaimReclaim(digest)
			So(errors.Is(err, zerr.ErrDigestReferenced), ShouldBeTrue)
		})

		Convey("later pushes and mounts own the same payload through placeholders", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, _, err := imgStore.CheckBlob(ctx, "repo-c", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)

			for _, repo := range []string{"repo-b", "repo-c"} {
				So(fileSize(imgStore.BlobPath(repo, digest)), ShouldEqual, 0)

				reader, _, err := imgStore.GetBlob(repo, digest, "application/octet-stream")
				So(err, ShouldBeNil)

				data, err := io.ReadAll(reader)
				So(err, ShouldBeNil)
				So(reader.Close(), ShouldBeNil)
				So(data, ShouldResemble, content)
			}

			refs, err := cacheDriver.GetReferences(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldHaveLength, 3)
		})

		Convey("a push over wrong content repairs the payload every placeholder reads", func() {
			So(os.WriteFile(globalBlobPath, []byte("x"), storageConstants.DefaultFilePerms), ShouldBeNil)

			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			data, err := os.ReadFile(globalBlobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		})
	})

	Convey("A push waits for a reclaim sweep's claim on its digest to clear", t, func() {
		dir := t.TempDir()
		imgStore, cacheDriver := newRemoteDedupeStoreAt(dir)
		imagestore.SetLinkerClaimWait(imgStore, 300*time.Millisecond)
		ctx := context.Background()

		// a sweep has claimed an unowned payload for deletion
		So(cacheDriver.RecordGlobal(digest), ShouldBeNil)

		claim, err := cacheDriver.ClaimReclaim(digest)
		So(err, ShouldBeNil)

		Convey("and fails transiently while the claim is held", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrDigestClaimed), ShouldBeTrue)

			_, err = cacheDriver.GetReferences(digest)
			So(err, ShouldBeNil)

			// the sweep gives up, and the next push owns the payload
			So(cacheDriver.AbandonReclaim(claim), ShouldBeNil)

			_, _, err = imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)
		})

		Convey("and proceeds once the sweep finishes, promoting its own upload", func() {
			imagestore.SetLinkerClaimWait(imgStore, 5*time.Second)

			finished := make(chan error, 1)

			go func() {
				time.Sleep(300 * time.Millisecond)

				finished <- cacheDriver.FinishReclaim(claim)
			}()

			_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)
			So(<-finished, ShouldBeNil)

			data, err := os.ReadFile(imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest))
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)

			refs, err := cacheDriver.GetReferences(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldResemble, []string{imgStore.BlobPath("repo-a", digest)})
		})
	})
}
