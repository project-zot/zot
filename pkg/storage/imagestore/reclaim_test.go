package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// reclaimer is the sweep entry point a store offers to the GC scheduler.
type reclaimer interface {
	ReclaimGlobalBlobs(ctx context.Context, delay time.Duration) error
}

func sweep(imgStore storageTypes.ImageStore, delay time.Duration) error {
	store, ok := imgStore.(reclaimer)
	So(ok, ShouldBeTrue)

	return store.ReclaimGlobalBlobs(context.Background(), delay)
}

func TestReclaimGlobalBlobs(t *testing.T) {
	content := []byte("reclaim-sweep-content")
	digest := godigest.FromBytes(content)

	exists := func(blobPath string) bool {
		_, err := os.Stat(blobPath)

		return err == nil
	}

	Convey("The sweep deletes a remote payload once nothing owns it", t, func() {
		dir := t.TempDir()
		imgStore, cacheDriver := newRemoteDedupeStoreAt(dir)
		ctx := context.Background()

		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		markerPath := path.Join(dir, storageConstants.GlobalBlobsRepo, "_reclaim", digest.Algorithm().String(),
			digest.Encoded())

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		Convey("it leaves an owned payload alone, and there is no marker to act on", func() {
			So(sweep(imgStore, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
		})

		So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)
		So(exists(markerPath), ShouldBeTrue)

		Convey("it waits until the marker is older than the delay", func() {
			So(sweep(imgStore, time.Hour), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			So(exists(markerPath), ShouldBeTrue)
		})

		Convey("it deletes the payload and forgets it everywhere", func() {
			So(sweep(imgStore, 0), ShouldBeNil)

			So(exists(globalBlobPath), ShouldBeFalse)
			So(exists(markerPath), ShouldBeFalse)

			_, err := cacheDriver.GetReferences(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)

			origin, err := cacheDriver.GetBlob(digest)
			So(err != nil || origin == "", ShouldBeTrue)

			// a later push stores the content again
			_, _, err = imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			data, err := os.ReadFile(globalBlobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		})

		Convey("a push before the sweep owns the payload again, and the sweep drops the marker", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			So(sweep(imgStore, 0), ShouldBeNil)

			So(exists(globalBlobPath), ShouldBeTrue)
			So(exists(markerPath), ShouldBeFalse)
		})

		Convey("a digest another sweep has claimed is skipped", func() {
			claim, err := cacheDriver.ClaimReclaim(digest)
			So(err, ShouldBeNil)

			So(sweep(imgStore, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			So(exists(markerPath), ShouldBeTrue)

			So(cacheDriver.AbandonReclaim(claim), ShouldBeNil)
		})

		Convey("an unreadable marker is taken as old", func() {
			So(os.WriteFile(markerPath, []byte("not json"), storageConstants.DefaultFilePerms), ShouldBeNil)

			So(sweep(imgStore, time.Hour), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeFalse)
		})

		Convey("two sweeps at once delete it once, without error", func() {
			store, ok := imgStore.(reclaimer)
			So(ok, ShouldBeTrue)

			var wait sync.WaitGroup

			errs := make([]error, 2) //nolint:mnd

			for i := range errs {
				wait.Go(func() {
					errs[i] = store.ReclaimGlobalBlobs(context.Background(), 0)
				})
			}

			wait.Wait()

			So(errs[0], ShouldBeNil)
			So(errs[1], ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeFalse)
		})
	})

	Convey("The sweep keeps a payload whose ownership the cache cannot tell", t, func() {
		dir := t.TempDir()
		imgStore, _ := newRemoteDedupeStoreAt(dir)

		// a payload and its marker, but no record in the reference index, as after a lost cache
		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		markerPath := path.Join(dir, storageConstants.GlobalBlobsRepo, "_reclaim", digest.Algorithm().String(),
			digest.Encoded())

		So(os.MkdirAll(path.Dir(globalBlobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(globalBlobPath, content, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(os.MkdirAll(path.Dir(markerPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(markerPath, []byte(`{"markedAt":"2020-01-01T00:00:00Z"}`),
			storageConstants.DefaultFilePerms), ShouldBeNil)

		So(sweep(imgStore, 0), ShouldBeNil)
		So(exists(globalBlobPath), ShouldBeTrue)
		So(exists(markerPath), ShouldBeTrue)
	})

	Convey("A sweep whose payload delete fails gives up its claim, for the next one to retry", t, func() {
		dir := t.TempDir()
		storeDriver := &faultyDriver{Driver: local.New(true)}
		boltCache := newBoltCacheAbs(dir)
		imgStore := imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, &remoteNamedDriver{Driver: storeDriver}, boltCache, nil, nil)
		ctx := context.Background()

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		storeDriver.fail = func(op, p string) bool {
			return op == "Delete" && inGlobalBlobstore(p) && !strings.Contains(p, "/_reclaim/")
		}

		So(errors.Is(sweep(imgStore, 0), errInjectedFault), ShouldBeTrue)

		// the claim is gone, so a push owns the payload at once
		imagestore.SetLinkerClaimWait(imgStore, 0)

		_, _, err = imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
	})

	Convey("A local store has nothing to sweep", t, func() {
		dir := t.TempDir()
		imgStore, _ := newLocalDedupeStoreAt(dir, local.New(true))

		So(sweep(imgStore, 0), ShouldBeNil)
	})
}
