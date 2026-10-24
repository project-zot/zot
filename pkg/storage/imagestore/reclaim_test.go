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

	Convey("After the cache is lost the sweep waits for the dedupe walk", t, func() {
		dir := t.TempDir()
		ctx := context.Background()

		openStore := func() storageTypes.ImageStore {
			// each store gets a cache of its own: the second one has lost what the first recorded
			return imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(),
				monitoring.NewNopMetricServer(), nil, &remoteNamedDriver{Driver: local.New(true)},
				newBoltCacheAbs(t.TempDir()), nil, nil)
		}

		firstStore := openStore()
		So(firstStore, ShouldNotBeNil)

		repoPaths := []string{}

		for _, repo := range []string{"repo-a", "repo-b"} {
			_, _, err := firstStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			repoPaths = append(repoPaths, firstStore.BlobPath(repo, digest))
		}

		globalBlobPath := firstStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)

		// the migration marker skips the upgrade, so the new cache knows none of the placeholders
		store := openStore()
		So(store, ShouldNotBeNil)

		// a push and delete since record the payload as owned by repo-c alone, then as unowned
		_, _, err := store.FullBlobUpload(ctx, "repo-c", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(store.DeleteBlob("repo-c", digest), ShouldBeNil)

		So(sweep(store, 0), ShouldBeNil)
		So(exists(globalBlobPath), ShouldBeTrue)

		for _, repo := range []string{"repo-a", "repo-b"} {
			data, err := store.GetBlobContent(repo, digest)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		}

		Convey("and once the walk has recorded the placeholders, it leaves the payload they own", func() {
			So(store.RunDedupeForDigest(ctx, digest, true, repoPaths), ShouldBeNil)
			imagestore.FinishDedupeWalk(store)

			So(sweep(store, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
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

	Convey("A sweep whose claim comes back past the delete deadline leaves the payload", t, func() {
		dir := t.TempDir()
		hooked := &hookedClaimCache{Cache: newBoltCacheAbs(dir)}
		imgStore := imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, &remoteNamedDriver{Driver: local.New(true)}, hooked, nil, nil)
		ctx := context.Background()
		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		// the window runs from asking for the claim, so a slow answer uses it up
		imagestore.SetReclaimDeleteDeadline(imgStore, 50*time.Millisecond)

		hooked.afterClaim = func() {
			hooked.afterClaim = nil

			time.Sleep(100 * time.Millisecond)
		}

		So(errors.Is(sweep(imgStore, 0), zerr.ErrReclaimClaimLost), ShouldBeTrue)
		So(exists(globalBlobPath), ShouldBeTrue)

		// the claim was given up, so a push owns the payload at once
		imagestore.SetLinkerClaimWait(imgStore, 0)

		_, _, err = imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		data, err := imgStore.GetBlobContent("repo-b", digest)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("A push right after a sweep releases its claim keeps the origin it records", t, func() {
		dir := t.TempDir()
		hooked := &hookedClaimCache{Cache: newBoltCacheAbs(dir)}
		imgStore := imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, &remoteNamedDriver{Driver: local.New(true)}, hooked, nil, nil)
		ctx := context.Background()

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		// a push that waited on the claim stores a new payload at the same path as soon as it is released
		var pushErr error

		hooked.afterFinish = func() {
			hooked.afterFinish = nil
			_, _, pushErr = imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
		}

		So(sweep(imgStore, 0), ShouldBeNil)
		So(pushErr, ShouldBeNil)

		origin, err := hooked.GetBlob(digest)
		So(err, ShouldBeNil)
		So(origin, ShouldEqual, imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest))

		data, err := imgStore.GetBlobContent("repo-b", digest)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("A last owner going while a sweep decides keeps its payload marked", t, func() {
		dir := t.TempDir()
		hooked := &hookedClaimCache{Cache: newBoltCacheAbs(dir)}
		imgStore := imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, &remoteNamedDriver{Driver: local.New(true)}, hooked, nil, nil)
		ctx := context.Background()

		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		markerPath := path.Join(dir, storageConstants.GlobalBlobsRepo, "_reclaim", digest.Algorithm().String(),
			digest.Encoded())

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)
		So(exists(markerPath), ShouldBeTrue)

		Convey("when the sweep found it owned", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			// the sweep sees repo-b's ownership, then repo-b goes, finding the marker in place
			hooked.afterClaim = func() {
				So(imgStore.DeleteBlob("repo-b", digest), ShouldBeNil)
			}

			So(sweep(imgStore, 0), ShouldBeNil)
			So(exists(markerPath), ShouldBeTrue)

			hooked.afterClaim = nil

			So(sweep(imgStore, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeFalse)
		})

		Convey("when the sweep reclaimed it and the content came back", func() {
			// a push stores the content again right after the reclaim, and its copy then goes
			hooked.afterFinish = func() {
				_, _, err := imgStore.FullBlobUpload(ctx, "repo-c", bytes.NewReader(content), digest)
				So(err, ShouldBeNil)
				So(imgStore.DeleteBlob("repo-c", digest), ShouldBeNil)
			}

			So(sweep(imgStore, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			So(exists(markerPath), ShouldBeTrue)

			hooked.afterFinish = nil

			So(sweep(imgStore, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeFalse)
		})
	})

	Convey("A local store has nothing to sweep", t, func() {
		dir := t.TempDir()
		imgStore, _ := newLocalDedupeStoreAt(dir, local.New(true))

		So(sweep(imgStore, 0), ShouldBeNil)
	})
}

// hookedClaimCache runs afterClaim once ClaimReclaim has decided, and afterFinish once
// FinishReclaim has, to play out another writer acting inside a sweep.
type hookedClaimCache struct {
	storageTypes.Cache

	afterClaim  func()
	afterFinish func()
}

func (c *hookedClaimCache) ClaimReclaim(digest godigest.Digest) (storageTypes.ReclaimClaim, error) {
	claim, err := c.Cache.ClaimReclaim(digest)
	if c.afterClaim != nil {
		c.afterClaim()
	}

	return claim, err
}

func (c *hookedClaimCache) FinishReclaim(claim storageTypes.ReclaimClaim) error {
	err := c.Cache.FinishReclaim(claim)
	if c.afterFinish != nil {
		c.afterFinish()
	}

	return err
}
