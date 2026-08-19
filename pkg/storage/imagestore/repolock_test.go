package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	zlog "zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// Two stores over one directory stand in for two processes over one bucket:
// separate in-process mutexes, one index.
func newSharedStore(t *testing.T, rootDir string, cacheDriver storageTypes.Cache) storageTypes.ImageStore {
	t.Helper()

	return local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
		zlog.NewMetricsServer(false, log.NewTestLogger()), nil, cacheDriver, nil, nil)
}

func TestConcurrentTagWritesAcrossStores(t *testing.T) {
	Convey("Tags pushed concurrently from two stores all survive", t, func() {
		rootDir := t.TempDir()
		miniRedis := miniredis.RunT(t)

		connOpts, err := redis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client := redis.NewClient(connOpts)
		t.Cleanup(func() { _ = client.Close() })

		cacheDriver, err := storage.Create("redis",
			cache.RedisDriverParameters{Client: client, RootDir: rootDir, UseRelPaths: true, KeyPrefix: "zot"},
			log.NewTestLogger())
		So(err, ShouldBeNil)
		So(cacheDriver, ShouldNotBeNil)

		stores := []storageTypes.ImageStore{
			newSharedStore(t, rootDir, cacheDriver),
			newSharedStore(t, rootDir, cacheDriver),
		}

		const (
			repo    = "concurrent/tags"
			tagsNum = 24
		)

		ctx := context.Background()

		content := []byte("{}")
		digest := godigest.FromBytes(content)

		_, _, err = stores[0].FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{}
		manifest.SchemaVersion = 2
		manifest.MediaType = ispec.MediaTypeImageManifest
		manifest.Config = ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    digest,
			Size:      int64(len(content)),
		}
		manifest.Layers = []ispec.Descriptor{{
			MediaType: ispec.MediaTypeImageLayerGzip,
			Digest:    digest,
			Size:      int64(len(content)),
		}}

		body, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		var waitGroup sync.WaitGroup

		errs := make([]error, tagsNum)

		for i := range tagsNum {
			waitGroup.Add(1)

			go func(i int) {
				defer waitGroup.Done()

				_, _, errs[i] = stores[i%len(stores)].PutImageManifest(ctx, repo,
					fmt.Sprintf("t%02d", i), ispec.MediaTypeImageManifest, body, nil)
			}(i)
		}

		waitGroup.Wait()

		for i, err := range errs {
			So(err, ShouldBeNil)
			_ = i
		}

		tags, err := stores[0].GetImageTags(repo)
		So(err, ShouldBeNil)
		So(len(tags), ShouldEqual, tagsNum)
	})
}

// pushTestManifest uploads one shared blob and returns a manifest body referencing it.
func pushTestManifest(t *testing.T, store storageTypes.ImageStore, repo string) []byte {
	t.Helper()

	content := []byte("{}")
	digest := godigest.FromBytes(content)

	_, _, err := store.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
	So(err, ShouldBeNil)

	manifest := ispec.Manifest{}
	manifest.SchemaVersion = 2
	manifest.MediaType = ispec.MediaTypeImageManifest
	manifest.Config = ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Digest:    digest,
		Size:      int64(len(content)),
	}
	manifest.Layers = []ispec.Descriptor{{
		MediaType: ispec.MediaTypeImageLayerGzip,
		Digest:    digest,
		Size:      int64(len(content)),
	}}

	body, err := json.Marshal(manifest)
	So(err, ShouldBeNil)

	return body
}

func newRedisCacheDriver(t *testing.T, rootDir string) storageTypes.Cache {
	t.Helper()

	miniRedis := miniredis.RunT(t)

	connOpts, err := redis.ParseURL("redis://" + miniRedis.Addr())
	So(err, ShouldBeNil)

	client := redis.NewClient(connOpts)
	t.Cleanup(func() { _ = client.Close() })

	cacheDriver, err := storage.Create("redis",
		cache.RedisDriverParameters{Client: client, RootDir: rootDir, UseRelPaths: true, KeyPrefix: "zot"},
		log.NewTestLogger())
	So(err, ShouldBeNil)

	return cacheDriver
}

// TestRepoLockHeldByOtherStoreBlocksPush covers the collection-versus-push contract: while one
// instance holds the repo lock (as gc does for the length of a sweep), another instance's push
// cannot proceed. The push waits rather than failing outright, errors only when its own context
// expires, and succeeds once the holder releases.
func TestRepoLockHeldByOtherStoreBlocksPush(t *testing.T) {
	Convey("A push cannot take the repo lock another store holds, and succeeds after release", t, func() {
		rootDir := t.TempDir()
		cacheDriver := newRedisCacheDriver(t, rootDir)

		stores := []storageTypes.ImageStore{
			newSharedStore(t, rootDir, cacheDriver),
			newSharedStore(t, rootDir, cacheDriver),
		}

		ctx := context.Background()
		repo := "locked/repo"
		body := pushTestManifest(t, stores[0], repo)

		heldLock, err := stores[0].LockRepo(ctx, repo)
		So(err, ShouldBeNil)

		pushCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		_, _, err = stores[1].PutImageManifest(pushCtx, repo, "t1", ispec.MediaTypeImageManifest, body, nil)
		So(errors.Is(err, zerr.ErrRepoLockUnavailable), ShouldBeTrue)

		heldLock.Release()

		_, _, err = stores[1].PutImageManifest(ctx, repo, "t1", ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		tags, err := stores[1].GetImageTags(repo)
		So(err, ShouldBeNil)
		So(tags, ShouldContain, "t1")
	})
}

// failLockCache is a cache driver whose RepoLocker always fails, to prove a write that cannot be
// serialized fails instead of proceeding unlocked.
type failLockCache struct {
	mocks.CacheMock
}

func (failLockCache) LockRepo(context.Context, string) (storageTypes.RepoLock, error) {
	return nil, zerr.ErrRepoLockUnavailable
}

// lostLockCache hands out locks that report themselves lost, simulating a holder that was stalled
// past expiry and resumed after another instance took the lock.
type lostLockCache struct {
	mocks.CacheMock
}

func (lostLockCache) LockRepo(context.Context, string) (storageTypes.RepoLock, error) {
	return mocks.RepoLockMock{StillHeldFn: func(context.Context) bool { return false }}, nil
}

// TestRepoLockLostFenceFailsCommit proves the fence before the index commit: a writer that lost
// the repo lock mid-write fails instead of clobbering another instance's commit.
func TestRepoLockLostFenceFailsCommit(t *testing.T) {
	Convey("A push that lost the repo lock mid-write fails and writes nothing", t, func() {
		rootDir := t.TempDir()
		ctx := context.Background()

		// the blob lands through a store with a working lock
		goodStore := local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
			zlog.NewMetricsServer(false, log.NewTestLogger()), nil, nil, nil, nil)

		body := pushTestManifest(t, goodStore, "repo")

		// the manifest push then goes through a store whose lock reports lost
		store := local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
			zlog.NewMetricsServer(false, log.NewTestLogger()), nil, lostLockCache{}, nil, nil)

		_, _, err := store.PutImageManifest(ctx, "repo", "t1", ispec.MediaTypeImageManifest, body, nil)
		So(errors.Is(err, zerr.ErrRepoLockUnavailable), ShouldBeTrue)

		// the index was never committed
		tags, err := goodStore.GetImageTags("repo")
		So(err, ShouldBeNil)
		So(tags, ShouldNotContain, "t1")
	})

	Convey("A delete that lost the repo lock mid-write fails before rewriting the index", t, func() {
		rootDir := t.TempDir()
		ctx := context.Background()

		// write a manifest with a working lock first
		goodStore := local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
			zlog.NewMetricsServer(false, log.NewTestLogger()), nil, nil, nil, nil)

		body := pushTestManifest(t, goodStore, "repo")

		_, _, err := goodStore.PutImageManifest(ctx, "repo", "t1", ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		// then delete through a store whose lock reports lost
		store := local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
			zlog.NewMetricsServer(false, log.NewTestLogger()), nil, lostLockCache{}, nil, nil)

		err = store.DeleteImageManifest(ctx, "repo", "t1", false)
		So(errors.Is(err, zerr.ErrRepoLockUnavailable), ShouldBeTrue)

		// the tag survived
		tags, err := goodStore.GetImageTags("repo")
		So(err, ShouldBeNil)
		So(tags, ShouldContain, "t1")
	})
}

func TestRepoLockFailureFailsWrites(t *testing.T) {
	Convey("Writes fail when the repo lock is unavailable", t, func() {
		rootDir := t.TempDir()
		ctx := context.Background()

		store := local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
			zlog.NewMetricsServer(false, log.NewTestLogger()), nil, failLockCache{}, nil, nil)

		Convey("InitRepo fails", func() {
			So(errors.Is(store.InitRepo(ctx, "repo"), zerr.ErrRepoLockUnavailable), ShouldBeTrue)
		})

		Convey("PutImageManifest fails and writes nothing", func() {
			_, _, err := store.PutImageManifest(ctx, "repo", "t1", ispec.MediaTypeImageManifest, []byte("{}"), nil)
			So(errors.Is(err, zerr.ErrRepoLockUnavailable), ShouldBeTrue)

			_, err = store.GetImageTags("repo")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteImageManifest fails", func() {
			// the repo layout exists, so the delete reaches the lock acquisition
			So(os.MkdirAll(path.Join(rootDir, "repo"), 0o755), ShouldBeNil)

			err := store.DeleteImageManifest(ctx, "repo", "t1", false)
			So(errors.Is(err, zerr.ErrRepoLockUnavailable), ShouldBeTrue)
		})
	})

	Convey("A cache driver without RepoLocker gets the no-op locker", t, func() {
		rootDir := t.TempDir()

		store := local.NewImageStore(rootDir, false, false, log.NewTestLogger(),
			zlog.NewMetricsServer(false, log.NewTestLogger()), nil, mocks.CacheMock{}, nil, nil)

		body := pushTestManifest(t, store, "repo")

		_, _, err := store.PutImageManifest(context.Background(), "repo", "t1",
			ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		tags, err := store.GetImageTags("repo")
		So(err, ShouldBeNil)
		So(tags, ShouldContain, "t1")
	})
}
