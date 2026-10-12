package imagestore_test

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type globalBlobReclaimer interface {
	ReclaimGlobalBlobs(ctx context.Context, delay time.Duration) error
}

// reclaimFixture is a remote-style store (logical repo refs) holding one payload that "repo"
// owns. A second zot instance is played by writing its marker, claim and pin objects straight
// into the shared driver, which is all another instance would ever show this one.
type reclaimFixture struct {
	store      storageTypes.ImageStore
	reclaimer  globalBlobReclaimer
	driver     *mocks.StorageDriverMock
	cache      *mapBackedCache
	repo       string
	digest     godigest.Digest
	globalPath string
	markerPath string
	pinDir     string
}

func newReclaimFixture(t *testing.T) *reclaimFixture {
	t.Helper()

	rootDir := "/oci-repo-test/deferred-reclaim"
	content := []byte("shared-payload")
	digest := godigest.FromBytes(content)

	blobPath := func(repoName string) string {
		return path.Join(rootDir, repoName, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
	}

	fixture := &reclaimFixture{
		repo:       "repo",
		digest:     digest,
		globalPath: blobPath(constants.GlobalBlobsRepo),
		markerPath: path.Join(rootDir, constants.GlobalBlobsRepo, "_reclaim",
			digest.Algorithm().String(), digest.Encoded()),
		pinDir: path.Join(rootDir, constants.GlobalBlobsRepo, "_reclaim_pins",
			digest.Algorithm().String(), digest.Encoded()),
	}

	fixture.driver = makeStatefulMigrationStoreMock(rootDir, fixture.repo, fixture.globalPath, content)
	fixture.cache = newMapBackedCache()
	So(fixture.cache.PutBlob(digest, fixture.globalPath), ShouldBeNil)
	So(fixture.cache.PutBlob(digest, blobPath(fixture.repo)), ShouldBeNil)

	testLog := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, testLog)
	t.Cleanup(metrics.Stop)

	fixture.store = imagestore.NewImageStore(rootDir, "", true, false, testLog, metrics, nil,
		gcs.New(fixture.driver), fixture.cache, nil, nil)
	So(fixture.store, ShouldNotBeNil)

	reclaimer, ok := fixture.store.(globalBlobReclaimer)
	So(ok, ShouldBeTrue)

	fixture.reclaimer = reclaimer

	return fixture
}

func (fixture *reclaimFixture) exists(filePath string) bool {
	_, err := fixture.driver.StatFn(context.Background(), filePath)

	return err == nil
}

func (fixture *reclaimFixture) pinCount() int {
	pins, err := fixture.driver.ListFn(context.Background(), fixture.pinDir)
	if err != nil {
		return 0
	}

	return len(pins)
}

// TestGlobalBlobLinkPinsItselfWhenSlow covers the linker that found no marker and so started
// unpinned: if it is still running when a sweep could come for the digest, it must be visible.
func TestGlobalBlobLinkPinsItselfWhenSlow(t *testing.T) {
	ctx := context.Background()

	Convey("A link that runs long pins itself even though it saw no marker", t, func() {
		fixture := newReclaimFixture(t)
		imagestore.SetReclaimLatePinAfter(fixture.store, 50*time.Millisecond)

		started, finish := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)

		go func() {
			done <- imagestore.GuardGlobalBlobLink(fixture.store, fixture.digest, func() error {
				close(started)
				<-finish

				return nil
			})
		}()

		<-started

		So(test.WaitForStableCondition(100, 1, 20*time.Millisecond, func() bool {
			return fixture.pinCount() == 1
		}), ShouldBeTrue)

		// the owner lets go while the link is still running: the sweep must see the pin
		So(fixture.store.DeleteBlob(fixture.repo, fixture.digest), ShouldBeNil)
		So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.globalPath), ShouldBeTrue)

		close(finish)
		So(<-done, ShouldBeNil)
		So(fixture.pinCount(), ShouldEqual, 0)
	})

	Convey("A link that finishes quickly never writes a pin", t, func() {
		fixture := newReclaimFixture(t)

		So(imagestore.GuardGlobalBlobLink(fixture.store, fixture.digest, func() error { return nil }), ShouldBeNil)
		So(fixture.exists(fixture.pinDir), ShouldBeFalse)
	})
}

// TestDeferredGlobalBlobReclaim drives the sweep and the marker-present linker path.
func TestDeferredGlobalBlobReclaim(t *testing.T) {
	ctx := context.Background()

	Convey("Global payloads are reclaimed by a deferred, coordinated sweep", t, func() {
		fixture := newReclaimFixture(t)
		store, storeMock, cache, reclaimer := fixture.store, fixture.driver, fixture.cache, fixture.reclaimer
		repo, digest := fixture.repo, fixture.digest
		globalBlobPath, markerPath, pinDir := fixture.globalPath, fixture.markerPath, fixture.pinDir
		exists := fixture.exists

		readMarker := func() map[string]any {
			buf, err := storeMock.GetContentFn(ctx, markerPath)
			So(err, ShouldBeNil)

			marker := map[string]any{}
			So(json.Unmarshal(buf, &marker), ShouldBeNil)

			return marker
		}

		writeMarker := func(marker map[string]any) {
			buf, err := json.Marshal(marker)
			So(err, ShouldBeNil)
			So(storeMock.PutContentFn(ctx, markerPath, buf), ShouldBeNil)
		}

		// the last owner lets go: the payload must outlive the delete
		So(store.DeleteBlob(repo, digest), ShouldBeNil)
		So(exists(globalBlobPath), ShouldBeTrue)
		So(exists(markerPath), ShouldBeTrue)

		Convey("not before the reclaim delay has passed", func() {
			So(reclaimer.ReclaimGlobalBlobs(ctx, time.Hour), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			So(exists(markerPath), ShouldBeTrue)
		})

		Convey("once the delay has passed and nothing references the payload", func() {
			So(reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeFalse)
			So(exists(markerPath), ShouldBeFalse)

			_, err := cache.GetBlob(digest)
			So(err, ShouldNotBeNil)
		})

		Convey("not when the sweep cannot finish inside its claim's lease", func() {
			// a lease this short has run out before the delete is reached
			imagestore.SetReclaimClaimLease(store, time.Nanosecond)

			So(reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			// released, so the next sweep can try again
			So(readMarker()["claimId"], ShouldBeNil)
		})

		Convey("not when a repository picked the digest up again", func() {
			found, _, err := store.CheckBlob(ctx, "other", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)

			So(reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			// the marker is spent: the next last-ref delete writes a fresh one
			So(exists(markerPath), ShouldBeFalse)
		})

		Convey("not while another instance pins the digest", func() {
			pinPath := path.Join(pinDir, "other-instance")
			So(storeMock.PutContentFn(ctx, pinPath, []byte(time.Now().UTC().Format(time.RFC3339Nano))), ShouldBeNil)

			So(reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			// the claim is released so the linker behind the pin is not kept waiting
			So(readMarker()["claimId"], ShouldBeNil)
		})

		Convey("a pin left behind by a crashed linker does not block it forever", func() {
			pinPath := path.Join(pinDir, "crashed-instance")
			stale := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
			So(storeMock.PutContentFn(ctx, pinPath, []byte(stale)), ShouldBeNil)

			So(reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeFalse)
			So(exists(pinPath), ShouldBeFalse)
		})

		Convey("not while another instance's sweep holds the claim", func() {
			writeMarker(map[string]any{
				"markedAt": time.Now().Add(-time.Hour), "claimId": "other-sweep", "claimedAt": time.Now(),
			})

			So(reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(exists(globalBlobPath), ShouldBeTrue)
			So(readMarker()["claimId"], ShouldEqual, "other-sweep")
		})

		Convey("a linker pins the digest and waits for a claim to clear", func() {
			writeMarker(map[string]any{
				"markedAt": time.Now().Add(-time.Hour), "claimId": "other-sweep", "claimedAt": time.Now(),
			})

			done := make(chan error, 1)

			go func() {
				_, _, err := store.CheckBlob(ctx, "other", digest)
				done <- err
			}()

			// held back by the claim, with its pin already visible to the other sweep
			select {
			case <-done:
				So("linker returned while the claim was held", ShouldBeEmpty)
			case <-time.After(300 * time.Millisecond):
			}

			pins, err := storeMock.ListFn(ctx, pinDir)
			So(err, ShouldBeNil)
			So(len(pins), ShouldEqual, 1)

			// the other sweep saw the pin and backed off
			writeMarker(map[string]any{"markedAt": time.Now().Add(-time.Hour)})

			select {
			case err := <-done:
				So(err, ShouldBeNil)
			case <-time.After(5 * time.Second):
				So("linker still waiting after the claim cleared", ShouldBeEmpty)
			}

			pins, err = storeMock.ListFn(ctx, pinDir)
			So(err == nil && len(pins) > 0, ShouldBeFalse)
		})

		Convey("a linker does not wait on a dead claim past its lease", func() {
			imagestore.SetReclaimClaimLease(store, 200*time.Millisecond)
			writeMarker(map[string]any{
				"markedAt": time.Now().Add(-time.Hour), "claimId": "dead-sweep", "claimedAt": time.Now(),
			})

			found, _, err := store.CheckBlob(ctx, "other", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
		})
	})
}

func TestStatRepoKeepsTheReason(t *testing.T) {
	Convey("StatRepo tells a missing repository from a storage failure", t, func() {
		fixture := newReclaimFixture(t)

		So(fixture.store.StatRepo(fixture.repo), ShouldBeNil)
		So(fixture.store.StatRepo("absent"), ShouldWrap, zerr.ErrRepoNotFound)

		// an outage must not read as "no such repository"
		statFn := fixture.driver.StatFn
		fixture.driver.StatFn = func(ctx context.Context, filePath string) (driver.FileInfo, error) {
			if path.Base(filePath) == "flaky" {
				return nil, driver.Error{DriverName: "gcs", Detail: errBackendDown}
			}

			return statFn(ctx, filePath)
		}

		err := fixture.store.StatRepo("flaky")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)
		So(fixture.store.RepoExists("flaky"), ShouldBeFalse)
	})

	Convey("WithRepoCleanupLock skips the blobstore lock where reclaim is deferred", t, func() {
		fixture := newReclaimFixture(t)

		// holding the blobstore lock here would deadlock if the cleanup lock wanted it too
		err := fixture.store.WithBlobstoreLock(func() error {
			return fixture.store.WithRepoCleanupLock(fixture.repo, func() error { return nil })
		})
		So(err, ShouldBeNil)
	})
}

var errBackendDown = errors.New("backend down")

// lockingCache is a shared-style cache: it offers the cross-instance reclaim lock.
type lockingCache struct {
	*mapBackedCache

	heldElsewhere bool
	locked        int
	unlocked      int
}

func (cache *lockingCache) TryLockBlobReclaim(_ godigest.Digest, _ time.Duration) (func(), bool, error) {
	if cache.heldElsewhere {
		return nil, false, nil
	}

	cache.locked++

	return func() { cache.unlocked++ }, true, nil
}

func TestGlobalBlobReclaimTakesTheCacheLock(t *testing.T) {
	ctx := context.Background()

	newStore := func(fixture *reclaimFixture, cache *lockingCache) globalBlobReclaimer {
		testLog := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, testLog)
		t.Cleanup(metrics.Stop)

		// a second store on the same driver and refs, as another view of the shared state
		store := imagestore.NewImageStore("/oci-repo-test/deferred-reclaim", "", true, false, testLog, metrics, nil,
			gcs.New(fixture.driver), cache, nil, nil)
		So(store, ShouldNotBeNil)

		reclaimer, ok := store.(globalBlobReclaimer)
		So(ok, ShouldBeTrue)

		return reclaimer
	}

	Convey("A sweep leaves a digest another instance's sweep has locked", t, func() {
		fixture := newReclaimFixture(t)
		So(fixture.store.DeleteBlob(fixture.repo, fixture.digest), ShouldBeNil)

		cache := &lockingCache{mapBackedCache: fixture.cache, heldElsewhere: true}

		So(newStore(fixture, cache).ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.globalPath), ShouldBeTrue)
		So(fixture.exists(fixture.markerPath), ShouldBeTrue)
	})

	Convey("A sweep holds the lock for the reclaim and gives it back", t, func() {
		fixture := newReclaimFixture(t)
		So(fixture.store.DeleteBlob(fixture.repo, fixture.digest), ShouldBeNil)

		cache := &lockingCache{mapBackedCache: fixture.cache}

		So(newStore(fixture, cache).ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.globalPath), ShouldBeFalse)
		So(cache.locked, ShouldEqual, 1)
		So(cache.unlocked, ShouldEqual, 1)
	})
}

// setManifestRef makes the fixture's repo reference its payload from a manifest, or, with
// referenced false, drops that manifest again as a manifest delete would.
func (fixture *reclaimFixture) setManifestRef(referenced bool) {
	ctx := context.Background()
	rootDir := "/oci-repo-test/deferred-reclaim"
	index := ispec.Index{SchemaVersion: 2}

	if referenced {
		manifest := ispec.Manifest{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageManifest,
			Config:        ispec.DescriptorEmptyJSON,
			Layers:        []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayer, Digest: fixture.digest, Size: 1}},
		}

		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBuf)
		So(fixture.driver.PutContentFn(ctx, path.Join(rootDir, fixture.repo, ispec.ImageBlobsDir,
			manifestDigest.Algorithm().String(), manifestDigest.Encoded()), manifestBuf), ShouldBeNil)

		index.Manifests = []ispec.Descriptor{{
			MediaType: ispec.MediaTypeImageManifest, Digest: manifestDigest, Size: int64(len(manifestBuf)),
		}}
	}

	indexBuf, err := json.Marshal(index)
	So(err, ShouldBeNil)
	So(fixture.driver.PutContentFn(ctx, path.Join(rootDir, fixture.repo, ispec.ImageIndexFile), indexBuf), ShouldBeNil)
}

func TestGlobalBlobReclaimAndManifestReferences(t *testing.T) {
	ctx := context.Background()

	Convey("A sweep right after a manifest delete does not go by the cached manifest graph", t, func() {
		fixture := newReclaimFixture(t)
		fixture.setManifestRef(true)

		// the graph cache now holds the repo's manifest reference to the payload
		referenced, err := imagestore.IsDigestReferencedOutsideRepo(fixture.store, "other", fixture.digest)
		So(err, ShouldBeNil)
		So(referenced, ShouldBeTrue)

		// manifest deleted, then GC drops the blob: all well inside the cache's lifetime
		fixture.setManifestRef(false)
		So(fixture.store.DeleteBlob(fixture.repo, fixture.digest), ShouldBeNil)
		So(fixture.exists(fixture.markerPath), ShouldBeTrue)

		So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.globalPath), ShouldBeFalse)
	})

	Convey("A payload only a manifest references keeps both itself and its marker", t, func() {
		fixture := newReclaimFixture(t)
		fixture.setManifestRef(true)

		// ownership record lost, as after a cache loss: only the global record is left
		So(fixture.cache.DeleteBlob(fixture.digest, path.Join("/oci-repo-test/deferred-reclaim", fixture.repo,
			ispec.ImageBlobsDir, fixture.digest.Algorithm().String(), fixture.digest.Encoded())), ShouldBeNil)
		So(fixture.driver.PutContentFn(ctx, fixture.markerPath, []byte(`{"markedAt":"2020-01-01T00:00:00Z"}`)),
			ShouldBeNil)

		So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.globalPath), ShouldBeTrue)
		// dropping the marker would strand the payload once the manifest goes
		So(fixture.exists(fixture.markerPath), ShouldBeTrue)

		fixture.setManifestRef(false)
		So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.globalPath), ShouldBeFalse)
	})
}

func TestGlobalBlobLinkWithFailingPin(t *testing.T) {
	// failPins makes every pin write fail, as a store rejecting writes under the pin dir would
	failPins := func(fixture *reclaimFixture) {
		putContent, writer := fixture.driver.PutContentFn, fixture.driver.WriterFn

		fixture.driver.PutContentFn = func(ctx context.Context, filePath string, content []byte) error {
			if strings.HasPrefix(filePath, fixture.pinDir) {
				return errBackendDown
			}

			return putContent(ctx, filePath, content)
		}
		fixture.driver.WriterFn = func(ctx context.Context, filePath string, isAppend bool) (driver.FileWriter, error) {
			if strings.HasPrefix(filePath, fixture.pinDir) {
				return nil, errBackendDown
			}

			return writer(ctx, filePath, isAppend)
		}
	}

	// slowLink outlasts the unpinned allowance and several pin retries
	slowLink := func(during func()) func() error {
		return func() error {
			time.Sleep(150 * time.Millisecond)
			during()

			return nil
		}
	}

	Convey("A link whose late pin could not be written is checked afterwards", t, func() {
		Convey("and stands if the payload is still there", func() {
			fixture := newReclaimFixture(t)
			imagestore.SetReclaimLatePinAfter(fixture.store, 20*time.Millisecond)
			failPins(fixture)

			err := imagestore.GuardGlobalBlobLink(fixture.store, fixture.digest, slowLink(func() {}))
			So(err, ShouldBeNil)
		})

		Convey("and fails as retryable if a sweep took the payload meanwhile", func() {
			fixture := newReclaimFixture(t)
			imagestore.SetReclaimLatePinAfter(fixture.store, 20*time.Millisecond)
			failPins(fixture)

			err := imagestore.GuardGlobalBlobLink(fixture.store, fixture.digest, slowLink(func() {
				// another instance's sweep, which saw neither a pin nor a ref
				So(fixture.driver.DeleteFn(context.Background(), fixture.globalPath), ShouldBeNil)
			}))
			So(err, ShouldWrap, zerr.ErrGlobalBlobReclaimed)
			So(err, ShouldWrap, zerr.ErrStorageTransient)
		})

		Convey("but a link's own failure is reported as it is", func() {
			fixture := newReclaimFixture(t)
			imagestore.SetReclaimLatePinAfter(fixture.store, 20*time.Millisecond)
			failPins(fixture)

			err := imagestore.GuardGlobalBlobLink(fixture.store, fixture.digest, func() error {
				time.Sleep(150 * time.Millisecond)

				return errBackendDown
			})
			So(err, ShouldEqual, errBackendDown)
		})
	})

	Convey("A pin write that fails at first is retried until it lands", t, func() {
		fixture := newReclaimFixture(t)
		imagestore.SetReclaimLatePinAfter(fixture.store, 20*time.Millisecond)

		var failures atomic.Int32

		putContent, writer := fixture.driver.PutContentFn, fixture.driver.WriterFn
		fixture.driver.PutContentFn = func(ctx context.Context, filePath string, content []byte) error {
			if strings.HasPrefix(filePath, fixture.pinDir) && failures.Add(1) <= 2 {
				return errBackendDown
			}

			return putContent(ctx, filePath, content)
		}
		fixture.driver.WriterFn = func(ctx context.Context, filePath string, isAppend bool) (driver.FileWriter, error) {
			if strings.HasPrefix(filePath, fixture.pinDir) && failures.Add(1) <= 2 {
				return nil, errBackendDown
			}

			return writer(ctx, filePath, isAppend)
		}

		pinned := false

		err := imagestore.GuardGlobalBlobLink(fixture.store, fixture.digest, slowLink(func() {
			pinned = fixture.pinCount() == 1
		}))
		So(err, ShouldBeNil)
		So(pinned, ShouldBeTrue)
		So(fixture.pinCount(), ShouldEqual, 0)
	})
}

func TestGlobalBlobReclaimWithLostRefIndex(t *testing.T) {
	ctx := context.Background()

	Convey("With no index record of a marked payload, ownership is unknown", t, func() {
		fixture := newReclaimFixture(t)
		So(fixture.store.DeleteBlob(fixture.repo, fixture.digest), ShouldBeNil)

		// The index is lost. Some repository may still own the payload through a blob it
		// uploaded but has not put in a manifest yet, which nothing but the index records.
		So(fixture.cache.DeleteBlob(fixture.digest, fixture.globalPath), ShouldBeNil)
		_, err := fixture.cache.GetBlob(fixture.digest)
		So(err, ShouldNotBeNil)

		Convey("so the sweep keeps the payload and its marker", func() {
			So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(fixture.exists(fixture.globalPath), ShouldBeTrue)
			So(fixture.exists(fixture.markerPath), ShouldBeTrue)

			// and reclaims it once the index knows the payload again
			So(fixture.cache.PutBlob(fixture.digest, fixture.globalPath), ShouldBeNil)
			So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(fixture.exists(fixture.globalPath), ShouldBeFalse)
			So(fixture.exists(fixture.markerPath), ShouldBeFalse)
		})

		Convey("unless the payload is gone as well, which only leaves a marker to tidy up", func() {
			So(fixture.driver.DeleteFn(ctx, fixture.globalPath), ShouldBeNil)

			So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
			So(fixture.exists(fixture.markerPath), ShouldBeFalse)
		})
	})

	Convey("A sweep interrupted after deleting the payload is finished by the next one", t, func() {
		fixture := newReclaimFixture(t)
		So(fixture.store.DeleteBlob(fixture.repo, fixture.digest), ShouldBeNil)

		// what a crash between the payload delete and the record delete leaves behind
		So(fixture.driver.DeleteFn(ctx, fixture.globalPath), ShouldBeNil)

		So(fixture.reclaimer.ReclaimGlobalBlobs(ctx, 0), ShouldBeNil)
		So(fixture.exists(fixture.markerPath), ShouldBeFalse)

		_, err := fixture.cache.GetBlob(fixture.digest)
		So(err, ShouldNotBeNil)
	})
}

// TestGlobalBlobFallbackKeepsOutages covers the read that GC's stale-manifest prune relies on
// when the blob-ref index is partial: a repo whose ownership record is gone resolves its blob
// from the global blobstore, and a backend failure on the way must not come back as "missing".
func TestGlobalBlobFallbackKeepsOutages(t *testing.T) {
	Convey("A repo blob whose ownership record is lost", t, func() {
		fixture := newReclaimFixture(t)

		So(fixture.cache.DeleteBlob(fixture.digest, fixture.store.BlobPath(fixture.repo, fixture.digest)), ShouldBeNil)

		Convey("is reported as unknown, not missing, while the global blobstore cannot be read", func() {
			statFn := fixture.driver.StatFn
			fixture.driver.StatFn = func(ctx context.Context, filePath string) (driver.FileInfo, error) {
				if filePath == fixture.globalPath {
					return nil, driver.Error{DriverName: "gcs", Detail: errBackendDown}
				}

				return statFn(ctx, filePath)
			}

			exists, _, _, err := fixture.store.StatBlob(fixture.repo, fixture.digest)
			So(exists, ShouldBeFalse)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
		})

		Convey("is reported as missing once the payload really is gone", func() {
			So(fixture.driver.DeleteFn(context.Background(), fixture.globalPath), ShouldBeNil)

			_, _, _, err := fixture.store.StatBlob(fixture.repo, fixture.digest)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
		})
	})
}
