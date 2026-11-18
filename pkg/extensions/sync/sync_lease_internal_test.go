//go:build sync

package sync //nolint:testpackage // white-box test of the sync lease coordinator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/ref"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errLeaseTestUpstream = errors.New("upstream unreachable")

const leaseTestRepo = "lease-repo"

// newLeaseTestCoordinator builds a coordinator for one replica sharing transport's table and
// storeCtrl's storage with the other replicas of a test, with short timings.
func newLeaseTestCoordinator(t *testing.T, transport *fakeDynamoTransport, storeCtrl stypes.StoreController,
	ttl time.Duration,
) *syncLeaseCoordinator {
	t.Helper()

	service := &BaseService{storeController: storeCtrl.(storage.StoreController)} //nolint:forcetypeassert

	coordinator, err := newSyncLeaseCoordinator(
		newFakeDynamoSyncLeaseStore(transport, "https://registry-1.docker.io"),
		service.localManifestDigest, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	coordinator.ttl = ttl
	coordinator.minPoll = 20 * time.Millisecond
	coordinator.maxPoll = 100 * time.Millisecond

	return coordinator
}

func TestSyncLeaseCoordinator(t *testing.T) {
	ctx := context.Background()
	key := trackerKey(leaseTestRepo, predictTestTag)

	Convey("Concurrent pulls on two replicas fetch from upstream once", t, func() {
		_, storeCtrl := newTestStore(t)
		transport := newFakeDynamoTransport()
		replicaA := newLeaseTestCoordinator(t, transport, storeCtrl, time.Minute)
		replicaB := newLeaseTestCoordinator(t, transport, storeCtrl, time.Minute)

		var upstreamFetches atomic.Int32

		syncFromUpstream := func(context.Context) error {
			upstreamFetches.Add(1)
			time.Sleep(200 * time.Millisecond)
			writeOCISingleManifest(t, storeCtrl, leaseTestRepo)

			return nil
		}

		var waitGroup sync.WaitGroup

		errs := make([]error, 2)

		for idx, replica := range []*syncLeaseCoordinator{replicaA, replicaB} {
			waitGroup.Add(1)

			go func() {
				defer waitGroup.Done()

				errs[idx] = replica.run(ctx, leaseTestRepo, predictTestTag, syncFromUpstream)
			}()

			time.Sleep(20 * time.Millisecond)
		}

		waitGroup.Wait()

		So(errs[0], ShouldBeNil)
		So(errs[1], ShouldBeNil)
		So(upstreamFetches.Load(), ShouldEqual, 1)
		So(transport.item(replicaA.store.(*dynamoSyncLeaseStore).keyPrefix+key), ShouldBeNil)
	})

	Convey("A waiter takes over once the holder's lease lapses", t, func() {
		_, storeCtrl := newTestStore(t)
		transport := newFakeDynamoTransport()
		dead := newFakeDynamoSyncLeaseStore(transport, "https://registry-1.docker.io")
		waiter := newLeaseTestCoordinator(t, transport, storeCtrl, time.Second)

		held, err := dead.Acquire(ctx, key, "dead-replica", time.Second)
		So(err, ShouldBeNil)
		So(held, ShouldBeTrue)

		var synced atomic.Bool

		start := time.Now()
		err = waiter.run(ctx, leaseTestRepo, predictTestTag, func(context.Context) error {
			synced.Store(true)

			return nil
		})
		So(err, ShouldBeNil)
		So(synced.Load(), ShouldBeTrue)
		So(time.Since(start), ShouldBeGreaterThan, 500*time.Millisecond)
		So(transport.item(dead.keyPrefix+key), ShouldBeNil)
	})

	Convey("A waiter whose context is cancelled stops waiting without syncing", t, func() {
		_, storeCtrl := newTestStore(t)
		transport := newFakeDynamoTransport()
		holder := newFakeDynamoSyncLeaseStore(transport, "https://registry-1.docker.io")
		waiter := newLeaseTestCoordinator(t, transport, storeCtrl, time.Minute)

		_, err := holder.Acquire(ctx, key, "busy-replica", time.Minute)
		So(err, ShouldBeNil)

		waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		var synced atomic.Bool

		err = waiter.run(waitCtx, leaseTestRepo, predictTestTag, func(context.Context) error {
			synced.Store(true)

			return nil
		})
		So(errors.Is(err, context.DeadlineExceeded), ShouldBeTrue)
		So(synced.Load(), ShouldBeFalse)
	})

	Convey("A lease store outage falls back to an uncoordinated sync", t, func() {
		_, storeCtrl := newTestStore(t)
		transport := newFakeDynamoTransport()
		replica := newLeaseTestCoordinator(t, transport, storeCtrl, time.Minute)
		transport.setFail("PutItem", true)

		var synced atomic.Bool

		err := replica.run(ctx, leaseTestRepo, predictTestTag, func(context.Context) error {
			synced.Store(true)

			return nil
		})
		So(err, ShouldBeNil)
		So(synced.Load(), ShouldBeTrue)

		Convey("and the sync's own error is returned", func() {
			err := replica.run(ctx, leaseTestRepo, predictTestTag, func(context.Context) error {
				return errLeaseTestUpstream
			})
			So(errors.Is(err, errLeaseTestUpstream), ShouldBeTrue)
		})
	})

	Convey("Losing the lease cancels the holder's sync", t, func() {
		_, storeCtrl := newTestStore(t)
		transport := newFakeDynamoTransport()
		holder := newLeaseTestCoordinator(t, transport, storeCtrl, 300*time.Millisecond)
		thief := newFakeDynamoSyncLeaseStore(transport, "https://registry-1.docker.io")
		thief.now = func() time.Time { return time.Now().Add(time.Hour) }

		err := holder.run(ctx, leaseTestRepo, predictTestTag, func(syncCtx context.Context) error {
			held, err := thief.Acquire(ctx, key, "thief", time.Minute)
			So(err, ShouldBeNil)
			So(held, ShouldBeTrue)

			select {
			case <-syncCtx.Done():
				return syncCtx.Err()
			case <-time.After(5 * time.Second):
				return errLeaseTestUpstream
			}
		})
		So(errors.Is(err, errSyncLeaseLost), ShouldBeTrue)
		So(errors.Is(err, context.Canceled), ShouldBeTrue)
		So(transport.item(thief.keyPrefix + key)["Owner"], ShouldResemble, map[string]any{"S": "thief"})
	})

	Convey("A sync error releases the lease and is returned", t, func() {
		_, storeCtrl := newTestStore(t)
		transport := newFakeDynamoTransport()
		replica := newLeaseTestCoordinator(t, transport, storeCtrl, time.Minute)

		err := replica.run(ctx, leaseTestRepo, predictTestTag, func(context.Context) error {
			return errLeaseTestUpstream
		})
		So(errors.Is(err, errLeaseTestUpstream), ShouldBeTrue)
		So(transport.item(replica.store.(*dynamoSyncLeaseStore).keyPrefix+key), ShouldBeNil)
	})
}

func TestEnsureImageUsesSyncLease(t *testing.T) {
	newService := func(transport *fakeDynamoTransport) *BaseService {
		service := &BaseService{
			log: log.NewTestLogger(),
			destination: &mocks.SyncDestinationMock{
				GetImageReferenceFn: func(string, string) (ref.Ref, error) {
					return ref.Ref{}, errLeaseTestUpstream
				},
			},
		}

		if transport != nil {
			coordinator := newLeaseTestCoordinator(t, transport, service.storeController, time.Minute)
			service.syncLease = coordinator
		}

		return service
	}

	Convey("A coordinated ensure acquires and releases the lease around the sync", t, func() {
		transport := newFakeDynamoTransport()
		service := newService(transport)

		err := service.ensureImage(context.Background(), leaseTestRepo, leaseTestRepo, predictTestTag, nil,
			syncImageOptions{Coordinate: true})
		So(errors.Is(err, errLeaseTestUpstream), ShouldBeTrue)
		So(transport.callCount("PutItem"), ShouldEqual, 1)
		So(transport.callCount("DeleteItem"), ShouldEqual, 1)
	})

	Convey("An uncoordinated ensure never touches the lease store", t, func() {
		transport := newFakeDynamoTransport()
		service := newService(transport)

		err := service.ensureImage(context.Background(), leaseTestRepo, leaseTestRepo, predictTestTag, nil,
			syncImageOptions{})
		So(errors.Is(err, errLeaseTestUpstream), ShouldBeTrue)
		So(transport.callCount("PutItem"), ShouldEqual, 0)
	})

	Convey("Without a lease store the ensure runs as before", t, func() {
		service := newService(nil)

		err := service.ensureImage(context.Background(), leaseTestRepo, leaseTestRepo, predictTestTag, nil,
			syncImageOptions{Coordinate: true})
		So(errors.Is(err, errLeaseTestUpstream), ShouldBeTrue)
	})

	Convey("localManifestDigest reports absent and present manifests", t, func() {
		_, storeCtrl := newTestStore(t)
		service := &BaseService{storeController: storeCtrl.(storage.StoreController)} //nolint:forcetypeassert

		So(service.localManifestDigest(leaseTestRepo, predictTestTag), ShouldEqual, godigest.Digest(""))
		So((&BaseService{}).localManifestDigest(leaseTestRepo, predictTestTag), ShouldEqual, godigest.Digest(""))

		writeOCISingleManifest(t, storeCtrl, leaseTestRepo)
		So(service.localManifestDigest(leaseTestRepo, predictTestTag), ShouldNotBeEmpty)
	})
}
