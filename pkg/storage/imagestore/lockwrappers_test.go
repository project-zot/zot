package imagestore_test

import (
	"errors"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

var errWrapped = errors.New("wrapped func failed") //nolint: gochecknoglobals

// The wrappers share the store gate and take repository locks as required. Every wrapper
// must run its function, return its error, and exclude conflicting shared or repository work.
func TestLockWrappersRespectSharedAndRepositoryLocks(t *testing.T) {
	const repo = "repo"

	log := zlog.NewTestLogger()
	store := local.NewImageStore(t.TempDir(), false, false, log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

	type wrapper struct {
		name      string
		exclusive bool
		repoWrite bool
		repoRead  bool
		with      func(wrappedFunc func() error) error
	}

	wrappers := []wrapper{
		{"WithRepoLock", false, true, false, func(f func() error) error { return store.WithRepoLock(repo, f) }},
		{"WithRepoReadLock", false, false, true, func(f func() error) error { return store.WithRepoReadLock(repo, f) }},
		{"WithBlobstoreLock", true, false, false, store.WithBlobstoreLock},
		{"WithBlobstoreReadLock", false, false, false, store.WithBlobstoreReadLock},
		{"WithBlobstoreAndRepoLock", true, false, false, func(f func() error) error {
			return store.WithBlobstoreAndRepoLock(repo, f)
		}},
		{"WithBlobstoreReadAndRepoLock", false, true, false, func(f func() error) error {
			return store.WithBlobstoreReadAndRepoLock(repo, f)
		}},
		{"WithRepoCleanupLock", false, true, false, func(f func() error) error {
			return store.WithRepoCleanupLock(repo, f)
		}},
	}
	conflicts := func(outer, inner wrapper) bool {
		return outer.exclusive || inner.exclusive ||
			(outer.repoWrite && (inner.repoRead || inner.repoWrite)) ||
			(inner.repoWrite && outer.repoRead)
	}

	// acquiredWhileHeld reports whether inner got its lock while outer was holding its own.
	// A pair expected to exclude each other is given a short wait, since the wait is spent in
	// full; a pair expected to share the lock is given a long one, since it ends at once.
	acquiredWhileHeld := func(outer, inner wrapper) bool {
		acquired := false

		wait := 100 * time.Millisecond
		if !conflicts(outer, inner) {
			wait = 10 * time.Second
		}

		done := make(chan struct{})

		_ = outer.with(func() error {
			go func() {
				_ = inner.with(func() error { return nil })

				close(done)
			}()

			select {
			case <-done:
				acquired = true
			case <-time.After(wait):
			}

			return nil
		})

		// An inner wrapper that timed out is still queued for the lock. Wait for it, or a
		// queued writer would hold up the readers of the next pair.
		<-done

		return acquired
	}

	Convey("Every wrapper runs its function and returns its error", t, func() {
		for _, lock := range wrappers {
			ran := false

			err := lock.with(func() error {
				ran = true

				return errWrapped
			})
			So(ran, ShouldBeTrue)
			So(err, ShouldEqual, errWrapped)
		}
	})

	Convey("Wrappers exclude only conflicting shared or repository operations", t, func() {
		for _, outer := range wrappers {
			for _, inner := range wrappers {
				Convey(outer.name+" then "+inner.name, func() {
					So(acquiredWhileHeld(outer, inner), ShouldEqual, !conflicts(outer, inner))
				})
			}
		}
	})
}
