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

// The repo and blobstore lock wrappers all take the store's single lock. These tests pin
// that down from the outside: every wrapper runs its function and returns its error, and
// which wrappers exclude each other is what one read-write lock gives.
func TestLockWrappersShareTheStoreLock(t *testing.T) {
	const repo = "repo"

	log := zlog.NewTestLogger()
	store := local.NewImageStore(t.TempDir(), false, false, log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

	type wrapper struct {
		name  string
		write bool
		with  func(wrappedFunc func() error) error
	}

	wrappers := []wrapper{
		{"WithRepoLock", true, func(f func() error) error { return store.WithRepoLock(repo, f) }},
		{"WithRepoReadLock", false, func(f func() error) error { return store.WithRepoReadLock(repo, f) }},
		{"WithBlobstoreLock", true, store.WithBlobstoreLock},
		{"WithBlobstoreReadLock", false, store.WithBlobstoreReadLock},
		{"WithBlobstoreAndRepoLock", true, func(f func() error) error {
			return store.WithBlobstoreAndRepoLock(repo, f)
		}},
		{"WithBlobstoreReadAndRepoLock", true, func(f func() error) error {
			return store.WithBlobstoreReadAndRepoLock(repo, f)
		}},
		{"WithRepoCleanupLock", true, func(f func() error) error { return store.WithRepoCleanupLock(repo, f) }},
	}

	// acquiredWhileHeld reports whether inner got its lock while outer was holding its own.
	// A pair expected to exclude each other is given a short wait, since the wait is spent in
	// full; a pair expected to share the lock is given a long one, since it ends at once.
	acquiredWhileHeld := func(outer, inner wrapper) bool {
		acquired := false

		wait := 100 * time.Millisecond
		if !outer.write && !inner.write {
			wait = 10 * time.Second
		}

		_ = outer.with(func() error {
			done := make(chan struct{})

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

	Convey("Two wrappers run together only if both take the lock for reading", t, func() {
		for _, outer := range wrappers {
			for _, inner := range wrappers {
				Convey(outer.name+" then "+inner.name, func() {
					So(acquiredWhileHeld(outer, inner), ShouldEqual, !outer.write && !inner.write)
				})
			}
		}
	})
}
