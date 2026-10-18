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

// lockMode is what a wrapper takes in one lock domain.
type lockMode int

const (
	noLock lockMode = iota
	readLock
	writeLock
)

// conflicts reports whether two holders of one lock domain exclude each other.
func conflicts(a, b lockMode) bool {
	return a != noLock && b != noLock && (a == writeLock || b == writeLock)
}

// The lock wrappers take the global blobstore's lock and a lock per repo. These tests pin that
// down from the outside: every wrapper runs its function and returns its error, and two wrappers
// exclude each other exactly when they collide in one domain, the blobstore's or, for the same
// repo, the repo's.
func TestLockWrappers(t *testing.T) {
	log := zlog.NewTestLogger()
	store := local.NewImageStore(t.TempDir(), false, false, log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

	type wrapper struct {
		name      string
		blobstore lockMode
		repo      lockMode
		with      func(repo string, wrappedFunc func() error) error
	}

	wrappers := []wrapper{
		{"WithRepoLock", noLock, writeLock, store.WithRepoLock},
		{"WithRepoReadLock", noLock, readLock, store.WithRepoReadLock},
		{"WithBlobstoreLock", writeLock, noLock, func(_ string, f func() error) error {
			return store.WithBlobstoreLock(f)
		}},
		{"WithBlobstoreReadLock", readLock, noLock, func(_ string, f func() error) error {
			return store.WithBlobstoreReadLock(f)
		}},
		{"WithBlobstoreAndRepoLock", writeLock, writeLock, store.WithBlobstoreAndRepoLock},
		{"WithBlobstoreReadAndRepoLock", readLock, writeLock, store.WithBlobstoreReadAndRepoLock},
		{"WithRepoCleanupLock", writeLock, writeLock, store.WithRepoCleanupLock},
	}

	// acquiredWhileHeld reports whether inner, on innerRepo, got its locks while outer was holding
	// its own on repo "a". A pair expected to exclude each other is given a short wait, since the
	// wait is spent in full; a pair expected not to is given a long one, since it ends at once.
	acquiredWhileHeld := func(outer, inner wrapper, innerRepo string, excluded bool) bool {
		acquired := false

		wait := 10 * time.Second
		if excluded {
			wait = 100 * time.Millisecond
		}

		done := make(chan struct{})

		_ = outer.with("a", func() error {
			go func() {
				_ = inner.with(innerRepo, func() error { return nil })

				close(done)
			}()

			select {
			case <-done:
				acquired = true
			case <-time.After(wait):
			}

			return nil
		})

		// An inner wrapper that timed out is still queued for its locks. Wait for it, or a
		// queued writer would hold up the readers of the next pair.
		<-done

		return acquired
	}

	Convey("Every wrapper runs its function and returns its error", t, func() {
		for _, lock := range wrappers {
			ran := false

			err := lock.with("a", func() error {
				ran = true

				return errWrapped
			})
			So(ran, ShouldBeTrue)
			So(err, ShouldEqual, errWrapped)
		}
	})

	for _, sameRepo := range []bool{true, false} {
		innerRepo, title := "a", "Two wrappers on one repo exclude each other only if they collide in a domain"
		if !sameRepo {
			innerRepo, title = "b", "Two wrappers on different repos exclude each other only over the blobstore"
		}

		Convey(title, t, func() {
			for _, outer := range wrappers {
				for _, inner := range wrappers {
					excluded := conflicts(outer.blobstore, inner.blobstore) ||
						(sameRepo && conflicts(outer.repo, inner.repo))

					Convey(outer.name+" then "+inner.name, func() {
						So(acquiredWhileHeld(outer, inner, innerRepo, excluded), ShouldEqual, !excluded)
					})
				}
			}
		})
	}
}
