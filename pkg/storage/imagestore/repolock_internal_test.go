package imagestore

import (
	"sync"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
)

func TestRepoLockMapDropsIdleEntries(t *testing.T) {
	Convey("A repo's lock entry lives only while someone holds or waits for it", t, func() {
		locks := &repoLockMap{}

		first := locks.acquire("repo")
		second := locks.acquire("repo")
		So(second, ShouldEqual, first)

		locks.release("repo", first)
		So(locks.locks, ShouldContainKey, "repo")

		locks.release("repo", second)
		So(locks.locks, ShouldBeEmpty)
	})

	Convey("Locking names that never become repositories leaves nothing behind", t, func() {
		store := &ImageStore{metrics: monitoring.NewNopMetricServer()}

		var group sync.WaitGroup

		for _, repo := range []string{"a", "b", "a", "c", "b"} {
			group.Go(func() {
				_ = store.WithRepoLock(repo, func() error { return nil })
				_ = store.WithRepoReadLock(repo, func() error { return nil })
			})
		}

		group.Wait()
		So(store.repoLocks.locks, ShouldBeEmpty)
	})
}
