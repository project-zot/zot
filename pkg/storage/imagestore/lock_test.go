package imagestore_test

import (
	_ "crypto/sha256"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	"zotregistry.dev/zot/pkg/storage/local"
)

func TestStorageLocks(t *testing.T) {
	dir := t.TempDir()

	log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)

	imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

	Convey("Locks", t, func() {
		// in parallel, a mix of read and write locks - mainly for coverage
		var wg sync.WaitGroup
		for i := 0; i < 1000; i++ {
			repo := "repo" + strconv.Itoa(i%10)

			wg.Add(2)

			go func() {
				var lockLatency time.Time

				defer wg.Done()

				t.Logf("Repo %s will be write-locked in loop %d", repo, i)
				imgStore.LockRepo(repo, &lockLatency)
				func() {
					t.Logf("Execute while repo %s is write-locked in loop %d", repo, i)
				}()
				imgStore.UnlockRepo(repo, &lockLatency)
				t.Logf("Repo %s is write-unlocked in loop %d", repo, i)
			}()
			go func() {
				var lockLatency time.Time

				defer wg.Done()
				t.Logf("Repo %s will be read-locked in loop %d", repo, i)
				imgStore.RLockRepo(repo, &lockLatency)
				func() {
					t.Logf("Execute while repo %s is read-locked in loop %d", repo, i)
				}()
				imgStore.RUnlockRepo(repo, &lockLatency)
				t.Logf("Repo %s is read-unlocked in loop %d", repo, i)
			}()
		}

		wg.Wait()
	})
}
