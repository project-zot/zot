package gc

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconfig "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func testStoreWithRepos(t *testing.T, root string, repos ...string) storage.StoreController {
	t.Helper()

	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()
	localStore := local.NewImageStore(root, false, false, log, metrics, nil, nil, nil, nil)
	ctx := context.Background()

	for _, repo := range repos {
		if err := localStore.InitRepo(ctx, repo); err != nil {
			t.Fatalf("InitRepo(%q): %v", repo, err)
		}
	}

	return storage.StoreController{DefaultStore: localStore}
}

func plantStaleSyncSession(t *testing.T, syncDir, name string, age time.Duration) string {
	t.Helper()

	session := filepath.Join(syncDir, name)
	if err := os.MkdirAll(session, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", session, err)
	}

	older := time.Now().Add(-age)
	if err := os.Chtimes(session, older, older); err != nil {
		t.Fatalf("Chtimes(%q): %v", session, err)
	}

	return session
}

func confWithReapDelay(gcDelay time.Duration) *config.Config {
	conf := config.New()
	conf.Storage.GCDelay = gcDelay
	conf.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconfig.Config{
			Registries: []syncconfig.RegistryConfig{{SyncTimeout: gcDelay}},
		},
	}

	return conf
}

func runSchedulerUntil(t *testing.T, sch *scheduler.Scheduler, timeout time.Duration, condition func() bool) {
	t.Helper()

	go sch.RunScheduler()
	defer sch.Shutdown()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("condition not met within %v", timeout)
}

func TestRunSyncSessionReaperPeriodicallyNilExtensions(t *testing.T) {
	Convey("RunSyncSessionReaperPeriodically with nil extensions config does not panic", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		root := t.TempDir()

		conf := config.New()
		conf.Extensions = nil

		localStore := local.NewImageStore(root, false, false, log, metrics, nil, nil, nil, nil)
		sc := storage.StoreController{DefaultStore: localStore}

		sch := scheduler.NewScheduler(conf, metrics, log)
		So(func() { RunSyncSessionReaperPeriodically(conf, sc, sch, log) }, ShouldNotPanic)
		So(sc.SyncStagingRoots(), ShouldResemble, []string{root})
	})

	Convey("RunSyncSessionReaperPeriodically uses default GC interval when unset", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		conf := confWithReapDelay(time.Hour)
		conf.Storage.GCInterval = 0

		sc := storage.StoreController{DefaultStore: local.NewImageStore(root, false, false, log, metrics, nil, nil, nil, nil)}
		sch := scheduler.NewScheduler(conf, metrics, log)

		staleDir := plantStaleSyncSession(t,
			filepath.Join(root, repo, syncConstants.SyncBlobUploadDir), "stale-session", 2*time.Hour)

		So(func() { RunSyncSessionReaperPeriodically(conf, sc, sch, log) }, ShouldNotPanic)

		runSchedulerUntil(t, sch, 2*time.Second, func() bool {
			_, err := os.Stat(staleDir)

			return os.IsNotExist(err)
		})
	})
}

func TestSyncSessionReapDelay(t *testing.T) {
	Convey("syncSessionReapDelay from config", t, func() {
		Convey("uses largest GCDelay across substores", func() {
			conf := config.New()
			conf.Storage.GCDelay = time.Hour
			conf.Storage.SubPaths = map[string]config.StorageConfig{
				"/a": {GCDelay: 3 * time.Hour},
				"/b": {GCDelay: 2 * time.Hour},
			}

			So(syncSessionReapDelay(conf), ShouldEqual, 3*time.Hour)
		})

		Convey("defaults to max(default GCDelay, default SyncTimeout)", func() {
			So(syncSessionReapDelay(config.New()), ShouldEqual, syncConstants.DefaultSyncTimeout)
		})

		Convey("sync timeout wins when larger", func() {
			conf := config.New()
			conf.Storage.GCDelay = 2 * time.Hour
			conf.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconfig.Config{
					Registries: []syncconfig.RegistryConfig{{SyncTimeout: 3 * time.Hour}},
				},
			}

			So(syncSessionReapDelay(conf), ShouldEqual, 3*time.Hour)
		})

		Convey("gc delay wins when larger", func() {
			conf := config.New()
			conf.Storage.GCDelay = 4 * time.Hour
			conf.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconfig.Config{
					Registries: []syncconfig.RegistryConfig{{SyncTimeout: 3 * time.Hour}},
				},
			}

			So(syncSessionReapDelay(conf), ShouldEqual, 4*time.Hour)
		})
	})
}

func TestHasInProgressSessions(t *testing.T) {
	Convey("HasInProgressSessions", t, func() {
		log := zlog.NewTestLogger()
		repo := "org/app"

		Convey("session blocks removal", func() {
			root := t.TempDir()
			session := path.Join(root, repo, syncConstants.SyncBlobUploadDir, "session-uuid")
			So(os.MkdirAll(session, 0o755), ShouldBeNil)

			So(HasInProgressSessions(root, repo, log), ShouldBeTrue)
		})

		Convey("empty root does not block", func() {
			So(HasInProgressSessions("", repo, log), ShouldBeFalse)
		})

		Convey("empty .sync does not block", func() {
			root := t.TempDir()
			syncDir := path.Join(root, repo, syncConstants.SyncBlobUploadDir)
			So(os.MkdirAll(syncDir, 0o755), ShouldBeNil)

			So(HasInProgressSessions(root, repo, log), ShouldBeFalse)
		})

		Convey("ReadDir error fails closed", func() {
			root := t.TempDir()
			syncDir := path.Join(root, repo, syncConstants.SyncBlobUploadDir)
			So(os.MkdirAll(syncDir, 0o755), ShouldBeNil)
			So(os.Chmod(syncDir, 0o000), ShouldBeNil)

			Reset(func() {
				_ = os.Chmod(syncDir, 0o755)
			})

			So(HasInProgressSessions(root, repo, log), ShouldBeTrue)
		})
	})
}

func TestCollectStaleSyncSessionsAtRoot(t *testing.T) {
	Convey("collectStaleSyncSessionsAtRoot discovers stale sessions via pruned walk", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		testStoreWithRepos(t, root, "a", "org/nested")

		staleA := plantStaleSyncSession(t,
			filepath.Join(root, "a", syncConstants.SyncBlobUploadDir), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 2*time.Hour)
		staleNested := plantStaleSyncSession(t,
			filepath.Join(root, "org/nested", syncConstants.SyncBlobUploadDir), "bbbbbbbb-cccc-dddd-eeee-ffffffffffffff", 2*time.Hour)

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldContain, staleA)
		So(sessions, ShouldContain, staleNested)
	})

	Convey("collectStaleSyncSessionsAtRoot does not descend into blob subtrees", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "heavy"
		testStoreWithRepos(t, root, repo)

		blobLeaf := filepath.Join(root, repo, "blobs", "sha256", "aa", "bb", "cc", "dd")
		So(os.MkdirAll(blobLeaf, 0o755), ShouldBeNil)
		trap := filepath.Join(blobLeaf, "trap")
		So(os.WriteFile(trap, []byte("x"), 0o000), ShouldBeNil)

		stale := plantStaleSyncSession(t,
			filepath.Join(root, repo, syncConstants.SyncBlobUploadDir), "stale-session", 2*time.Hour)

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldContain, stale)
	})

	Convey("collectStaleSyncSessionsAtRoot reaps unregistered sessions under SyncDownloadDir", t, func() {
		log := zlog.NewTestLogger()
		downloadDir := t.TempDir()

		orphanRepo := "new-repo"
		stale := plantStaleSyncSession(t,
			filepath.Join(downloadDir, orphanRepo, syncConstants.SyncBlobUploadDir), "orphan-session", 2*time.Hour)

		sessions, err := collectStaleSyncSessionsAtRoot(downloadDir, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldContain, stale)
	})

	Convey("collectStaleSyncSessionsAtRoot reaps unregistered sessions on a local store root", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		testStoreWithRepos(t, root)

		orphanRepo := "new-repo"
		stale := plantStaleSyncSession(t,
			filepath.Join(root, orphanRepo, syncConstants.SyncBlobUploadDir), "orphan-session", 2*time.Hour)

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldContain, stale)
	})

	Convey("collectStaleSyncSessionsAtRoot finds sessions for nested repo names", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "org/team/app"
		testStoreWithRepos(t, root, repo)

		stale := plantStaleSyncSession(t,
			filepath.Join(root, repo, syncConstants.SyncBlobUploadDir), "nested-session", 2*time.Hour)

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldContain, stale)
	})
}

func TestSyncSessionReaper(t *testing.T) {
	Convey("syncSessionReaperGenerator reaps stale sessions and keeps recent ones", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "org/app"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		staleDir := plantStaleSyncSession(t, syncDir, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 2*time.Hour)

		freshDir := filepath.Join(syncDir, "bbbbbbbb-cccc-dddd-eeee-ffffffffffffff")
		So(os.MkdirAll(freshDir, 0o755), ShouldBeNil)

		gen := newSyncSessionReaperGenerator([]string{root}, time.Hour, log)
		So(gen.Name(), ShouldEqual, "SyncSessionReaperGenerator")
		So(gen.IsReady(), ShouldBeTrue)

		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)
		So(gen.IsDone(), ShouldBeFalse)
		So(task.Name(), ShouldEqual, "SyncSessionReaperTask")
		So(task.String(), ShouldContainSubstring, staleDir)

		err = task.DoWork(context.Background())
		So(err, ShouldBeNil)

		_, err = os.Stat(staleDir)
		So(os.IsNotExist(err), ShouldBeTrue)
		_, err = os.Stat(freshDir)
		So(err, ShouldBeNil)

		task, err = gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)

		gen.Reset()
		So(gen.IsDone(), ShouldBeFalse)
	})

	Convey("second Next without DoWork does not re-emit the same session", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "org/app"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		staleDir := plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)

		gen := newSyncSessionReaperGenerator([]string{root}, time.Hour, log)

		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)
		So(gen.IsDone(), ShouldBeFalse)

		taskAgain, err := gen.Next()
		So(err, ShouldBeNil)
		So(taskAgain, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)

		So(task.DoWork(context.Background()), ShouldBeNil)
		_, err = os.Stat(staleDir)
		So(os.IsNotExist(err), ShouldBeTrue)
	})

	Convey("syncSessionReaperGenerator returns nil when no sessions exist", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		testStoreWithRepos(t, root)

		gen := newSyncSessionReaperGenerator([]string{root}, time.Hour, log)
		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)
	})

	Convey("DoWork skips a session that is no longer past the delay", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		session := plantStaleSyncSession(t,
			filepath.Join(root, repo, syncConstants.SyncBlobUploadDir), "recent", 2*time.Hour)

		gen := newSyncSessionReaperGenerator([]string{root}, time.Hour, log)
		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)

		now := time.Now()
		So(os.Chtimes(session, now, now), ShouldBeNil)

		So(task.DoWork(context.Background()), ShouldBeNil)
		_, err = os.Stat(session)
		So(err, ShouldBeNil)
	})
}

func TestRunSyncSessionReaperPeriodically_reapsStaleSessionViaScheduler(t *testing.T) {
	Convey("RunSyncSessionReaperPeriodically reaps stale sessions via the scheduler", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		conf := confWithReapDelay(time.Hour)
		conf.Storage.GCInterval = 20 * time.Millisecond

		sc := storage.StoreController{DefaultStore: local.NewImageStore(root, false, false, log, metrics, nil, nil, nil, nil)}
		sch := scheduler.NewScheduler(conf, metrics, log)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		staleDir := plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)
		freshDir := filepath.Join(syncDir, "fresh-session")
		So(os.MkdirAll(freshDir, 0o755), ShouldBeNil)

		RunSyncSessionReaperPeriodically(conf, sc, sch, log)

		runSchedulerUntil(t, sch, 2*time.Second, func() bool {
			_, err := os.Stat(staleDir)

			return os.IsNotExist(err)
		})

		_, err := os.Stat(freshDir)
		So(err, ShouldBeNil)
	})
}

func TestRunSyncSessionReaperPeriodically_skipsWhenNoStagingRoots(t *testing.T) {
	Convey("RunSyncSessionReaperPeriodically skips registration when there are no staging roots", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		remoteRoot := t.TempDir()
		repo := "repo"

		remote := mocks.MockedImageStore{
			NameFn:    func() string { return "s3" },
			RootDirFn: func() string { return remoteRoot },
		}
		sc := storage.StoreController{DefaultStore: remote}
		So(sc.SyncStagingRoots(), ShouldBeEmpty)

		session := plantStaleSyncSession(t,
			filepath.Join(remoteRoot, repo, syncConstants.SyncBlobUploadDir), "orphan", 2*time.Hour)

		conf := confWithReapDelay(time.Hour)
		conf.Storage.GCInterval = 20 * time.Millisecond
		sch := scheduler.NewScheduler(conf, metrics, log)

		RunSyncSessionReaperPeriodically(conf, sc, sch, log)

		sch.RunScheduler()
		time.Sleep(200 * time.Millisecond)
		sch.Shutdown()

		_, err := os.Stat(session)
		So(err, ShouldBeNil)
	})
}

func TestRunSyncSessionReaperPeriodically_reapsUnderSyncDownloadDir(t *testing.T) {
	Convey("RunSyncSessionReaperPeriodically uses SyncDownloadDir as the staging root", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		storeRoot := t.TempDir()
		downloadDir := t.TempDir()
		repo := "repo"

		sc := storage.StoreController{
			DefaultStore:    local.NewImageStore(storeRoot, false, false, log, metrics, nil, nil, nil, nil),
			SyncDownloadDir: downloadDir,
		}
		So(sc.SyncStagingRoots(), ShouldResemble, []string{downloadDir})

		staleDir := plantStaleSyncSession(t,
			filepath.Join(downloadDir, repo, syncConstants.SyncBlobUploadDir), "stale-session", 2*time.Hour)

		conf := confWithReapDelay(time.Hour)
		conf.Storage.GCInterval = 20 * time.Millisecond
		sch := scheduler.NewScheduler(conf, metrics, log)

		RunSyncSessionReaperPeriodically(conf, sc, sch, log)

		runSchedulerUntil(t, sch, 2*time.Second, func() bool {
			_, err := os.Stat(staleDir)

			return os.IsNotExist(err)
		})
	})
}

func TestSyncSessionReaperGenerator_multipleRoots(t *testing.T) {
	Convey("syncSessionReaperGenerator emits one task per stale session across staging roots", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		defaultRoot := t.TempDir()
		subRoot := t.TempDir()

		defaultStore := local.NewImageStore(defaultRoot, false, false, log, metrics, nil, nil, nil, nil)
		subStore := local.NewImageStore(subRoot, false, false, log, metrics, nil, nil, nil, nil)
		sc := storage.StoreController{
			DefaultStore: defaultStore,
			SubStore: map[string]storageTypes.ImageStore{
				"/a": subStore,
			},
		}

		testStoreWithRepos(t, defaultRoot, "centos")
		testStoreWithRepos(t, subRoot, "a/myrepo")

		staleDefault := plantStaleSyncSession(t,
			filepath.Join(defaultRoot, "centos", syncConstants.SyncBlobUploadDir), "default-stale", 2*time.Hour)
		staleSub := plantStaleSyncSession(t,
			filepath.Join(subRoot, "a/myrepo", syncConstants.SyncBlobUploadDir), "sub-stale", 2*time.Hour)

		gen := newSyncSessionReaperGenerator(sc.SyncStagingRoots(), time.Hour, log)

		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)
		So(task.(*syncSessionReaperTask).session, ShouldBeIn, staleDefault, staleSub)
		So(task.DoWork(context.Background()), ShouldBeNil)

		task, err = gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)
		So(task.(*syncSessionReaperTask).session, ShouldBeIn, staleDefault, staleSub)
		So(task.DoWork(context.Background()), ShouldBeNil)

		task, err = gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)

		_, err = os.Stat(staleDefault)
		So(os.IsNotExist(err), ShouldBeTrue)
		_, err = os.Stat(staleSub)
		So(os.IsNotExist(err), ShouldBeTrue)
	})
}

func TestCollectStaleSyncSessionsAtRoot_skipsNonDirectoryEntries(t *testing.T) {
	Convey("expiredSyncSessionDirs ignores non-directory entries under .sync", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		So(os.MkdirAll(syncDir, 0o755), ShouldBeNil)
		So(os.WriteFile(filepath.Join(syncDir, "not-a-session"), []byte("x"), 0o644), ShouldBeNil)
		stale := plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldResemble, []string{stale})
	})
}

func TestCollectStaleSyncSessionsAtRoot_missingRoot(t *testing.T) {
	Convey("collectStaleSyncSessionsAtRoot on a missing root returns empty", t, func() {
		log := zlog.NewTestLogger()
		root := filepath.Join(t.TempDir(), "does-not-exist")

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldBeEmpty)
	})
}

func TestCollectStaleSyncSessionsAtRoot_readDirError(t *testing.T) {
	Convey("collectStaleSyncSessionsAtRoot propagates ReadDir errors", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)
		So(os.Chmod(syncDir, 0o000), ShouldBeNil)

		Reset(func() {
			_ = os.Chmod(syncDir, 0o755)
		})

		_, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldNotBeNil)
	})
}

func TestCollectStaleSyncSessionsAtRoot_skipsFreshSessions(t *testing.T) {
	Convey("collectStaleSyncSessionsAtRoot does not return sessions within the reap delay", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		fresh := filepath.Join(syncDir, "fresh-session")
		So(os.MkdirAll(fresh, 0o755), ShouldBeNil)

		sessions, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldBeNil)
		So(sessions, ShouldBeEmpty)
	})
}

func TestCollectStaleSyncSessionsAtRoot_walkError(t *testing.T) {
	Convey("collectStaleSyncSessionsAtRoot propagates walk errors", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)

		repoDir := filepath.Join(root, repo)
		So(os.Chmod(repoDir, 0o000), ShouldBeNil)

		Reset(func() {
			_ = os.Chmod(repoDir, 0o755)
		})

		_, err := collectStaleSyncSessionsAtRoot(root, time.Hour, log)
		So(err, ShouldNotBeNil)
	})
}

func TestSyncSessionReaperGenerator_skipsFailedRoot(t *testing.T) {
	Convey("syncSessionReaperGenerator skips unreadable roots and continues the sweep", t, func() {
		log := zlog.NewTestLogger()
		badRoot := t.TempDir()
		goodRoot := t.TempDir()
		repo := "repo"

		testStoreWithRepos(t, badRoot, repo)
		testStoreWithRepos(t, goodRoot, repo)

		plantStaleSyncSession(t,
			filepath.Join(badRoot, repo, syncConstants.SyncBlobUploadDir), "bad-stale", 2*time.Hour)
		staleGood := plantStaleSyncSession(t,
			filepath.Join(goodRoot, repo, syncConstants.SyncBlobUploadDir), "good-stale", 2*time.Hour)

		badRepoDir := filepath.Join(badRoot, repo)
		So(os.Chmod(badRepoDir, 0o000), ShouldBeNil)

		Reset(func() {
			_ = os.Chmod(badRepoDir, 0o755)
		})

		gen := newSyncSessionReaperGenerator([]string{badRoot, goodRoot}, time.Hour, log)

		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)
		So(task.(*syncSessionReaperTask).session, ShouldEqual, staleGood)
		So(gen.IsDone(), ShouldBeFalse)

		So(task.DoWork(context.Background()), ShouldBeNil)
		_, err = os.Stat(staleGood)
		So(os.IsNotExist(err), ShouldBeTrue)

		task, err = gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)
	})

	Convey("syncSessionReaperGenerator finishes when every root fails discovery", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		plantStaleSyncSession(t,
			filepath.Join(root, repo, syncConstants.SyncBlobUploadDir), "stale-session", 2*time.Hour)

		repoDir := filepath.Join(root, repo)
		So(os.Chmod(repoDir, 0o000), ShouldBeNil)

		Reset(func() {
			_ = os.Chmod(repoDir, 0o755)
		})

		gen := newSyncSessionReaperGenerator([]string{root}, time.Hour, log)
		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)
	})
}

func TestSyncSessionReaperTask_contextCancelled(t *testing.T) {
	Convey("syncSessionReaperTask returns ctx.Err when cancelled", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		first := plantStaleSyncSession(t,
			filepath.Join(root, repo, syncConstants.SyncBlobUploadDir), "first", 2*time.Hour)

		task := &syncSessionReaperTask{
			session:   first,
			reapDelay: time.Hour,
			log:       log,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		So(task.DoWork(ctx), ShouldEqual, context.Canceled)
	})
}

func TestSyncSessionReaperTask_sessionAlreadyRemoved(t *testing.T) {
	Convey("syncSessionReaperTask ignores sessions removed before DoWork", t, func() {
		log := zlog.NewTestLogger()
		task := &syncSessionReaperTask{
			session:   filepath.Join(t.TempDir(), "missing", "session"),
			reapDelay: time.Hour,
			log:       log,
		}

		So(task.DoWork(context.Background()), ShouldBeNil)
	})
}

func TestSyncSessionReaperTask_removeAllError(t *testing.T) {
	Convey("syncSessionReaperTask returns RemoveAll errors", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		session := plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)
		So(os.Chmod(syncDir, 0o555), ShouldBeNil)

		Reset(func() {
			_ = os.Chmod(syncDir, 0o755)
		})

		task := &syncSessionReaperTask{
			session:   session,
			reapDelay: time.Hour,
			log:       log,
		}

		So(task.DoWork(context.Background()), ShouldNotBeNil)
	})
}

func TestSyncSessionReaperTask_statError(t *testing.T) {
	Convey("syncSessionReaperTask returns stat errors before delete", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "repo"
		testStoreWithRepos(t, root, repo)

		syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)
		session := plantStaleSyncSession(t, syncDir, "stale-session", 2*time.Hour)
		So(os.Chmod(syncDir, 0o644), ShouldBeNil)

		Reset(func() {
			_ = os.Chmod(syncDir, 0o755)
		})

		task := &syncSessionReaperTask{
			session:   session,
			reapDelay: time.Hour,
			log:       log,
		}

		So(task.DoWork(context.Background()), ShouldNotBeNil)
	})
}

func TestHasInProgressSessions_matchesStoreControllerRoot(t *testing.T) {
	Convey("HasInProgressSessions uses SyncStagingRootForRepo", t, func() {
		log := zlog.NewTestLogger()
		root := t.TempDir()
		repo := "org/app"
		sc := testStoreWithRepos(t, root, repo)

		session := path.Join(root, repo, syncConstants.SyncBlobUploadDir, "session-uuid")
		So(os.MkdirAll(session, 0o755), ShouldBeNil)

		So(HasInProgressSessions(sc.SyncStagingRootForRepo(repo), repo, log), ShouldBeTrue)
	})
}
