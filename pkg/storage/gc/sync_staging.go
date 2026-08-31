package gc

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/pkg/api/config"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

// stagingRootWalkSkipDirs are not descended while scanning a local staging root for .sync sessions.
var stagingRootWalkSkipDirs = map[string]struct{}{ //nolint:gochecknoglobals
	ispec.ImageBlobsDir:             {},
	storageConstants.BlobUploadDir:  {},
	syncConstants.SyncBlobUploadDir: {},
	ispec.ImageLayoutFile:           {},
	ispec.ImageIndexFile:            {},
}

// syncSessionReapDelay returns how old a .sync/<uuid> session must be before the reaper
// may delete it: max(largest configured gcDelay, largest configured syncTimeout).
func syncSessionReapDelay(conf *config.Config) time.Duration {
	gcDelay := conf.CopyStorageConfig().LargestGCDelay()
	syncTimeout := conf.LargestSyncTimeout()

	if syncTimeout > gcDelay {
		return syncTimeout
	}

	return gcDelay
}

// RunSyncSessionReaperPeriodically registers a low-priority periodic reaper for orphaned local
// .sync/<uuid> sessions. Runs regardless of whether the sync extension is enabled.
func RunSyncSessionReaperPeriodically(conf *config.Config, storeController storage.StoreController,
	sch *scheduler.Scheduler, log zlog.Logger,
) {
	roots := storeController.SyncStagingRoots()
	if len(roots) == 0 {
		log.Debug().Str("module", "gc").Msg("sync staging cleanup skipped: no local staging roots")

		return
	}

	storageConfig := conf.CopyStorageConfig()

	delay := syncSessionReapDelay(conf)

	interval := storageConfig.GCInterval
	if interval <= 0 {
		interval = storageConstants.DefaultGCInterval
	}

	log.Info().Str("module", "gc").Dur("delay", delay).
		Dur("interval", interval).Int("roots", len(roots)).
		Msg("enabling sync staging session cleanup")

	sch.SubmitGenerator(newSyncSessionReaperGenerator(roots, delay, log), interval, scheduler.LowPriority)
}

// HasInProgressSessions reports whether root has an active <repo>/.sync/<uuid> session directory.
// Missing .sync is treated as idle; any other ReadDir error fails closed (true).
// An empty root is treated as idle.
func HasInProgressSessions(root, repo string, log zlog.Logger) bool {
	if root == "" {
		return false
	}

	syncDir := filepath.Join(root, repo, syncConstants.SyncBlobUploadDir)

	entries, err := os.ReadDir(syncDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}

		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("dir", syncDir).
			Msg("failed to list sync staging sessions; skipping repo removal")

		return true
	}

	for _, entry := range entries {
		if entry.IsDir() {
			log.Info().Str("module", "gc").Str("repository", repo).Str("session", entry.Name()).
				Msg("sync staging session present; skipping repo removal")

			return true
		}
	}

	return false
}

// collectStaleSyncSessionsAtRoot returns session directories past reapDelay under root.
// Discovery is a pruned walk for <repo>/.sync/<uuid>/; blob subtrees are not descended.
func collectStaleSyncSessionsAtRoot(root string, reapDelay time.Duration, log zlog.Logger) ([]string, error) {
	now := time.Now()
	stale := make([]string, 0)

	err := filepath.WalkDir(root, func(path string, dirEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}

			return walkErr
		}

		if !dirEntry.IsDir() {
			return nil
		}

		name := dirEntry.Name()
		if name == syncConstants.SyncBlobUploadDir {
			sessions, err := expiredSyncSessionDirs(path, reapDelay, now, log)
			if err != nil {
				return err
			}

			stale = append(stale, sessions...)

			return filepath.SkipDir
		}

		if _, skip := stagingRootWalkSkipDirs[name]; skip {
			return filepath.SkipDir
		}

		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return stale, nil
		}

		return nil, err
	}

	return stale, nil
}

// expiredSyncSessionDirs lists <syncDir>/<uuid>/ directories whose mtime is past reapDelay.
func expiredSyncSessionDirs(syncDir string, reapDelay time.Duration, now time.Time, log zlog.Logger) ([]string, error) {
	stale := make([]string, 0)

	entries, err := os.ReadDir(syncDir)
	if err != nil {
		if os.IsNotExist(err) {
			return stale, nil
		}

		log.Error().Err(err).Str("module", "gc").Str("dir", syncDir).
			Msg("failed to list sync staging sessions")

		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			log.Error().Err(err).Str("module", "gc").Str("session", entry.Name()).Str("dir", syncDir).
				Msg("failed to stat sync staging session")

			continue
		}

		if info.ModTime().Add(reapDelay).After(now) {
			continue
		}

		stale = append(stale, filepath.Join(syncDir, entry.Name()))
	}

	return stale, nil
}

type syncSessionReaperGenerator struct {
	roots         []string
	reapDelay     time.Duration
	log           zlog.Logger
	done          bool
	staleSessions []string
	nextIndex     int
}

func newSyncSessionReaperGenerator(roots []string, reapDelay time.Duration,
	log zlog.Logger,
) *syncSessionReaperGenerator {
	return &syncSessionReaperGenerator{
		roots:     roots,
		reapDelay: reapDelay,
		log:       log,
	}
}

func (gen *syncSessionReaperGenerator) Name() string {
	return "SyncSessionReaperGenerator"
}

func (gen *syncSessionReaperGenerator) Next() (scheduler.Task, error) {
	if gen.staleSessions == nil {
		stale := make([]string, 0)

		for _, root := range gen.roots {
			sessions, err := collectStaleSyncSessionsAtRoot(root, gen.reapDelay, gen.log)
			if err != nil {
				// Skip the failed root so the sweep can finish and wait for the next
				// interval. Returning the error would leave staleSessions nil and the
				// generator Ready, causing a tight re-walk/retry loop.
				gen.log.Error().Err(err).Str("module", "gc").Str("root", root).
					Msg("failed to collect stale sync sessions; skipping root")

				continue
			}

			stale = append(stale, sessions...)
		}

		gen.staleSessions = stale
	}

	if gen.nextIndex >= len(gen.staleSessions) {
		gen.done = true

		return nil, nil //nolint:nilnil
	}

	session := gen.staleSessions[gen.nextIndex]
	gen.nextIndex++

	return &syncSessionReaperTask{session: session, reapDelay: gen.reapDelay, log: gen.log}, nil
}

func (gen *syncSessionReaperGenerator) IsDone() bool {
	return gen.done
}

func (gen *syncSessionReaperGenerator) IsReady() bool {
	return true
}

func (gen *syncSessionReaperGenerator) Reset() {
	gen.done = false
	gen.staleSessions = nil
	gen.nextIndex = 0
}

type syncSessionReaperTask struct {
	session   string
	reapDelay time.Duration
	log       zlog.Logger
}

func (task *syncSessionReaperTask) DoWork(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	info, err := os.Stat(task.session)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		task.log.Error().Err(err).Str("module", "gc").Str("session", task.session).
			Msg("failed to stat sync staging session before delete")

		return err
	}

	if info.ModTime().Add(task.reapDelay).After(time.Now()) {
		task.log.Debug().Str("module", "gc").Str("session", task.session).
			Msg("sync staging session no longer past delay; skipping delete")

		return nil
	}

	task.log.Info().Str("module", "gc").Str("session", task.session).
		Msg("removing stale sync staging session")

	if err := os.RemoveAll(task.session); err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		task.log.Error().Err(err).Str("module", "gc").Str("session", task.session).
			Msg("failed to remove stale sync staging session")

		return err
	}

	return nil
}

func (task *syncSessionReaperTask) String() string {
	return fmt.Sprintf("{Name: %s, session: %s}", task.Name(), task.session)
}

func (task *syncSessionReaperTask) Name() string {
	return "SyncSessionReaperTask"
}
