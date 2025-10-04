package api

import (
	"context"
	"encoding/gob"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/rbcervilla/redisstore/v9"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	rediscfg "zotregistry.dev/zot/pkg/api/config/redis"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
)

const cookiesMaxAge = 7200 // 2h

type CookieStore struct {
	needsCleanup bool // if store should be periodically cleaned
	rootDir      string
	sessions.Store
}

func (c *CookieStore) RunSessionCleaner(sch *scheduler.Scheduler) {
	if c.needsCleanup {
		sch.SubmitGenerator(
			&SessionCleanup{rootDir: c.rootDir},
			cookiesMaxAge*time.Second,
			scheduler.LowPriority,
		)
	}
}

func NewCookieStore(
	authCfg *config.AuthConfig,
	storeController storage.StoreController,
	log log.Logger,
) (*CookieStore, error) {
	// To store custom types in our cookies
	// we must first register them using gob.Register
	gob.Register(map[string]interface{}{})

	var store sessions.Store

	var sessionsDir string

	var needsCleanup bool

	if authCfg.SessionDriver == nil {
		// If the session driver is not configured, then
		// behave in the usual way for file system cookie store and memory cookie store.
		createdStore, returnedSessionsDir, doesStoreNeedCleanup, err := localSessionStoreInit(
			storeController,
			authCfg.SessionHashKey,
			authCfg.SessionEncryptKey,
		)
		if err != nil {
			return &CookieStore{}, err
		}

		store = createdStore
		sessionsDir = returnedSessionsDir
		needsCleanup = doesStoreNeedCleanup
	} else {
		switch authCfg.SessionDriver["name"] {
		case storageConstants.RedisDriverName:
			{
				prefix, ok := rediscfg.GetString(authCfg.SessionDriver, "keyprefix", false, log)
				if !ok {
					prefix = "zotsession"
				}

				// The redisstore library code uses a colon to separate the prefix
				// and the actual key and is expected to be part of the prefix argument.
				// ref: https://github.com/rbcervilla/redisstore/blob/v9.0.0/redisstore.go#L44
				// This adds a colon to the prefix only if it is not empty.
				if prefix != "" {
					prefix += ":"
				}

				client, err := rediscfg.GetRedisClient(authCfg.SessionDriver, log)
				if err != nil {
					return nil, err
				}

				redisStore, err := redisstore.NewRedisStore(context.Background(), client)
				if err != nil {
					return nil, err
				}

				redisStore.KeyPrefix(prefix)
				redisStore.Options(sessions.Options{
					MaxAge: cookiesMaxAge,
					Path:   "/",
				})

				store = redisStore
			}
		case storageConstants.LocalStorageDriverName:
			{
				// This behaves the same as if there was no sessionDriver config.
				// It is also the same behaviour prior to supporting this config.
				// This allows for a backwards compatible migration path for upgrades.
				createdStore, sessDir, cleanupReq, err := localSessionStoreInit(
					storeController,
					authCfg.SessionHashKey,
					authCfg.SessionEncryptKey,
				)
				if err != nil {
					return &CookieStore{}, err
				}

				store = createdStore
				sessionsDir = sessDir
				needsCleanup = cleanupReq
			}
		default:
			return nil, fmt.Errorf(
				"%w: sessiondriver %s not supported",
				errors.ErrBadConfig,
				authCfg.SessionDriver["name"],
			)
		}
	}

	return &CookieStore{
		Store:        store,
		rootDir:      sessionsDir,
		needsCleanup: needsCleanup,
	}, nil
}

// Handles creation and init of a local session store.
// This can be either in memory or on the local file system.
// Returns a session Store, root directory for the sessions if applicable,
// a boolean indicating whether clean up is required, and an error.
func localSessionStoreInit(
	storeController storage.StoreController,
	hashKey,
	encryptKey []byte,
) (sessions.Store, string, bool, error) {
	var store sessions.Store

	var sessionsDir string

	var needsCleanup bool

	if storeController.DefaultStore.Name() == storageConstants.LocalStorageDriverName {
		sessionsDir = path.Join(storeController.DefaultStore.RootDir(), "_sessions")
		if err := os.MkdirAll(sessionsDir, storageConstants.DefaultDirPerms); err != nil {
			return &CookieStore{}, "", false, err
		}

		localStore := sessions.NewFilesystemStore(sessionsDir, hashKey, encryptKey)

		localStore.MaxAge(cookiesMaxAge)

		store = localStore
		needsCleanup = true
	} else {
		memStore := sessions.NewCookieStore(hashKey, encryptKey)

		memStore.MaxAge(cookiesMaxAge)

		store = memStore
	}

	return store, sessionsDir, needsCleanup, nil
}

func IsExpiredSession(dirEntry fs.DirEntry) bool {
	fileInfo, err := dirEntry.Info()
	if err != nil { // may have been deleted in the meantime
		return false
	}

	if !strings.HasPrefix(fileInfo.Name(), "session_") {
		return false
	}

	if fileInfo.ModTime().Add(cookiesMaxAge * time.Second).After(time.Now()) {
		return false
	}

	return true
}

func getExpiredSessions(dir string) ([]string, error) {
	sessions := make([]string, 0)

	err := filepath.WalkDir(dir, func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if IsExpiredSession(dirEntry) {
			sessions = append(sessions, filePath)
		}

		return nil
	})

	if os.IsNotExist(err) {
		return sessions, nil
	}

	return sessions, err
}

type SessionCleanup struct {
	rootDir string
	done    bool
}

func (gen *SessionCleanup) Name() string {
	return "SessionCleanupGenerator"
}

func (gen *SessionCleanup) Next() (scheduler.Task, error) {
	sessions, err := getExpiredSessions(gen.rootDir)
	if err != nil {
		return nil, err
	}

	if len(sessions) == 0 {
		gen.done = true

		return nil, nil //nolint:nilnil
	}

	return &CleanTask{sessions: sessions}, nil
}

func (gen *SessionCleanup) IsDone() bool {
	return gen.done
}

func (gen *SessionCleanup) IsReady() bool {
	return true
}

func (gen *SessionCleanup) Reset() {
	gen.done = false
}

type CleanTask struct {
	sessions []string
}

func (cleanTask *CleanTask) DoWork(ctx context.Context) error {
	for _, session := range cleanTask.sessions {
		if err := os.Remove(session); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		}
	}

	return nil
}

func (cleanTask *CleanTask) String() string {
	return fmt.Sprintf("{Name: %s, sessions: %s}",
		cleanTask.Name(), cleanTask.sessions)
}

func (cleanTask *CleanTask) Name() string {
	return "SessionCleanupTask"
}
