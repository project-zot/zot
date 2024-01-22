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

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
)

const cookiesMaxAge = 7200 // 2h

type CookieStore struct {
	needsCleanup bool // if store should be periodically cleaned
	rootDir      string
	sessions.Store
}

func (c *CookieStore) RunSessionCleaner(sch *scheduler.Scheduler) {
	if c.needsCleanup {
		sch.SubmitGenerator(&SessionCleanup{rootDir: c.rootDir}, cookiesMaxAge, scheduler.LowPriority)
	}
}

func NewCookieStore(storeController storage.StoreController) (*CookieStore, error) {
	// To store custom types in our cookies
	// we must first register them using gob.Register
	gob.Register(map[string]interface{}{})

	hashKey, err := getHashKey()
	if err != nil {
		return &CookieStore{}, err
	}

	var store sessions.Store

	var sessionsDir string

	var needsCleanup bool

	if storeController.DefaultStore.Name() == storageConstants.LocalStorageDriverName {
		sessionsDir = path.Join(storeController.DefaultStore.RootDir(), "_sessions")
		if err := os.MkdirAll(sessionsDir, storageConstants.DefaultDirPerms); err != nil {
			return &CookieStore{}, err
		}

		localStore := sessions.NewFilesystemStore(sessionsDir, hashKey)

		localStore.MaxAge(cookiesMaxAge)

		store = localStore
		needsCleanup = true
	} else {
		memStore := sessions.NewCookieStore(hashKey)

		memStore.MaxAge(cookiesMaxAge)

		store = memStore
	}

	return &CookieStore{
		Store:        store,
		rootDir:      sessionsDir,
		needsCleanup: needsCleanup,
	}, nil
}

func getHashKey() ([]byte, error) {
	hashKey := securecookie.GenerateRandomKey(64)
	if hashKey == nil {
		return nil, zerr.ErrHashKeyNotCreated
	}

	return hashKey, nil
}

func getExpiredSessions(dir string) ([]string, error) {
	sessions := make([]string, 0)

	err := filepath.WalkDir(dir, func(_ string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fileInfo, err := dirEntry.Info()
		if err != nil { // may have been deleted in the meantime
			return nil //nolint: nilerr
		}

		if !strings.HasPrefix(fileInfo.Name(), "session_") {
			return nil
		}

		if fileInfo.ModTime().Add(cookiesMaxAge * time.Second).Before(time.Now()) {
			sessions = append(sessions, path.Join(dir, fileInfo.Name()))
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

func (gen *SessionCleanup) Next() (scheduler.Task, error) {
	sessions, err := getExpiredSessions(gen.rootDir)
	if err != nil {
		return nil, err
	}

	if len(sessions) == 0 {
		gen.done = true

		return nil, nil
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
