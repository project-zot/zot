package imagestore

import (
	"fmt"
	"sync"
)

type ImageStoreLock struct {
	// locks per repository paths
	repoLocks sync.Map
}

func NewImageStoreLock() *ImageStoreLock {
	return &ImageStoreLock{
		repoLocks: sync.Map{},
	}
}

func (sl *ImageStoreLock) getKeys() []interface{} {
	locks := sl.repoLocks //nolint:govet // we don't want to block when reading keys
	keys := []interface{}{}

	locks.Range(func(key, value interface{}) bool {
		keys = append(keys, key)

		return true
	})

	return keys
}

func (sl *ImageStoreLock) RLockRepo(repo string) {
	val, _ := sl.repoLocks.LoadOrStore(repo, &sync.RWMutex{})

	// lock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.RLock()
}

func (sl *ImageStoreLock) RUnlockRepo(repo string) {
	val, ok := sl.repoLocks.Load(repo)
	if !ok {
		// somehow the unlock is called for repo that was not locked
		panic(fmt.Sprintf("failed to find lock for repo %s in %v", repo, sl.getKeys()))
	}

	// read-unlock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.RUnlock()
}

func (sl *ImageStoreLock) LockRepo(repo string) {
	val, _ := sl.repoLocks.LoadOrStore(repo, &sync.RWMutex{})

	// write-lock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.Lock()
}

func (sl *ImageStoreLock) UnlockRepo(repo string) {
	val, ok := sl.repoLocks.Load(repo)
	if !ok {
		// somehow the unlock is called for a repo that was not locked
		panic(fmt.Sprintf("failed to find lock for repo %s in %v", repo, sl.getKeys()))
	}

	// write-unlock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.Unlock()
}
