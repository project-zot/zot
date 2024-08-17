package imagestore

import (
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
		return
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
		return
	}

	// write-unlock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.Unlock()
}
