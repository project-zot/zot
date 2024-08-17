package imagestore

import (
	"sync"
)

type ImageStoreLock struct {
	// locks per repository paths
	repoLocks sync.Map
	// lock for the entire storage, needed in case all repos need to be processed
	// including blocking creating new repos
	globalLock *sync.RWMutex
}

func NewImageStoreLock() *ImageStoreLock {
	return &ImageStoreLock{
		repoLocks:  sync.Map{},
		globalLock: &sync.RWMutex{},
	}
}

func (sl *ImageStoreLock) RLock() {
	// block reads and writes to the entire storage, including new repos
	sl.globalLock.RLock()
}

func (sl *ImageStoreLock) RUnlock() {
	// unlock to the storage in general
	sl.globalLock.RUnlock()
}

func (sl *ImageStoreLock) Lock() {
	// block reads and writes to the entire storage, including new repos
	sl.globalLock.Lock()
}

func (sl *ImageStoreLock) Unlock() {
	// unlock to the storage in general
	sl.globalLock.Unlock()
}

func (sl *ImageStoreLock) RLockRepo(repo string) {
	// besides the individual repo increment the read counter for the
	// global lock, this will make sure the storage cannot be
	// write-locked at global level while individual repos are accessed
	sl.globalLock.RLock()

	val, _ := sl.repoLocks.LoadOrStore(repo, &sync.RWMutex{})

	// lock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.RLock()
}

func (sl *ImageStoreLock) RUnlockRepo(repo string) {
	val, ok := sl.repoLocks.Load(repo)
	if !ok {
		// somehow the unlock is called for repo that was never locked
		return
	}

	// read-unlock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.RUnlock()

	// decrement the global read counter after the one for the individual repo is decremented
	sl.globalLock.RUnlock()
}

func (sl *ImageStoreLock) LockRepo(repo string) {
	// besides the individual repo increment the read counter for the
	// global lock, this will make sure the storage cannot be
	// write-locked at global level while individual repos are accessed
	// we are not using the write lock here, as that would make all repos
	// wait for one another
	sl.globalLock.RLock()

	val, _ := sl.repoLocks.LoadOrStore(repo, &sync.RWMutex{})

	// write-lock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.Lock()
}

func (sl *ImageStoreLock) UnlockRepo(repo string) {
	val, ok := sl.repoLocks.Load(repo)
	if !ok {
		// somehow the unlock is called for a repo that was never locked
		return
	}

	// write-unlock individual repo
	repoLock, _ := val.(*sync.RWMutex)
	repoLock.Unlock()

	// decrement the global read counter after the individual repo was unlocked
	sl.globalLock.RUnlock()
}
