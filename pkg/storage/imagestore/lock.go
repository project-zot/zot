package imagestore

import (
	"sync"
)

type ImageStoreLock struct {
	// locks per repository paths
	repoLocks map[string]*sync.RWMutex
	// lock for managing the content of the repo lock map
	internalLock *sync.Mutex
}

func NewImageStoreLock() *ImageStoreLock {
	return &ImageStoreLock{
		repoLocks:    map[string]*sync.RWMutex{},
		internalLock: &sync.Mutex{},
	}
}

func (sl *ImageStoreLock) RLockRepo(repo string) {
	repoLock, _ := sl.loadLock(repo)

	// lock individual repo
	repoLock.RLock()
}

func (sl *ImageStoreLock) RUnlockRepo(repo string) {
	repoLock, ok := sl.loadLock(repo)
	if !ok {
		// somehow the unlock is called for a repo that was not locked
		return
	}

	// read-unlock individual repo
	repoLock.RUnlock()
}

func (sl *ImageStoreLock) LockRepo(repo string) {
	repoLock, _ := sl.loadLock(repo)

	// write-lock individual repo
	repoLock.Lock()
}

func (sl *ImageStoreLock) UnlockRepo(repo string) {
	repoLock, ok := sl.loadLock(repo)
	if !ok {
		// somehow the unlock is called for a repo that was not locked
		return
	}

	// write-unlock individual repo
	repoLock.Unlock()

	// attempt to clean up the map of unused locks
	sl.discardLockIfPossible(repo)
}

func (sl *ImageStoreLock) loadLock(repo string) (*sync.RWMutex, bool) {
	sl.internalLock.Lock()
	defer sl.internalLock.Unlock()

	repoLock, ok := sl.repoLocks[repo]
	if !ok {
		sl.repoLocks[repo] = &sync.RWMutex{}
		repoLock = sl.repoLocks[repo]
	}

	return repoLock, ok
}

func (sl *ImageStoreLock) discardLockIfPossible(repo string) {
	sl.internalLock.Lock()
	defer sl.internalLock.Unlock()

	repoLock, ok := sl.repoLocks[repo]
	if !ok {
		// the lock is not set, no need to do anything else
		return
	}

	// check if the lock is in use
	// this is a non-blocking operation if someone else is already blocking the lock
	// the internalLock prevents the case where someone else attempts
	// to load/block the lock after this function started executing
	ok = repoLock.TryLock()
	if !ok {
		// if someone else is using this lock, it is still needed, keep it as is
		return
	}
	// final unlock
	defer repoLock.Unlock()

	// nobody else is using this lock, remove it from the map
	delete(sl.repoLocks, repo)
}
