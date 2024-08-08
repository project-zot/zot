package imagestore

import (
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"

	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type ImageStoreLock struct {
	// locks per repository paths
	repoLocks   sync.Map
	digestLocks sync.Map
	imgStore    storageTypes.ImageStore
}

func NewImageStoreLock(imgStore storageTypes.ImageStore) *ImageStoreLock {
	return &ImageStoreLock{
		repoLocks:   sync.Map{},
		digestLocks: sync.Map{},
		imgStore:    imgStore,
	}
}

func (sl *ImageStoreLock) WithRepoLock(repo string, wrappedFunc func() error) error {
	val, _ := sl.repoLocks.LoadOrStore(repo, &sync.RWMutex{})
	repoLock, _ := val.(*sync.RWMutex)

	lockStart := time.Now()

	// write-lock individual repo
	repoLock.Lock()

	defer func() {
		repoLock.Unlock()
		latency := time.Since(lockStart)

		sl.imgStore.ObserveLockLatency(latency, storageConstants.RWLOCK) // histogram
	}()

	return wrappedFunc()
}

func (sl *ImageStoreLock) WithRepoReadLock(repo string, wrappedFunc func() error) error {
	val, _ := sl.repoLocks.LoadOrStore(repo, &sync.RWMutex{})
	repoLock, _ := val.(*sync.RWMutex)

	lockStart := time.Now()

	// read-lock individual repo
	repoLock.RLock()

	defer func() {
		repoLock.RUnlock()
		latency := time.Since(lockStart)

		sl.imgStore.ObserveLockLatency(latency, storageConstants.RLOCK) // histogram
	}()

	return wrappedFunc()
}

func (sl *ImageStoreLock) WithDigestLock(digest godigest.Digest, wrappedFunc func() error) error {
	val, _ := sl.repoLocks.LoadOrStore(digest.String(), &sync.Mutex{})
	digestLock, _ := val.(*sync.Mutex)
	digestLock.Lock()

	defer digestLock.Unlock()

	return wrappedFunc()
}
