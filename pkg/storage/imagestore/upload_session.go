package imagestore

import (
	"strings"
	"sync"
	"sync/atomic"

	zerr "zotregistry.dev/zot/v2/errors"
)

const (
	maxUploadSessionIDLength = 255
)

type uploadSessionState uint32

const (
	uploadSessionOpen uploadSessionState = iota
	uploadSessionSealing
	uploadSessionSealed
)

// uploadSession serializes operations on one partial upload while allowing a
// finalizer to reject new writers before waiting for an already active writer.
type uploadSession struct {
	state       atomic.Uint32
	operationMu sync.Mutex
}

func newUploadSession() *uploadSession {
	session := &uploadSession{}
	session.state.Store(uint32(uploadSessionOpen))

	return session
}

// withOpen runs callback as one upload operation. A writer that started before a
// finalizer seals the session may finish; writers that arrive after sealing do
// not consume their request bodies and receive the normal upload-not-found
// response.
func (session *uploadSession) withOpen(callback func() error) error {
	if uploadSessionState(session.state.Load()) != uploadSessionOpen {
		return zerr.ErrUploadNotFound
	}

	session.operationMu.Lock()
	defer session.operationMu.Unlock()

	if uploadSessionState(session.state.Load()) != uploadSessionOpen {
		return zerr.ErrUploadNotFound
	}

	return callback()
}

// finalize seals the session before waiting for an already active writer and
// while callback performs commit, digest verification, and move. Failed finalization
// reopens the session so existing retry behavior is preserved.
func (session *uploadSession) finalize(callback func() error) error {
	if !session.state.CompareAndSwap(uint32(uploadSessionOpen), uint32(uploadSessionSealing)) {
		return zerr.ErrUploadNotFound
	}

	session.operationMu.Lock()
	defer session.operationMu.Unlock()

	err := callback()
	if err == nil {
		session.state.Store(uint32(uploadSessionSealed))
	} else {
		session.state.Store(uint32(uploadSessionOpen))
	}

	return err
}

// tryFinalize seals and finalizes an idle session without waiting for an active
// upload operation. It returns false when the session is busy or not open.
func (session *uploadSession) tryFinalize(callback func() error) (bool, error) {
	if !session.operationMu.TryLock() {
		return false, nil
	}
	defer session.operationMu.Unlock()

	if !session.state.CompareAndSwap(uint32(uploadSessionOpen), uint32(uploadSessionSealing)) {
		return false, nil
	}

	err := callback()
	if err == nil {
		session.state.Store(uint32(uploadSessionSealed))
	} else {
		session.state.Store(uint32(uploadSessionOpen))
	}

	return true, err
}

func (session *uploadSession) isSealing() bool {
	return uploadSessionState(session.state.Load()) == uploadSessionSealing
}

func (session *uploadSession) isSealed() bool {
	return uploadSessionState(session.state.Load()) == uploadSessionSealed
}

// cleanupSealed serializes cleanup of a source left behind after a successful
// move. It never reopens the upload session for normal writers.
func (session *uploadSession) cleanupSealed(callback func() error) error {
	if !session.isSealed() {
		return zerr.ErrUploadNotFound
	}

	session.operationMu.Lock()
	defer session.operationMu.Unlock()

	if !session.isSealed() {
		return zerr.ErrUploadNotFound
	}

	return callback()
}

// tryCleanupSealed removes a sealed upload without waiting for another cleanup
// operation. It returns false when the session is not sealed or is busy.
func (session *uploadSession) tryCleanupSealed(callback func() error) (bool, error) {
	if !session.isSealed() || !session.operationMu.TryLock() {
		return false, nil
	}
	defer session.operationMu.Unlock()

	if !session.isSealed() {
		return false, nil
	}

	return true, callback()
}

func validateUploadSessionID(uuid string) error {
	if uuid == "" || len(uuid) > maxUploadSessionIDLength || strings.IndexByte(uuid, 0) >= 0 {
		return zerr.ErrUploadNotFound
	}

	return nil
}

type uploadSessionRegistry struct {
	lock     sync.Mutex
	sessions map[string]*uploadSession
	// inProgress counts chunk copies and commits, which run before the bytes
	// are a listed object. It changes only while lock is held.
	inProgress map[string]int
	// blocked prefixes refuse startInProgress until the matching repo delete
	// finishes. Same lock as inProgress, so a session cannot become in progress
	// between the idle check and the refusal.
	blocked map[string]struct{}
}

func newUploadSessionRegistry() uploadSessionRegistry {
	return uploadSessionRegistry{
		sessions:   make(map[string]*uploadSession),
		inProgress: make(map[string]int),
		blocked:    make(map[string]struct{}),
	}
}

func (registry *uploadSessionRegistry) get(key string) *uploadSession {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	session, ok := registry.sessions[key]
	if !ok {
		session = newUploadSession()
		registry.sessions[key] = session
	}

	return session
}

func (registry *uploadSessionRegistry) delete(key string, session *uploadSession) {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	if registry.sessions[key] == session {
		delete(registry.sessions, key)
	}
}

// startInProgress marks key until finishInProgress. A prefix already blocked
// for deletion is refused, so the upload cannot start against a repo GC has
// decided to remove.
func (registry *uploadSessionRegistry) startInProgress(key string) error {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	for prefix := range registry.blocked {
		if strings.HasPrefix(key, prefix) {
			return zerr.ErrUploadNotFound
		}
	}

	registry.inProgress[key]++

	return nil
}

func (registry *uploadSessionRegistry) finishInProgress(key string) {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	registry.inProgress[key]--
	if registry.inProgress[key] <= 0 {
		delete(registry.inProgress, key)
	}
}

// blockIfIdle reports whether prefix has no in-progress upload. When it does
// not, startInProgress for that prefix fails until release runs. Both the
// observation and the refusal happen before this method returns the lock, so
// a session cannot become in progress while the caller is deciding to delete.
func (registry *uploadSessionRegistry) blockIfIdle(prefix string) (func(), bool) {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	prefix = strings.TrimSuffix(prefix, "/") + "/"

	for key, count := range registry.inProgress {
		if count > 0 && strings.HasPrefix(key, prefix) {
			return nil, false
		}
	}

	registry.blocked[prefix] = struct{}{}

	return func() {
		registry.lock.Lock()
		delete(registry.blocked, prefix)
		registry.lock.Unlock()
	}, true
}
