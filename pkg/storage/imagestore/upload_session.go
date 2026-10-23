package imagestore

import (
	"sync"
	"sync/atomic"

	zerr "zotregistry.dev/zot/v2/errors"
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
	state     atomic.Uint32
	operation sync.Mutex
}

func newUploadSession() *uploadSession {
	session := &uploadSession{}
	session.state.Store(uint32(uploadSessionOpen))

	return session
}

// withOpen runs fn as one upload operation. A writer that started before a
// finalizer seals the session may finish; writers that arrive after sealing do
// not consume their request bodies and receive the normal upload-not-found
// response.
func (session *uploadSession) withOpen(operation func() error) error {
	if uploadSessionState(session.state.Load()) != uploadSessionOpen {
		return zerr.ErrUploadNotFound
	}

	session.operation.Lock()
	defer session.operation.Unlock()

	if uploadSessionState(session.state.Load()) != uploadSessionOpen {
		return zerr.ErrUploadNotFound
	}

	return operation()
}

// finalize seals the session before waiting for an already active writer and
// while fn performs commit, digest verification, and move. Failed finalization
// reopens the session so existing retry behavior is preserved.
func (session *uploadSession) finalize(operation func() error) error {
	if !session.state.CompareAndSwap(uint32(uploadSessionOpen), uint32(uploadSessionSealing)) {
		return zerr.ErrUploadNotFound
	}

	session.operation.Lock()
	defer session.operation.Unlock()

	err := operation()
	if err == nil {
		session.state.Store(uint32(uploadSessionSealed))
	} else {
		session.state.Store(uint32(uploadSessionOpen))
	}

	return err
}

func (session *uploadSession) isSealing() bool {
	return uploadSessionState(session.state.Load()) == uploadSessionSealing
}

func (session *uploadSession) isSealed() bool {
	return uploadSessionState(session.state.Load()) == uploadSessionSealed
}

// cleanupSealed serializes cleanup of a source left behind after a successful
// move. It never reopens the upload session for normal writers.
func (session *uploadSession) cleanupSealed(operation func() error) error {
	if !session.isSealed() {
		return zerr.ErrUploadNotFound
	}

	session.operation.Lock()
	defer session.operation.Unlock()

	if !session.isSealed() {
		return zerr.ErrUploadNotFound
	}

	return operation()
}

type uploadSessionRegistry struct {
	lock     sync.Mutex
	sessions map[string]*uploadSession
}

func (registry *uploadSessionRegistry) get(key string) *uploadSession {
	registry.lock.Lock()
	defer registry.lock.Unlock()

	if registry.sessions == nil {
		registry.sessions = make(map[string]*uploadSession)
	}

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
