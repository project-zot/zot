//go:build dev
// +build dev

// This file should be linked only in **development** mode.

package inject

import (
	"net/http"
	"sync"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

func Ok(ok bool) bool {
	if !ok {
		return ok
	}

	if injectedFailure() {
		return false
	}

	return true
}

func Error(err error) error {
	if err != nil {
		return err
	}

	if injectedFailure() {
		return zerr.ErrInjected
	}

	return nil
}

// Used to inject error status codes for coverage purposes.
// -1 will be returned in case of successful failure injection.
func ErrStatusCode(status int) int {
	if !injectedFailure() {
		if status == http.StatusAccepted || status == http.StatusCreated {
			return status
		}

		return 0
	}

	return -1
}

/**
 *
 * Failure injection infrastructure to cover hard-to-reach code paths.
 *
 **/

type inject struct {
	skip int
}

//nolint:gochecknoglobals // only used by test code
var injMap sync.Map

func InjectFailure(skip int) bool {
	gid := log.GoroutineID()
	if gid < 0 {
		panic("invalid goroutine id")
	}

	if _, ok := injMap.Load(gid); ok {
		panic("prior incomplete fault injection")
	}

	injst := inject{skip: skip}
	injMap.Store(gid, injst)

	return true
}

func injectedFailure() bool {
	gid := log.GoroutineID()

	val, ok := injMap.Load(gid)
	if !ok {
		return false
	}

	injst, ok := val.(inject)
	if !ok {
		panic("invalid type")
	}

	if injst.skip == 0 {
		injMap.Delete(gid)

		return true
	}

	injst.skip--
	injMap.Store(gid, injst)

	return false
}
