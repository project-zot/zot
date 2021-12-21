//go:build dev
// +build dev

// This file should be linked only in **development** mode.

package test

import (
	"sync"

	zerr "zotregistry.io/zot/errors"
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

/**
 *
 * Failure injection infrastructure to cover hard-to-reach code paths.
 *
 **/

type inject struct {
	skip    int
	enabled bool
}

//nolint:gochecknoglobals // only used by test code
var (
	injlock sync.Mutex
	injst   = inject{}
)

func InjectFailure(skip int) bool {
	injlock.Lock()
	injst = inject{enabled: true, skip: skip}
	injlock.Unlock()

	return true
}

func injectedFailure() bool {
	injlock.Lock()
	defer injlock.Unlock()

	if !injst.enabled {
		return false
	}

	if injst.skip == 0 {
		// disable the injection point
		injst.enabled = false

		return true
	}

	injst.skip--

	return false
}
