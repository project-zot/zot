package api

import (
	"context"
	"errors"
	"reflect"

	zerr "zotregistry.dev/zot/v2/errors"
)

type asyncSyncOnDemand interface {
	IsAsyncOnDemandEnabledForRepo(repo string) bool
	QueueImage(ctx context.Context, repo, reference string)
}

func (rh *RouteHandler) asyncOnDemand(repo string) (asyncSyncOnDemand, bool) {
	if rh.c.SyncOnDemand == nil {
		return nil, false
	}

	asyncSync, ok := rh.c.SyncOnDemand.(asyncSyncOnDemand)
	if !ok || isNilInterface(asyncSync) || !asyncSync.IsAsyncOnDemandEnabledForRepo(repo) {
		return nil, false
	}

	return asyncSync, true
}

func isManifestCacheMiss(err error) bool {
	return errors.Is(err, zerr.ErrRepoNotFound) ||
		errors.Is(err, zerr.ErrManifestNotFound) ||
		errors.Is(err, zerr.ErrBlobNotFound)
}

// isNilInterface reports whether value holds a typed nil (e.g. a nil *BaseOnDemand), which a plain
// "!= nil" check on the interface does not catch.
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}

	rv := reflect.ValueOf(value)

	switch rv.Kind() { //nolint:exhaustive // only nillable kinds matter here
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
