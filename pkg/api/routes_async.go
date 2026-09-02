package api

import (
	"context"
	"errors"

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
	if !ok || !asyncSync.IsAsyncOnDemandEnabledForRepo(repo) {
		return nil, false
	}

	return asyncSync, true
}

func isManifestCacheMiss(err error) bool {
	return errors.Is(err, zerr.ErrRepoNotFound) ||
		errors.Is(err, zerr.ErrManifestNotFound) ||
		errors.Is(err, zerr.ErrBlobNotFound)
}
