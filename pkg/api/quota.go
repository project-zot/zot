package api

import (
	"errors"
	"net/http"
	"strconv"
	"sync"

	zerr "zotregistry.dev/zot/v2/errors"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
)

type repoMutationLock struct {
	mu         sync.Mutex
	references int
}

type repoMutationLockSet struct {
	mu    sync.Mutex
	locks map[string]*repoMutationLock
}

func (locks *repoMutationLockSet) acquire(repo string) func() {
	locks.mu.Lock()

	if locks.locks == nil {
		locks.locks = map[string]*repoMutationLock{}
	}

	lock := locks.locks[repo]
	if lock == nil {
		lock = &repoMutationLock{}
		locks.locks[repo] = lock
	}

	lock.references++
	locks.mu.Unlock()

	lock.mu.Lock()

	return func() {
		lock.mu.Unlock()

		locks.mu.Lock()
		lock.references--
		if lock.references == 0 {
			delete(locks.locks, repo)
		}
		locks.mu.Unlock()
	}
}

func writeQuotaExceeded(response http.ResponseWriter, current, projected, limit int64) {
	detail := map[string]string{
		"current":   strconv.FormatInt(current, 10),
		"projected": strconv.FormatInt(projected, 10),
		"limit":     strconv.FormatInt(limit, 10),
	}
	zcommon.WriteJSON(response, http.StatusRequestEntityTooLarge,
		apiErr.NewErrorList(apiErr.NewError(apiErr.DENIED).AddDetail(detail)))
}

func writeInvalidRepoSize(response http.ResponseWriter) {
	detail := map[string]string{"reason": "manifest descriptor digest or size is invalid"}
	zcommon.WriteJSON(response, http.StatusBadRequest,
		apiErr.NewErrorList(apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(detail)))
}

func writeQuotaMetadataInvalid(response http.ResponseWriter) {
	detail := map[string]string{"reason": "repository size metadata is invalid"}
	zcommon.WriteJSON(response, http.StatusInternalServerError,
		apiErr.NewErrorList(apiErr.NewError(apiErr.DENIED).AddDetail(detail)))
}

// writeManifestMetaError maps MetaDB failures from OnUpdateManifest / OnUpdateManifestDigestTags
// to HTTP responses. Quota enforcement lives in SetRepoReference; storage was already written and
// rolled back by the hook on failure. Returns true when the response was written.
func writeManifestMetaError(response http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	details := zerr.GetDetails(err)

	switch {
	case errors.Is(err, zerr.ErrRepoByteQuotaExceeded), errors.Is(err, zerr.ErrMaxReposExceeded):
		current, _ := strconv.ParseInt(details["current"], 10, 64)
		projected, _ := strconv.ParseInt(details["projected"], 10, 64)
		limit, _ := strconv.ParseInt(details["limit"], 10, 64)
		writeQuotaExceeded(response, current, projected, limit)

		return true
	case errors.Is(err, zerr.ErrInvalidRepoSizeCandidate):
		writeInvalidRepoSize(response)

		return true
	case errors.Is(err, zerr.ErrInvalidRepoSize):
		writeQuotaMetadataInvalid(response)

		return true
	default:
		return false
	}
}

// acquireRepoMutationLock keeps storage mutations and their MetaDB hooks (including
// rollback) ordered for the whole repository, even when byte quotas are disabled.
func (rh *RouteHandler) acquireRepoMutationLock(repo string) func() {
	if rh == nil || rh.c == nil || rh.c.MetaDB == nil {
		return func() {}
	}

	return rh.c.repoMutationLocks.acquire(repo)
}
