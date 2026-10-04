package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/log"
	metaCommon "zotregistry.dev/zot/v2/pkg/meta/common"
	"zotregistry.dev/zot/v2/pkg/meta/convert"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
)

type repoQuotaLock struct {
	mu         sync.Mutex
	references int
}

type repoQuotaLockSet struct {
	mu    sync.Mutex
	locks map[string]*repoQuotaLock
}

func (locks *repoQuotaLockSet) acquire(repo string) func() {
	locks.mu.Lock()

	if locks.locks == nil {
		locks.locks = map[string]*repoQuotaLock{}
	}

	lock := locks.locks[repo]
	if lock == nil {
		lock = &repoQuotaLock{}
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

// repoQuotaMiddleware serializes new-repository checks for maxRepos. Byte quota locking runs in
// UpdateManifest after the request body has been read.
func repoQuotaMiddleware(conf *config.Config, metaDB mTypes.MetaDB, log log.Logger) mux.MiddlewareFunc {
	var repoCountMu sync.Mutex

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				next.ServeHTTP(w, r)

				return
			}

			vars := mux.Vars(r)

			// "reference" is only set on /v2/{name}/manifests/{reference} routes.
			if _, ok := vars["reference"]; !ok {
				next.ServeHTTP(w, r)

				return
			}

			repoName := vars["name"]
			if repoName == "" {
				next.ServeHTTP(w, r)

				return
			}

			_, err := metaDB.GetRepoMeta(r.Context(), repoName)
			repoExists := err == nil
			if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
				log.Error().Err(err).Str("repo", repoName).
					Msg("failed to check repo existence for quota, allowing push")
				next.ServeHTTP(w, r)

				return
			}

			needsRepoCountGate := !repoExists && conf.Storage.MaxRepos > 0

			if !needsRepoCountGate {
				next.ServeHTTP(w, r)

				return
			}

			repoCountMu.Lock()
			defer repoCountMu.Unlock()

			// Re-check after acquiring the lock: another request may have created this
			// repository while this request was waiting.
			_, err = metaDB.GetRepoMeta(r.Context(), repoName)
			repoExists = err == nil
			if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
				log.Error().Err(err).Str("repo", repoName).
					Msg("failed to re-check repo existence for quota, allowing push")
				next.ServeHTTP(w, r)

				return
			}

			if !repoExists && conf.Storage.MaxRepos > 0 {
				count, countErr := metaDB.CountRepos(r.Context())
				if countErr != nil {
					log.Error().Err(countErr).Msg("failed to count repos for quota, allowing push")
					next.ServeHTTP(w, r)

					return
				}

				if count >= conf.Storage.MaxRepos {
					log.Warn().Str("repo", repoName).Int("current", count).
						Int("limit", conf.Storage.MaxRepos).
						Msg("repository quota limit reached, rejecting push")

					writeQuotaExceeded(w, int64(count), int64(count+1), int64(conf.Storage.MaxRepos))

					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeQuotaExceeded(response http.ResponseWriter, current, projected, limit int64) {
	detail := map[string]string{
		"current":   strconv.FormatInt(current, 10),
		"projected": strconv.FormatInt(projected, 10),
		"limit":     strconv.FormatInt(limit, 10),
	}
	zcommon.WriteJSON(response, http.StatusRequestEntityTooLarge,
		apiErr.NewErrorList(apiErr.NewError(apiErr.TOOMANYREQUESTS).AddDetail(detail)))
}

// checkRepoByteQuota checks the projected tag-rooted RepoMeta.Size before the manifest is written.
// It returns true when the request was rejected.
func (rh *RouteHandler) checkRepoByteQuota(response http.ResponseWriter, request *http.Request,
	repo, reference, mediaType string,
	body []byte, extraTags []string,
) bool {
	storePath := rh.c.StoreController.GetStorePath(repo)
	limit := rh.c.Config.MaxRepoBytesForStore(storePath)
	if limit <= 0 || rh.c.MetaDB == nil {
		return false
	}

	imageMeta, ok := quotaImageMeta(reference, mediaType, body)
	if !ok {
		// Let the normal manifest validation report malformed input.
		return false
	}

	references, registerByDigest, ok := quotaReferences(repo, reference, body, extraTags)
	if !ok {
		return false
	}

	if !registerByDigest && len(references) == 0 {
		// Signatures and referrers do not contribute to the tag-rooted RepoMeta.Size.
		return false
	}

	current, projected, err := rh.c.MetaDB.GetRepoSizeWithCandidate(request.Context(), repo, references, imageMeta)
	if err != nil {
		if errors.Is(err, metaCommon.ErrInvalidRepoSize) {
			rh.c.Log.Warn().Err(err).Str("repo", repo).
				Msg("repository size candidate is invalid, rejecting push")
			writeQuotaExceeded(response, current, projected, limit)

			return true
		}

		rh.c.Log.Error().Err(err).Str("repo", repo).
			Msg("failed to project repository size for quota, allowing push")

		return false
	}

	// A write which does not increase usage remains useful for recovering from a
	// quota lowered below an already-existing repository size.
	if projected <= limit || projected <= current {
		return false
	}

	rh.c.Log.Warn().Str("repo", repo).Int64("current", current).
		Int64("projected", projected).Int64("limit", limit).
		Msg("repository byte quota limit reached, rejecting push")
	writeQuotaExceeded(response, current, projected, limit)

	return true
}

func quotaImageMeta(reference, mediaType string, body []byte) (mTypes.ImageMeta, bool) {
	digest := godigest.FromBytes(body)
	if zcommon.IsDigest(reference) {
		requestedDigest, err := godigest.Parse(reference)
		if err != nil || requestedDigest.Algorithm().FromBytes(body) != requestedDigest {
			return mTypes.ImageMeta{}, false
		}

		digest = requestedDigest
	}

	switch {
	case compat.IsImageManifestMediaType(mediaType):
		var manifest ispec.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			return mTypes.ImageMeta{}, false
		}

		return convert.GetImageManifestMeta(manifest, ispec.Image{}, int64(len(body)), digest, mediaType), true
	case compat.IsImageIndexMediaType(mediaType):
		var index ispec.Index
		if err := json.Unmarshal(body, &index); err != nil {
			return mTypes.ImageMeta{}, false
		}

		return convert.GetImageIndexMeta(index, int64(len(body)), digest, mediaType), true
	default:
		return mTypes.ImageMeta{}, false
	}
}

func quotaReferences(repo, reference string, body []byte, extraTags []string) ([]string, bool, bool) {
	if zcommon.IsReferrersTag(reference) {
		return nil, false, true
	}

	if len(extraTags) > 0 {
		references := make([]string, 0, len(extraTags))
		for _, tag := range extraTags {
			if zcommon.IsReferrersTag(tag) {
				continue
			}

			isSignature, err := quotaIsImageSignature(repo, body, tag)
			if err != nil {
				return nil, false, false
			}
			if !isSignature {
				references = append(references, tag)
			}
		}

		return references, false, true
	}

	isSignature, err := quotaIsImageSignature(repo, body, reference)
	if err != nil {
		return nil, false, false
	}
	if isSignature {
		return nil, false, true
	}

	if zcommon.IsDigest(reference) {
		return nil, true, true
	}

	return []string{reference}, false, true
}

func quotaIsImageSignature(repo string, body []byte, reference string) (bool, error) {
	if zcommon.IsCosignSignature(reference) && !validCosignSignatureTag(reference) {
		return false, nil
	}

	isSignature, _, _, err := storage.CheckIsImageSignature(repo, body, reference)

	return isSignature, err
}

func validCosignSignatureTag(reference string) bool {
	const (
		cosignPrefix = "sha256-"
		digestLength = 64
	)

	if len(reference) != len(cosignPrefix)+digestLength+len(".sig") {
		return false
	}

	_, err := godigest.Parse("sha256:" + reference[len(cosignPrefix):len(cosignPrefix)+digestLength])

	return err == nil
}

func setupQuotaMiddleware(
	conf *config.Config,
	router *mux.Router,
	metaDB mTypes.MetaDB,
	log log.Logger,
) {
	if !conf.IsQuotaEnabled() {
		return
	}

	if metaDB == nil {
		log.Warn().Msg("metaDB is not initialized, repository quota enforcement disabled")

		return
	}

	log.Info().Int("maxRepos", conf.Storage.MaxRepos).
		Int64("maxRepoBytes", conf.Storage.MaxRepoBytes).
		Msg("repository quota enforcement enabled")
	if conf.Storage.MaxRepos > 0 {
		router.Use(repoQuotaMiddleware(conf, metaDB, log))
	}
}

func (rh *RouteHandler) acquireRepoByteQuotaLock(repo string) func() {
	if rh == nil || rh.c == nil || rh.c.Config == nil || rh.c.MetaDB == nil {
		return func() {}
	}

	storePath := rh.c.StoreController.GetStorePath(repo)
	if rh.c.Config.MaxRepoBytesForStore(storePath) <= 0 {
		return func() {}
	}

	return rh.repoByteLocks.acquire(repo)
}
