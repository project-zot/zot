package api

import (
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

func repoQuotaMiddleware(maxRepos int, metaDB mTypes.MetaDB, log log.Logger) mux.MiddlewareFunc {
	var quotaMu sync.Mutex

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
			if err == nil {
				next.ServeHTTP(w, r)

				return
			}

			if !errors.Is(err, zerr.ErrRepoMetaNotFound) {
				log.Error().Err(err).Str("repo", repoName).
					Msg("failed to check repo existence for quota, allowing push")
				next.ServeHTTP(w, r)

				return
			}

			quotaMu.Lock()
			defer quotaMu.Unlock()

			// Re-check after acquiring the lock: another request may have
			// created this repo while we were waiting.
			_, err = metaDB.GetRepoMeta(r.Context(), repoName)
			if err == nil {
				next.ServeHTTP(w, r)

				return
			}

			count, err := metaDB.CountRepos(r.Context())
			if err != nil {
				log.Error().Err(err).Msg("failed to count repos for quota, allowing push")
				next.ServeHTTP(w, r)

				return
			}

			if count >= maxRepos {
				log.Warn().
					Str("repo", repoName).
					Int("current", count).
					Int("limit", maxRepos).
					Msg("repository quota limit reached, rejecting push")

				detail := map[string]string{"limit": strconv.Itoa(maxRepos)}
				zcommon.WriteJSON(w, http.StatusTooManyRequests,
					apiErr.NewErrorList(apiErr.NewError(apiErr.TOOMANYREQUESTS).AddDetail(detail)))

				return
			}

			next.ServeHTTP(w, r)
		})
	}
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

	log.Info().Int("maxRepos", conf.Storage.MaxRepos).Msg("repository quota enforcement enabled")
	router.Use(repoQuotaMiddleware(conf.Storage.MaxRepos, metaDB, log))
}
