//go:build quota

package extensions

import (
	"errors"
	"fmt"
	"net/http"
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
	var mu sync.Mutex

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

			// Serialize new-repo pushes to prevent concurrent requests from
			// both observing count < maxRepos and exceeding the limit.
			mu.Lock()
			defer mu.Unlock()

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

				detail := map[string]string{"limit": fmt.Sprintf("%d", maxRepos)}
				zcommon.WriteJSON(w, http.StatusTooManyRequests,
					apiErr.NewErrorList(apiErr.NewError(apiErr.TOOMANYREQUESTS).AddDetail(detail)))

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func SetupQuotaRoutes(
	conf *config.Config,
	router *mux.Router,
	metaDB mTypes.MetaDB,
	log log.Logger,
) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if extensionsConfig == nil || extensionsConfig.Quota == nil {
		return
	}

	quotaConf := extensionsConfig.Quota
	if quotaConf.Enable == nil || !*quotaConf.Enable {
		return
	}

	if quotaConf.MaxRepos <= 0 {
		return
	}

	if metaDB == nil {
		log.Warn().Msg("metaDB is not initialized, repository quota enforcement disabled")
		return
	}

	log.Info().Int("maxRepos", quotaConf.MaxRepos).Msg("repository quota enforcement enabled")
	router.Use(repoQuotaMiddleware(quotaConf.MaxRepos, metaDB, log))
}
