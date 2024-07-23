//go:build userprefs
// +build userprefs

package extensions

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

const (
	ToggleRepoBookmarkAction = "toggleBookmark"
	ToggleRepoStarAction     = "toggleStar"
)

func IsBuiltWithUserPrefsExtension() bool {
	return true
}

func SetupUserPreferencesRoutes(conf *config.Config, router *mux.Router,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	if !conf.AreUserPrefsEnabled() {
		log.Info().Msg("skip enabling the user preferences route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up user preferences routes")

	allowedMethods := zcommon.AllowedMethods(http.MethodPut)

	userPrefsRouter := router.PathPrefix(constants.ExtUserPrefs).Subrouter()
	userPrefsRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	userPrefsRouter.Use(zcommon.AddExtensionSecurityHeaders())
	userPrefsRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	userPrefsRouter.Methods(allowedMethods...).Handler(HandleUserPrefs(metaDB, log))

	log.Info().Msg("finished setting up user preferences routes")
}

// Repo preferences godoc
// @Summary Add bookmarks/stars info
// @Description Add bookmarks/stars info
// @Router  /v2/_zot/ext/userprefs [put]
// @Accept  json
// @Produce json
// @Param   action    query    string     true  "specify action" Enums(toggleBookmark, toggleStar)
// @Param   repo      query    string     true  "repository name"
// @Success 200 {string}   string   "ok"
// @Failure 404 {string}   string   "not found"
// @Failure 403 {string}   string   "forbidden"
// @Failure 500 {string}   string   "internal server error"
// @Failure 400 {string}   string   "bad request".
func HandleUserPrefs(metaDB mTypes.MetaDB, log log.Logger) http.Handler {
	return http.HandlerFunc(func(rsp http.ResponseWriter, req *http.Request) {
		if !zcommon.QueryHasParams(req.URL.Query(), []string{"action"}) {
			rsp.WriteHeader(http.StatusBadRequest)

			return
		}

		action := req.URL.Query().Get("action")

		switch action {
		case ToggleRepoBookmarkAction:
			PutBookmark(rsp, req, metaDB, log) //nolint:contextcheck

			return
		case ToggleRepoStarAction:
			PutStar(rsp, req, metaDB, log) //nolint:contextcheck

			return
		default:
			rsp.WriteHeader(http.StatusBadRequest)

			return
		}
	})
}

func PutStar(rsp http.ResponseWriter, req *http.Request, metaDB mTypes.MetaDB, log log.Logger) {
	if !zcommon.QueryHasParams(req.URL.Query(), []string{"repo"}) {
		rsp.WriteHeader(http.StatusBadRequest)

		return
	}

	repo := req.URL.Query().Get("repo")

	if repo == "" {
		rsp.WriteHeader(http.StatusNotFound)

		return
	}

	_, err := metaDB.ToggleStarRepo(req.Context(), repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			rsp.WriteHeader(http.StatusNotFound)

			return
		} else if errors.Is(err, zerr.ErrUserDataNotAllowed) {
			rsp.WriteHeader(http.StatusForbidden)

			return
		}

		rsp.WriteHeader(http.StatusInternalServerError)

		return
	}

	rsp.WriteHeader(http.StatusOK)
}

func PutBookmark(rsp http.ResponseWriter, req *http.Request, metaDB mTypes.MetaDB, log log.Logger) {
	if !zcommon.QueryHasParams(req.URL.Query(), []string{"repo"}) {
		rsp.WriteHeader(http.StatusBadRequest)

		return
	}

	repo := req.URL.Query().Get("repo")

	if repo == "" {
		rsp.WriteHeader(http.StatusNotFound)

		return
	}

	_, err := metaDB.ToggleBookmarkRepo(req.Context(), repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			rsp.WriteHeader(http.StatusNotFound)

			return
		} else if errors.Is(err, zerr.ErrUserDataNotAllowed) {
			rsp.WriteHeader(http.StatusForbidden)

			return
		}

		rsp.WriteHeader(http.StatusInternalServerError)

		return
	}

	rsp.WriteHeader(http.StatusOK)
}
