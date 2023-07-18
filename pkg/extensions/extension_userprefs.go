//go:build userprefs
// +build userprefs

package extensions

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

const (
	ToggleRepoBookmarkAction = "toggleBookmark"
	ToggleRepoStarAction     = "toggleStar"
)

func IsBuiltWithUserPrefsExtension() bool {
	return true
}

func SetupUserPreferencesRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, cveInfo CveInfo, log log.Logger,
) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		log.Info().Msg("setting up user preferences routes")

		allowedMethods := zcommon.AllowedMethods(http.MethodPut)

		userprefsRouter := router.PathPrefix(constants.ExtUserPreferences).Subrouter()
		userprefsRouter.Use(zcommon.ACHeadersHandler(allowedMethods...))
		userprefsRouter.Use(zcommon.AddExtensionSecurityHeaders())

		userprefsRouter.HandleFunc("", HandleUserPrefs(metaDB, log)).Methods(allowedMethods...)
	}
}

// ListTags godoc
// @Summary Add bookmarks/stars info
// @Description Add bookmarks/stars info
// @Router 	/v2/_zot/ext/userprefs [put]
// @Accept  json
// @Produce json
// @Param 	action	 	 query 	 string 		true	"specify action" Enums(toggleBookmark, toggleStar)
// @Param   repo     	 query    string			true	"repository name"
// @Success 200 {string}	string				"ok"
// @Failure 404 {string} 	string 				"not found"
// @Failure 403 {string} 	string 				"forbidden"
// @Failure 500 {string} 	string 				"internal server error"
// @Failure 400 {string} 	string 				"bad request".
func HandleUserPrefs(metaDB mTypes.MetaDB, log log.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(rsp http.ResponseWriter, req *http.Request) {
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
	}
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
