//go:build userprefs
// +build userprefs

package extensions

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

const (
	ToggleRepoBookmarkAction = "toggleBookmark"
	ToggleRepoStarAction     = "toggleStar"
)

func SetupUserPreferencesRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	repoDB repodb.RepoDB, cveInfo CveInfo, log log.Logger,
) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		log.Info().Msg("setting up user preferences routes")

		userprefsRouter := router.PathPrefix(constants.ExtUserPreferencesPrefix).Subrouter()

		userprefsRouter.HandleFunc("", HandleUserPrefs(repoDB, log)).Methods(http.MethodPut)
	}
}

func HandleUserPrefs(repoDB repodb.RepoDB, log log.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(rsp http.ResponseWriter, req *http.Request) {
		if !queryHasParams(req.URL.Query(), []string{"action"}) {
			rsp.WriteHeader(http.StatusBadRequest)

			return
		}

		action := req.URL.Query().Get("action")

		switch action {
		case ToggleRepoBookmarkAction:
			PutBookmark(rsp, req, repoDB, log) //nolint:contextcheck

			return
		case ToggleRepoStarAction:
			PutStar(rsp, req, repoDB, log) //nolint:contextcheck

			return
		default:
			rsp.WriteHeader(http.StatusBadRequest)

			return
		}
	}
}

func PutStar(rsp http.ResponseWriter, req *http.Request, repoDB repodb.RepoDB, log log.Logger) {
	if !queryHasParams(req.URL.Query(), []string{"repo"}) {
		rsp.WriteHeader(http.StatusBadRequest)

		return
	}

	repo := req.URL.Query().Get("repo")

	if repo == "" {
		rsp.WriteHeader(http.StatusNotFound)

		return
	}

	_, err := repoDB.ToggleStarRepo(req.Context(), repo)
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

func PutBookmark(rsp http.ResponseWriter, req *http.Request, repoDB repodb.RepoDB, log log.Logger) {
	if !queryHasParams(req.URL.Query(), []string{"repo"}) {
		rsp.WriteHeader(http.StatusBadRequest)

		return
	}

	repo := req.URL.Query().Get("repo")

	if repo == "" {
		rsp.WriteHeader(http.StatusNotFound)

		return
	}

	_, err := repoDB.ToggleBookmarkRepo(req.Context(), repo)
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

func queryHasParams(values url.Values, params []string) bool {
	for _, param := range params {
		if !values.Has(param) {
			return false
		}
	}

	return true
}
