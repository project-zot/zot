//go:build userprefs

package extensions

import (
	"errors"
	"net/http"
	"slices"

	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

const (
	ToggleRepoBookmarkAction = "toggleBookmark"
	ToggleRepoStarAction     = "toggleStar"
	UserProfilePath          = "/profile"
)

type UserProfile struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

func IsBuiltWithUserPrefsExtension() bool {
	return true
}

func SetupUserPreferencesRoutes(conf *config.Config, router *mux.Router,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.AreUserPrefsEnabled() {
		log.Info().Msg("skip enabling the user preferences route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up user preferences routes")

	userPrefsRouter := router.Path(constants.ExtUserPrefs).Subrouter()
	userPrefsRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	userPrefsRouter.Use(zcommon.AddExtensionSecurityHeaders())
	userPrefsRouter.Use(zcommon.ACHeadersMiddleware(conf, zcommon.AllowedMethods(http.MethodPut)...))
	userPrefsRouter.Methods(zcommon.AllowedMethods(http.MethodPut)...).Handler(HandleUserPrefs(metaDB, log))

	userProfileRouter := router.Path(constants.ExtUserPrefs + UserProfilePath).Subrouter()
	userProfileRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	userProfileRouter.Use(zcommon.AddExtensionSecurityHeaders())
	userProfileRouter.Use(zcommon.ACHeadersMiddleware(conf, zcommon.AllowedMethods(http.MethodGet)...))
	userProfileRouter.Methods(zcommon.AllowedMethods(http.MethodGet)...).Handler(HandleUserProfile())

	log.Info().Msg("finished setting up user preferences routes")
}

// HandleUserProfile godoc
// @Summary Get authenticated user profile
// @Description Get the authenticated user's username and groups
// @Router  /v2/_zot/ext/userprefs/profile [get]
// @Accept  json
// @Produce json
// @Success 200 {object} extensions.UserProfile
// @Failure 401 {string} string "unauthorized"
// @Failure 500 {string} string "internal server error".
func HandleUserProfile() http.Handler {
	return http.HandlerFunc(func(rsp http.ResponseWriter, req *http.Request) {
		userAc, err := reqCtx.UserAcFromContext(req.Context())
		if err != nil {
			rsp.WriteHeader(http.StatusInternalServerError)

			return
		}

		if userAc.IsAnonymous() {
			rsp.WriteHeader(http.StatusUnauthorized)

			return
		}

		groups := append([]string{}, userAc.GetGroups()...)
		slices.Sort(groups)
		groups = slices.Compact(groups)

		zcommon.WriteJSON(rsp, http.StatusOK, UserProfile{
			Username: userAc.GetUsername(),
			Groups:   groups,
		})
	})
}

// HandleUserPrefs godoc
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
