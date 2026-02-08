// @title Open Container Initiative Distribution Specification
// @version v1.1.1
// @description APIs for Open Container Initiative Distribution Specification

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	guuid "github.com/gofrs/uuid"
	"github.com/google/go-github/v62/github"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	gqlPlayground "zotregistry.dev/zot/v2/pkg/debug/gqlplayground"
	"zotregistry.dev/zot/v2/pkg/debug/pprof"
	debug "zotregistry.dev/zot/v2/pkg/debug/swagger"
	ext "zotregistry.dev/zot/v2/pkg/extensions"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/inject"
)

type RouteHandler struct {
	c *Controller
}

func NewRouteHandler(c *Controller) *RouteHandler {
	rh := &RouteHandler{c: c}
	rh.SetupRoutes()

	return rh
}

func (rh *RouteHandler) SetupRoutes() {
	// health endpoints get added first
	rh.c.Router.Path("/livez").Handler(rh.c.Healthz.Handler)
	rh.c.Router.Path("/readyz").Handler(rh.c.Healthz.Handler)
	rh.c.Router.Path("/startupz").Handler(rh.c.Healthz.Handler)

	// first get Auth middleware in order to first setup openid/ldap/htpasswd, before oidc provider routes are setup
	authHandler := AuthHandler(rh.c)

	// Get CORS config safely
	allowOrigin := rh.c.Config.GetAllowOrigin()
	applyCORSHeaders := getCORSHeadersHandler(allowOrigin)

	// Get auth config for OpenID checks
	authConfig := rh.c.Config.CopyAuthConfig()
	if authConfig.IsOpenIDAuthEnabled() {
		// login path for openID
		rh.c.Router.HandleFunc(constants.LoginPath, rh.AuthURLHandler())

		// callback path for openID
		for provider, relyingParty := range rh.c.RelyingParties {
			if config.IsOauth2Supported(provider) {
				rh.c.Router.HandleFunc(constants.CallbackBasePath+"/"+provider,
					rp.CodeExchangeHandler(rh.GithubCodeExchangeCallback(), relyingParty))
			} else if config.IsOpenIDSupported(provider) {
				rh.c.Router.HandleFunc(constants.CallbackBasePath+"/"+provider,
					rp.CodeExchangeHandler(rp.UserinfoCallback(rh.OpenIDCodeExchangeCallbackWithProvider(provider)), relyingParty))
			}
		}
	}

	// Get auth config for API key checks
	if authConfig.IsAPIKeyEnabled() {
		// enable api key management urls
		apiKeyRouter := rh.c.Router.PathPrefix(constants.APIKeyPath).Subrouter()
		apiKeyRouter.Use(authHandler)
		apiKeyRouter.Use(BaseAuthzHandler(rh.c))

		// Always use CORSHeadersMiddleware before ACHeadersMiddleware
		apiKeyRouter.Use(zcommon.CORSHeadersMiddleware(rh.c.Config.GetAllowOrigin()))
		apiKeyRouter.Use(zcommon.ACHeadersMiddleware(rh.c.Config,
			http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions))

		apiKeyRouter.Methods(http.MethodPost, http.MethodOptions).HandlerFunc(rh.CreateAPIKey)
		apiKeyRouter.Methods(http.MethodGet).HandlerFunc(rh.GetAPIKeys)
		apiKeyRouter.Methods(http.MethodDelete).HandlerFunc(rh.RevokeAPIKey)
	}

	/* on every route which may be used by UI we set OPTIONS as allowed METHOD
	to enable preflight request from UI to backend */
	if authConfig.IsBasicAuthnEnabled() {
		// logout path for openID
		rh.c.Router.HandleFunc(constants.LogoutPath,
			getUIHeadersHandler(rh.c.Config, http.MethodPost, http.MethodOptions)(applyCORSHeaders(rh.Logout))).
			Methods(http.MethodPost, http.MethodOptions)
	}

	prefixedRouter := rh.c.Router.PathPrefix(constants.RoutePrefix).Subrouter()
	prefixedRouter.Use(authHandler)

	prefixedDistSpecRouter := prefixedRouter.NewRoute().Subrouter()
	// authz is being enabled if AccessControl is specified
	// if Authn is not present AccessControl will have only default policies
	accessControlConfig := rh.c.Config.CopyAccessControlConfig()
	if accessControlConfig != nil {
		if authConfig.IsBasicAuthnEnabled() {
			rh.c.Log.Info().Msg("access control is being enabled")
		} else {
			rh.c.Log.Info().Msg("anonymous policy only access control is being enabled")
		}

		prefixedRouter.Use(BaseAuthzHandler(rh.c))
		prefixedDistSpecRouter.Use(DistSpecAuthzHandler(rh.c))
	}

	clusterRouteProxy := ClusterProxy(rh.c)

	// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#endpoints
	// dist-spec APIs that need to be proxied are wrapped in clusterRouteProxy for scale-out proxying.
	// these are handlers that have a repository name.
	{
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/tags/list", zreg.NameRegexp.String()),
			clusterRouteProxy(
				getUIHeadersHandler(rh.c.Config, http.MethodGet, http.MethodOptions)(
					applyCORSHeaders(rh.ListTags),
				),
			),
		).Methods(http.MethodGet, http.MethodOptions)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			clusterRouteProxy(
				getUIHeadersHandler(rh.c.Config, http.MethodHead, http.MethodGet, http.MethodDelete, http.MethodOptions)(
					applyCORSHeaders(rh.CheckManifest),
				),
			),
		).Methods(http.MethodHead, http.MethodOptions)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			clusterRouteProxy(
				applyCORSHeaders(rh.GetManifest),
			),
		).Methods(http.MethodGet)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.UpdateManifest)).Methods(http.MethodPut)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			clusterRouteProxy(
				applyCORSHeaders(rh.DeleteManifest),
			),
		).Methods(http.MethodDelete)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.CheckBlob)).Methods(http.MethodHead)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.GetBlob)).Methods(http.MethodGet)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.DeleteBlob)).Methods(http.MethodDelete)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.CreateBlobUpload)).Methods(http.MethodPost)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.GetBlobUpload)).Methods(http.MethodGet)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.PatchBlobUpload)).Methods(http.MethodPatch)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.UpdateBlobUpload)).Methods(http.MethodPut)
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			clusterRouteProxy(rh.DeleteBlobUpload)).Methods(http.MethodDelete)
		// support for OCI artifact references
		prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/referrers/{digest}", zreg.NameRegexp.String()),
			clusterRouteProxy(
				getUIHeadersHandler(rh.c.Config, http.MethodGet, http.MethodOptions)(
					applyCORSHeaders(rh.GetReferrers),
				),
			),
		).Methods(http.MethodGet, http.MethodOptions)

		// handlers which work fine with a single node do not need proxying.
		// catalog handler doesn't require proxying as the metadata and storage are shared.
		// discover and the default path handlers are node-specific so do not require proxying.
		prefixedRouter.HandleFunc(constants.ExtCatalogPrefix,
			getUIHeadersHandler(rh.c.Config, http.MethodGet, http.MethodOptions)(
				applyCORSHeaders(rh.ListRepositories))).Methods(http.MethodGet, http.MethodOptions)
		prefixedRouter.HandleFunc(constants.ExtOciDiscoverPrefix,
			getUIHeadersHandler(rh.c.Config, http.MethodGet, http.MethodOptions)(
				applyCORSHeaders(rh.ListExtensions))).Methods(http.MethodGet, http.MethodOptions)
		prefixedRouter.HandleFunc("/",
			getUIHeadersHandler(rh.c.Config, http.MethodGet, http.MethodOptions)(
				applyCORSHeaders(rh.CheckVersionSupport))).Methods(http.MethodGet, http.MethodOptions)
	}

	// swagger
	debug.SetupSwaggerRoutes(rh.c.Config, rh.c.Router, authHandler, rh.c.Log)
	// gql playground
	gqlPlayground.SetupGQLPlaygroundRoutes(prefixedRouter, rh.c.StoreController, rh.c.Log)
	// pprof
	pprof.SetupPprofRoutes(rh.c.Config, prefixedRouter, authHandler, rh.c.Log)

	// Preconditions for enabling the actual extension routes are part of extensions themselves
	ext.SetupMetricsRoutes(rh.c.Config, rh.c.Router, authHandler, MetricsAuthzHandler(rh.c), rh.c.Log, rh.c.Metrics)
	ext.SetupSearchRoutes(rh.c.Config, prefixedRouter, rh.c.StoreController, rh.c.MetaDB, rh.c.CveScanner,
		rh.c.Log)
	ext.SetupImageTrustRoutes(rh.c.Config, prefixedRouter, rh.c.MetaDB, rh.c.Log)
	ext.SetupMgmtRoutes(rh.c.Config, prefixedRouter, rh.c.Log)
	ext.SetupUserPreferencesRoutes(rh.c.Config, prefixedRouter, rh.c.MetaDB, rh.c.Log)
	// last should always be UI because it will setup a http.FileServer and paths will be resolved by this FileServer.
	ext.SetupUIRoutes(rh.c.Config, rh.c.Router, rh.c.Log)
}

func getCORSHeadersHandler(allowOrigin string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			zcommon.AddCORSHeaders(allowOrigin, response)

			next.ServeHTTP(response, request)
		})
	}
}

func getUIHeadersHandler(config *config.Config, allowedMethods ...string) func(http.HandlerFunc) http.HandlerFunc {
	allowedMethodsValue := strings.Join(allowedMethods, ",")

	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Access-Control-Allow-Methods", allowedMethodsValue)
			response.Header().Set("Access-Control-Allow-Headers",
				"Authorization,content-type,"+constants.SessionClientHeaderName)

			// Get auth config safely
			authConfig := config.CopyAuthConfig()
			if authConfig.IsBasicAuthnEnabled() {
				response.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			next.ServeHTTP(response, request)
		})
	}
}

// Method handlers

// CheckVersionSupport godoc
// @Summary Check API support
// @Description Check if this API version is supported
// @Router  /v2/ [get]
// @Accept  json
// @Produce json
// @Success 200 {string} string "ok".
func (rh *RouteHandler) CheckVersionSupport(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		return
	}

	response.Header().Set(constants.DistAPIVersion, "registry/2.0")
	// NOTE: compatibility workaround - return this header in "allowed-read" mode to allow for clients to
	// work correctly
	// Get auth config safely
	authConfig := rh.c.Config.CopyAuthConfig()
	if authConfig.IsBasicAuthnEnabled() || authConfig.IsBearerAuthEnabled() {
		// don't send auth headers if request is coming from UI
		if request.Header.Get(constants.SessionClientHeaderName) != constants.SessionClientHeaderValue {
			if authConfig.Bearer != nil {
				realm := authConfig.Bearer.Realm
				response.Header().Set("WWW-Authenticate", "bearer realm="+realm)
			} else {
				realm := rh.c.Config.GetRealm()
				response.Header().Set("WWW-Authenticate", "basic realm="+realm)
			}
		}
	}

	zcommon.WriteData(response, http.StatusOK, "application/json", []byte{})
}

// ListTags godoc
// @Summary List image tags
// @Description List all image tags in a repository
// @Router  /v2/{name}/tags/list [get]
// @Accept  json
// @Produce json
// @Param   name  path   string   true   "repository name"
// @Param   n     query  integer  true   "limit entries for pagination"
// @Param   last  query  string   true   "last tag value for pagination"
// @Success 200 {object}     common.ImageTags
// @Failure 404 {string}     string                 "not found"
// @Failure 400 {string}     string                 "bad request".
func (rh *RouteHandler) ListTags(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		return
	}

	vars := mux.Vars(request)

	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	paginate := false
	numTags := -1

	nQuery, ok := request.URL.Query()["n"]

	if ok {
		if len(nQuery) != 1 {
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		var nQuery1 int64

		var err error

		if nQuery1, err = strconv.ParseInt(nQuery[0], 10, 0); err != nil {
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		numTags = int(nQuery1)
		paginate = true

		if numTags < 0 {
			response.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	last := ""
	lastQuery, ok := request.URL.Query()["last"]

	if ok {
		if len(lastQuery) != 1 {
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		last = lastQuery[0]
	}

	imgStore := rh.getImageStore(name)

	tags, err := imgStore.GetImageTags(name)
	if err != nil {
		e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(map[string]string{"name": name})
		zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))

		return
	}

	// Tags need to be sorted regardless of pagination parameters
	sort.Strings(tags)

	// Determine index of first tag returned
	startIndex := 0

	if last != "" {
		found := false

		for i, tag := range tags {
			if tag == last {
				found = true
				startIndex = i + 1

				break
			}
		}

		if !found {
			response.WriteHeader(http.StatusNotFound)

			return
		}
	}

	pTags := zcommon.ImageTags{Name: name}

	if paginate && numTags == 0 {
		pTags.Tags = []string{}
		zcommon.WriteJSON(response, http.StatusOK, pTags)

		return
	}

	stopIndex := len(tags) - 1
	if paginate && (startIndex+numTags < len(tags)) {
		stopIndex = startIndex + numTags - 1
		response.Header().Set(
			"Link",
			fmt.Sprintf("</v2/%s/tags/list?n=%d&last=%s>; rel=\"next\"",
				name,
				numTags,
				tags[stopIndex],
			),
		)
	}

	pTags.Tags = tags[startIndex : stopIndex+1]

	zcommon.WriteJSON(response, http.StatusOK, pTags)
}

// CheckManifest godoc
// @Summary Check image manifest
// @Description Check an image's manifest given a reference or a digest
// @Router  /v2/{name}/manifests/{reference} [head]
// @Accept  json
// @Produce json
// @Param   name          path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Success 200 {string} string "ok"
// @Header  200 {object} constants.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error".
func (rh *RouteHandler) CheckManifest(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		return
	}

	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		e := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(map[string]string{"reference": reference})
		zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))

		return
	}

	content, digest, mediaType, err := getImageManifest(request.Context(), rh, imgStore, name, reference)
	if err != nil {
		details := zerr.GetDetails(err)
		details["reference"] = reference

		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			e := apiErr.NewError(apiErr.MANIFEST_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrSyncParseRemoteRepo) {
			e := apiErr.NewError(apiErr.DENIED).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusForbidden, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")

			e := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusInternalServerError, apiErr.NewErrorList(e))
		}

		return
	}

	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.Header().Set("Content-Length", strconv.Itoa(len(content)))
	response.Header().Set("Content-Type", mediaType)
	response.WriteHeader(http.StatusOK)
}

type ImageManifest struct {
	ispec.Manifest
}

type ExtensionList struct {
	extensions.ExtensionList
}

// GetManifest godoc
// @Summary Get image manifest
// @Description Get an image's manifest given a reference or a digest
// @Accept  json
// @Produce application/vnd.oci.image.manifest.v1+json
// @Param   name         path    string     true        "repository name"
// @Param   reference    path    string     true        "image reference or digest"
// @Success 200 {object} api.ImageManifest
// @Header  200 {object} constants.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/manifests/{reference} [get].
func (rh *RouteHandler) GetManifest(response http.ResponseWriter, request *http.Request) {
	// Get auth config safely
	authConfig := rh.c.Config.CopyAuthConfig()
	if authConfig.IsBasicAuthnEnabled() {
		response.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		err := apiErr.NewError(apiErr.MANIFEST_UNKNOWN).AddDetail(map[string]string{"reference": reference})
		zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(err))

		return
	}

	content, digest, mediaType, err := getImageManifest(request.Context(), rh, imgStore, name, reference)
	if err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoBadVersion) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrSyncParseRemoteRepo) {
			e := apiErr.NewError(apiErr.DENIED).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusForbidden, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if rh.c.MetaDB != nil {
		err := meta.OnGetManifest(name, reference, mediaType, content, rh.c.StoreController, rh.c.MetaDB, rh.c.Log)
		if err != nil && !errors.Is(err, zerr.ErrImageMetaNotFound) && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}
	}

	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.Header().Set("Content-Length", strconv.Itoa(len(content)))
	response.Header().Set("Content-Type", mediaType)
	zcommon.WriteData(response, http.StatusOK, mediaType, content)
}

type ImageIndex struct {
	ispec.Index
}

func getReferrers(ctx context.Context, routeHandler *RouteHandler,
	imgStore storageTypes.ImageStore, name string, digest godigest.Digest,
	artifactTypes []string,
) (ispec.Index, error) {
	if isSyncOnDemandEnabled(routeHandler.c) {
		routeHandler.c.Log.Info().Str("repository", name).Str("reference", digest.String()).
			Msg("trying to get updated referrers by syncing on demand")

		if errSync := routeHandler.c.SyncOnDemand.SyncReferrers(ctx, name, digest.String(), artifactTypes); errSync != nil {
			routeHandler.c.Log.Err(errSync).Str("repository", name).Str("reference", digest.String()).
				Msg("failed to sync image referrers")
		}
	}

	return imgStore.GetReferrers(name, digest, artifactTypes)
}

// GetReferrers godoc
// @Summary Get referrers for a given digest
// @Description Get referrers given a digest
// @Accept  json
// @Produce application/vnd.oci.image.index.v1+json
// @Param   name       path    string     true        "repository name"
// @Param   digest     path    string     true        "digest"
// @Param artifactType query string false "artifact type"
// @Success 200 {object} api.ImageIndex
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/referrers/{digest} [get].
func (rh *RouteHandler) GetReferrers(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		return
	}

	vars := mux.Vars(request)

	name, ok := vars["name"]
	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	digestStr, ok := vars["digest"]

	digest, err := godigest.Parse(digestStr)
	if !ok || digestStr == "" || err != nil {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	// filter by artifact type (more than one can be specified)
	artifactTypes := request.URL.Query()["artifactType"]

	rh.c.Log.Info().Str("digest", digest.String()).Interface("artifactType", artifactTypes).Msg("getting manifest")

	imgStore := rh.getImageStore(name)

	referrers, err := getReferrers(request.Context(), rh, imgStore, name, digest, artifactTypes)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestNotFound) || errors.Is(err, zerr.ErrRepoNotFound) {
			rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).
				Msg("failed to get manifest")
			response.WriteHeader(http.StatusNotFound)
		} else {
			rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).
				Msg("failed to get references")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	out, err := json.Marshal(referrers)
	if err != nil {
		rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("failed to marshal json")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	if len(artifactTypes) > 0 {
		// currently, the only filter supported and on this end-point
		response.Header().Set("OCI-Filters-Applied", "artifactType") //nolint:canonicalheader
	}

	zcommon.WriteData(response, http.StatusOK, ispec.MediaTypeImageIndex, out)
}

// UpdateManifest godoc
// @Summary Update image manifest
// @Description Update an image's manifest given a reference or a digest
// @Accept  json
// @Produce json
// @Param   name         path    string     true        "repository name"
// @Param   reference    path    string     true        "image reference or digest"
// @Header  201 {object} constants.DistContentDigestKey
// @Success 201 {string} string "created"
// @Failure 400 {string} string "bad request"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/manifests/{reference} [put].
func (rh *RouteHandler) UpdateManifest(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		err := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(map[string]string{"reference": reference})
		zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(err))

		return
	}

	mediaType := request.Header.Get("Content-Type")
	compatConfig := rh.c.Config.GetCompat()

	if !storageCommon.IsSupportedMediaType(compatConfig, mediaType) {
		err := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(map[string]string{"mediaType": mediaType})
		zcommon.WriteJSON(response, http.StatusUnsupportedMediaType, apiErr.NewErrorList(err))

		return
	}

	body, err := io.ReadAll(request.Body)
	// hard to reach test case, injected error (simulates an interrupted image manifest upload)
	// err could be io.ErrUnexpectedEOF
	if err := inject.Error(err); err != nil {
		rh.c.Log.Error().Err(err).Msg("unexpected error")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	digest, subjectDigest, err := imgStore.PutImageManifest(name, reference, mediaType, body)
	if err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBadManifest) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			details["blob"] = digest.String()
			e := apiErr.NewError(apiErr.BLOB_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrImageLintAnnotations) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else {
			// could be syscall.EMFILE (Err:0x18 too many opened files), etc
			rh.c.Log.Error().Err(err).Msg("unexpected error, performing cleanup")

			if err = imgStore.DeleteImageManifest(name, reference, false); err != nil {
				// deletion of image manifest is important, but not critical for image repo consistency
				// in the worst scenario a partial manifest file written to disk will not affect the repo because
				// the new manifest was not added to "index.json" file (it is possible that GC will take care of it)
				rh.c.Log.Error().Err(err).Str("repository", name).Str("reference", reference).
					Msg("couldn't remove image manifest in repo")
			}

			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if rh.c.MetaDB != nil {
		err := meta.OnUpdateManifest(request.Context(), name, reference, mediaType,
			digest, body, rh.c.StoreController, rh.c.MetaDB, rh.c.Log)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}
	}

	if subjectDigest.String() != "" {
		response.Header().Set(constants.SubjectDigestKey, subjectDigest.String())
	}

	response.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))
	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.WriteHeader(http.StatusCreated)
}

// DeleteManifest godoc
// @Summary Delete image manifest
// @Description Delete an image's manifest given a reference or a digest
// @Accept  json
// @Produce json
// @Param   name          path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Success 200 {string} string "ok"
// @Router /v2/{name}/manifests/{reference} [delete].
func (rh *RouteHandler) DeleteManifest(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	// user authz request context (set in authz middleware)
	userAc, err := reqCtx.UserAcFromContext(request.Context())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	var detectCollision bool
	if userAc != nil {
		detectCollision = userAc.Can(constants.DetectManifestCollisionPermission, name)
	}

	manifestBlob, manifestDigest, mediaType, err := imgStore.GetImageManifest(name, reference)
	if err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBadManifest) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.UNSUPPORTED).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	err = imgStore.DeleteImageManifest(name, reference, detectCollision)
	if err != nil { //nolint: dupl
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestConflict) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.MANIFEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusConflict, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBadManifest) {
			details["reference"] = reference
			e := apiErr.NewError(apiErr.UNSUPPORTED).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrManifestReferenced) {
			// manifest is part of an index image, don't allow index manipulations.
			details["reference"] = reference
			e := apiErr.NewError(apiErr.DENIED).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusMethodNotAllowed, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if rh.c.MetaDB != nil {
		err := meta.OnDeleteManifest(name, reference, mediaType, manifestDigest, manifestBlob,
			rh.c.StoreController, rh.c.MetaDB, rh.c.Log)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}
	}

	response.WriteHeader(http.StatusAccepted)
}

// canMount checks if a user has read permission on cached blobs with this specific digest.
// returns true if the user have permission to copy blob from cache.
func canMount(userAc *reqCtx.UserAccessControl, imgStore storageTypes.ImageStore, digest godigest.Digest,
) (bool, error) {
	canMount := true

	if userAc != nil {
		canMount = false

		repos, err := imgStore.GetAllDedupeReposCandidates(digest)
		if err != nil {
			return false, err
		}

		if len(repos) == 0 {
			canMount = false
		}

		// check if user can read any repo which contain this blob
		for _, repo := range repos {
			if userAc.Can(constants.ReadPermission, repo) {
				canMount = true
			}
		}
	}

	return canMount, nil
}

// CheckBlob godoc
// @Summary Check image blob/layer
// @Description Check an image's blob/layer given a digest
// @Accept  json
// @Produce json
// @Param   name     path    string     true        "repository name"
// @Param   digest   path    string     true        "blob/layer digest"
// @Success 200 {object} api.ImageManifest
// @Header  200 {object} constants.DistContentDigestKey
// @Router /v2/{name}/blobs/{digest} [head].
func (rh *RouteHandler) CheckBlob(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	digestStr, ok := vars["digest"]

	if !ok || digestStr == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	digest := godigest.Digest(digestStr)

	userAc, err := reqCtx.UserAcFromContext(request.Context())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	userCanMount := true
	accessControlConfig := rh.c.Config.CopyAccessControlConfig()

	if accessControlConfig.IsAuthzEnabled() {
		userCanMount, err = canMount(userAc, imgStore, digest)
		if err != nil {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
		}
	}

	var blen int64

	if userCanMount {
		ok, blen, err = imgStore.CheckBlob(name, digest)
	} else {
		var lockLatency time.Time

		imgStore.RLock(&lockLatency)
		defer imgStore.RUnlock(&lockLatency)

		ok, blen, _, err = imgStore.StatBlob(name, digest)
	}

	if err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic,dupl // errorslint conflicts with gocritic:IfElseChain
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.DIGEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.BLOB_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if !ok {
		e := apiErr.NewError(apiErr.BLOB_UNKNOWN).AddDetail(map[string]string{"digest": digest.String()})
		zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))

		return
	}

	response.Header().Set("Content-Length", strconv.FormatInt(blen, 10))
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.WriteHeader(http.StatusOK)
}

/* parseRangeHeader validates the "Range" HTTP header and returns the range. */
func parseRangeHeader(contentRange string) (int64, int64, error) {
	/* bytes=<start>- and bytes=<start>-<end> formats are supported */
	pattern := `bytes=(?P<rangeFrom>\d+)-(?P<rangeTo>\d*$)`

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return -1, -1, zerr.ErrParsingHTTPHeader
	}

	match := regex.FindStringSubmatch(contentRange)

	paramsMap := make(map[string]string)

	for i, name := range regex.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}

	var from int64

	to := int64(-1)

	rangeFrom := paramsMap["rangeFrom"]
	if rangeFrom == "" {
		return -1, -1, zerr.ErrParsingHTTPHeader
	}

	if from, err = strconv.ParseInt(rangeFrom, 10, 64); err != nil {
		return -1, -1, zerr.ErrParsingHTTPHeader
	}

	rangeTo := paramsMap["rangeTo"]
	if rangeTo != "" {
		if to, err = strconv.ParseInt(rangeTo, 10, 64); err != nil {
			return -1, -1, zerr.ErrParsingHTTPHeader
		}

		if to < from {
			return -1, -1, zerr.ErrParsingHTTPHeader
		}
	}

	return from, to, nil
}

// GetBlob godoc
// @Summary Get image blob/layer
// @Description Get an image's blob/layer given a digest
// @Accept  json
// @Produce application/vnd.oci.image.layer.v1.tar+gzip
// @Param   name     path    string     true        "repository name"
// @Param   digest   path    string     true        "blob/layer digest"
// @Header  200 {object} constants.DistContentDigestKey
// @Success 200 {object} api.ImageManifest
// @Router /v2/{name}/blobs/{digest} [get].
func (rh *RouteHandler) GetBlob(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	digestStr, ok := vars["digest"]

	if !ok || digestStr == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	digest := godigest.Digest(digestStr)

	mediaType := request.Header.Get("Accept")

	/* content range is supported for resumbale pulls */
	partial := false

	var from, to int64

	var err error

	contentRange := request.Header.Get("Range")

	_, ok = request.Header["Range"]
	if ok && contentRange == "" {
		response.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

		return
	}

	if contentRange != "" {
		from, to, err = parseRangeHeader(contentRange)
		if err != nil {
			response.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return
		}

		partial = true
	}

	var repo io.ReadCloser

	var blen, bsize int64

	if partial {
		repo, blen, bsize, err = imgStore.GetBlobPartial(name, digest, mediaType, from, to)
	} else {
		repo, blen, err = imgStore.GetBlob(name, digest, mediaType)
	}

	if err != nil {
		details := zerr.GetDetails(err)
		extConf := rh.c.Config.CopyExtensionsConfig()

		if extConf.IsStreamingEnabled() {
			rh.c.Log.Info().Msg("streaming enabled. using stream logic")

			if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrBlobNotFound) {
				rh.c.Log.Info().Msg("blob was not found. Connecting client to stream")

				copier, err := rh.c.StreamManager.ConnectClient(digest.String(), response)
				if err != nil {
					rh.c.Log.Error().Err(err).Msg("failed to connect client to stream")
					response.WriteHeader(http.StatusInternalServerError)
					return
				}

				// TODO: handle partial
				err = copier.Copy()
				if err != nil {
					rh.c.Log.Error().Err(err).Msg("unexpected error during stream copy")
				}

				response.Header().Set("Content-Length", strconv.FormatInt(copier.Source.InFlightReader.GetDescriptor().Size, 10))
				response.Header().Set(constants.DistContentDigestKey, digest.String())
				response.Header().Set("Content-Type", copier.Source.InFlightReader.GetDescriptor().MediaType)
				response.WriteHeader(http.StatusOK)

				return
			}
		}

		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.DIGEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.BLOB_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	defer repo.Close()

	response.Header().Set("Content-Length", strconv.FormatInt(blen, 10))

	status := http.StatusOK

	if partial {
		status = http.StatusPartialContent

		response.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, from+blen-1, bsize))
	} else {
		response.Header().Set(constants.DistContentDigestKey, digest.String())
	}

	// return the blob data
	WriteDataFromReader(response, status, blen, mediaType, repo, rh.c.Log)
}

// DeleteBlob godoc
// @Summary Delete image blob/layer
// @Description Delete an image's blob/layer given a digest
// @Accept  json
// @Produce json
// @Param   name      path    string     true        "repository name"
// @Param   digest    path    string     true        "blob/layer digest"
// @Success 202 {string} string "accepted"
// @Router /v2/{name}/blobs/{digest} [delete].
func (rh *RouteHandler) DeleteBlob(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	digestStr, ok := vars["digest"]

	digest, err := godigest.Parse(digestStr)
	if !ok || digestStr == "" || err != nil {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	err = imgStore.DeleteBlob(name, digest)
	if err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.DIGEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(map[string]string{"name": name})
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.BLOB_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBlobReferenced) {
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.DENIED).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusMethodNotAllowed, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusAccepted)
}

// CreateBlobUpload godoc
// @Summary Create image blob/layer upload
// @Description Create a new image blob/layer upload
// @Accept  json
// @Produce json
// @Param   name    path    string     true        "repository name"
// @Success 202 {string} string "accepted"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{session_id}"
// @Header  202 {string} Range "0-0"
// @Failure 401 {string} string "unauthorized"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads [post].
func (rh *RouteHandler) CreateBlobUpload(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	// currently zot does not support cross-repository mounting, following dist-spec and returning 202
	if mountDigests, ok := request.URL.Query()["mount"]; ok {
		if len(mountDigests) != 1 {
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		mountDigest := godigest.Digest(mountDigests[0])

		userAc, err := reqCtx.UserAcFromContext(request.Context())
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}

		userCanMount := true
		accessControlConfig := rh.c.Config.CopyAccessControlConfig()

		if accessControlConfig.IsAuthzEnabled() {
			userCanMount, err = canMount(userAc, imgStore, mountDigest)
			if err != nil {
				rh.c.Log.Error().Err(err).Msg("unexpected error")
			}
		}

		// zot does not support cross mounting directly and do a workaround creating using hard link.
		// check blob looks for actual path (name+mountDigests[0]) first then look for cache and
		// if found in cache, will do hard link and if fails we will start new upload.
		if userCanMount {
			_, _, err = imgStore.CheckBlob(name, mountDigest)
		}

		if err != nil || !userCanMount {
			upload, err := imgStore.NewBlobUpload(name)
			if err != nil {
				details := zerr.GetDetails(err)
				if errors.Is(err, zerr.ErrRepoNotFound) {
					details["name"] = name
					e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
					zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
				} else {
					rh.c.Log.Error().Err(err).Msg("unexpected error")
					response.WriteHeader(http.StatusInternalServerError)
				}

				return
			}

			response.Header().Set("Location", getBlobUploadSessionLocation(request.URL, upload))
			response.Header().Set("Range", "0-0")
			response.WriteHeader(http.StatusAccepted)

			return
		}

		response.Header().Set("Location", getBlobUploadLocation(request.URL, name, mountDigest))
		response.WriteHeader(http.StatusCreated)

		return
	}

	if _, ok := request.URL.Query()["from"]; ok {
		response.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	// a full blob upload if "digest" is present
	digests, ok := request.URL.Query()["digest"]
	if ok {
		if len(digests) != 1 {
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		if contentType := request.Header.Get("Content-Type"); contentType != constants.BinaryMediaType {
			rh.c.Log.Warn().Str("actual", contentType).Str("expected", constants.BinaryMediaType).Msg("invalid media type")
			response.WriteHeader(http.StatusUnsupportedMediaType)

			return
		}

		digestStr := digests[0]

		digest := godigest.Digest(digestStr)

		var contentLength int64

		contentLength, err := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64)
		if err != nil || contentLength <= 0 {
			rh.c.Log.Warn().Str("actual", request.Header.Get("Content-Length")).Msg("invalid content length")

			details := map[string]string{"digest": digest.String()}

			if err != nil {
				details["conversion error"] = err.Error()
			} else {
				details["Content-Length"] = request.Header.Get("Content-Length")
			}

			e := apiErr.NewError(apiErr.BLOB_UPLOAD_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))

			return
		}

		sessionID, size, err := imgStore.FullBlobUpload(name, request.Body, digest)
		if err != nil {
			rh.c.Log.Error().Err(err).Int64("actual", size).Int64("expected", contentLength).
				Msg("failed to full blob upload")
			response.WriteHeader(http.StatusInternalServerError)

			return
		}

		if size != contentLength {
			rh.c.Log.Warn().Int64("actual", size).Int64("expected", contentLength).Msg("invalid content length")
			response.WriteHeader(http.StatusInternalServerError)

			return
		}

		response.Header().Set("Location", getBlobUploadLocation(request.URL, name, digest))
		response.Header().Set(constants.BlobUploadUUID, sessionID)
		response.WriteHeader(http.StatusCreated)

		return
	}

	upload, err := imgStore.NewBlobUpload(name)
	if err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.Header().Set("Location", getBlobUploadSessionLocation(request.URL, upload))
	response.Header().Set("Range", "0-0")
	response.WriteHeader(http.StatusAccepted)
}

// GetBlobUpload godoc
// @Summary Get image blob/layer upload
// @Description Get an image's blob/layer upload given a session_id
// @Accept  json
// @Produce json
// @Param   name          path    string     true        "repository name"
// @Param   session_id    path    string     true        "upload session_id"
// @Success 204 {string} string "no content"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{session_id}"
// @Header  202 {string} Range "0-128"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [get].
func (rh *RouteHandler) GetBlobUpload(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	size, err := imgStore.GetBlobUpload(name, sessionID)
	if err != nil {
		details := zerr.GetDetails(err)
		//nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
		if errors.Is(err, zerr.ErrBadUploadRange) || errors.Is(err, zerr.ErrBadBlobDigest) {
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.Header().Set("Location", getBlobUploadSessionLocation(request.URL, sessionID))
	response.Header().Set("Range", fmt.Sprintf("0-%d", size-1))
	response.WriteHeader(http.StatusNoContent)
}

// PatchBlobUpload godoc
// @Summary Resume image blob/layer upload
// @Description Resume an image's blob/layer upload given an session_id
// @Accept  json
// @Produce json
// @Param   name         path    string     true        "repository name"
// @Param   session_id   path    string     true        "upload session_id"
// @Success 202 {string} string "accepted"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{session_id}"
// @Header  202 {string} Range "0-128"
// @Header  200 {object} api.BlobUploadUUID
// @Failure 400 {string} string "bad request"
// @Failure 404 {string} string "not found"
// @Failure 416 {string} string "range not satisfiable"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [patch].
func (rh *RouteHandler) PatchBlobUpload(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	var clen int64

	var err error

	if request.Header.Get("Content-Length") == "" || request.Header.Get("Content-Range") == "" {
		// streamed blob upload
		clen, err = imgStore.PutBlobChunkStreamed(name, sessionID, request.Body)
	} else {
		// chunked blob upload
		var contentLength int64

		if contentLength, err = strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64); err != nil {
			rh.c.Log.Warn().Str("actual", request.Header.Get("Content-Length")).Msg("invalid content length")
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		var from, to int64
		if from, to, err = getContentRange(request); err != nil || (to-from)+1 != contentLength {
			response.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return
		}

		clen, err = imgStore.PutBlobChunk(name, sessionID, from, to, request.Body)
	}

	if err != nil { //nolint: dupl
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrBadUploadRange) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusRequestedRangeNotSatisfiable, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			// could be io.ErrUnexpectedEOF, syscall.EMFILE (Err:0x18 too many opened files), etc
			rh.c.Log.Error().Err(err).Msg("unexpected error, removing .uploads/ files")

			if err = imgStore.DeleteBlobUpload(name, sessionID); err != nil {
				rh.c.Log.Error().Err(err).Str("blobUpload", sessionID).Str("repository", name).
					Msg("couldn't remove blobUpload in repo")
			}

			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.Header().Set("Location", getBlobUploadSessionLocation(request.URL, sessionID))
	response.Header().Set("Range", fmt.Sprintf("0-%d", clen-1))
	response.Header().Set("Content-Length", "0")
	response.Header().Set(constants.BlobUploadUUID, sessionID)
	response.WriteHeader(http.StatusAccepted)
}

// UpdateBlobUpload godoc
// @Summary Update image blob/layer upload
// @Description Update and finish an image's blob/layer upload given a digest
// @Accept  json
// @Produce json
// @Param   name         path    string     true        "repository name"
// @Param   session_id   path    string     true        "upload session_id"
// @Param   digest       query   string     true        "blob/layer digest"
// @Success 201 {string} string "created"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{digest}"
// @Header  200 {object} constants.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [put].
func (rh *RouteHandler) UpdateBlobUpload(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	digests, ok := request.URL.Query()["digest"]
	if !ok || len(digests) != 1 {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	digest, err := godigest.Parse(digests[0])
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	contentPresent := true

	contentLen, err := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		contentPresent = false
	}

	contentRangePresent := true

	if request.Header.Get("Content-Range") == "" {
		contentRangePresent = false
	}

	// we expect at least one of "Content-Length" or "Content-Range" to be
	// present
	if !contentPresent && !contentRangePresent {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	var from, to int64

	if contentPresent {
		contentRange := request.Header.Get("Content-Range")
		if contentRange == "" { // monolithic upload
			from = 0

			if contentLen == 0 {
				goto finish
			}

			to = contentLen
		} else if from, to, err = getContentRange(request); err != nil { // finish chunked upload
			response.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return
		}

		_, err = imgStore.PutBlobChunk(name, sessionID, from, to, request.Body)
		if err != nil { //nolint:dupl
			details := zerr.GetDetails(err)
			if errors.Is(err, zerr.ErrBadUploadRange) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
				details["session_id"] = sessionID
				e := apiErr.NewError(apiErr.BLOB_UPLOAD_INVALID).AddDetail(details)
				zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
			} else if errors.Is(err, zerr.ErrRepoNotFound) {
				details["name"] = name
				e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
				zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
			} else if errors.Is(err, zerr.ErrUploadNotFound) {
				details["session_id"] = sessionID
				e := apiErr.NewError(apiErr.BLOB_UPLOAD_UNKNOWN).AddDetail(details)
				zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
			} else {
				// could be io.ErrUnexpectedEOF, syscall.EMFILE (Err:0x18 too many opened files), etc
				rh.c.Log.Error().Err(err).Msg("unexpected error, removing .uploads/ files")

				if err = imgStore.DeleteBlobUpload(name, sessionID); err != nil {
					rh.c.Log.Error().Err(err).Str("blobUpload", sessionID).Str("repository", name).
						Msg("failed to remove blobUpload in repo")
				}

				response.WriteHeader(http.StatusInternalServerError)
			}

			return
		}
	}

finish:
	// blob chunks already transferred, just finish
	if err := imgStore.FinishBlobUpload(name, sessionID, request.Body, digest); err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["digest"] = digest.String()
			e := apiErr.NewError(apiErr.DIGEST_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrBadUploadRange) {
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_INVALID).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusBadRequest, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			// could be io.ErrUnexpectedEOF, syscall.EMFILE (Err:0x18 too many opened files), etc
			rh.c.Log.Error().Err(err).Msg("unexpected error, removing .uploads/ files")

			if err = imgStore.DeleteBlobUpload(name, sessionID); err != nil {
				rh.c.Log.Error().Err(err).Str("blobUpload", sessionID).Str("repository", name).
					Msg("failed to remove blobUpload in repo")
			}

			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.Header().Set("Location", getBlobUploadLocation(request.URL, name, digest))
	response.Header().Set("Content-Length", "0")
	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.WriteHeader(http.StatusCreated)
}

// DeleteBlobUpload godoc
// @Summary Delete image blob/layer
// @Description Delete an image's blob/layer given a digest
// @Accept  json
// @Produce json
// @Param   name         path    string     true        "repository name"
// @Param   session_id   path    string     true        "upload session_id"
// @Success 200 {string} string "ok"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [delete].
func (rh *RouteHandler) DeleteBlobUpload(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	if err := imgStore.DeleteBlobUpload(name, sessionID); err != nil {
		details := zerr.GetDetails(err)
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			details["name"] = name
			e := apiErr.NewError(apiErr.NAME_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			details["session_id"] = sessionID
			e := apiErr.NewError(apiErr.BLOB_UPLOAD_UNKNOWN).AddDetail(details)
			zcommon.WriteJSON(response, http.StatusNotFound, apiErr.NewErrorList(e))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusNoContent)
}

type RepositoryList struct {
	Repositories []string `json:"repositories"`
}

func (rh *RouteHandler) listStorageRepositories(lastEntry string, maxEntries int,
	userAc *reqCtx.UserAccessControl,
) ([]string, bool, error) {
	var moreEntries bool

	var err error

	var repos []string

	remainder := maxEntries

	combineRepoList := make([]string, 0)

	subStore := rh.c.StoreController.SubStore

	subPaths := make([]string, 0)
	for subPath := range subStore {
		subPaths = append(subPaths, subPath)
	}

	sort.Strings(subPaths)

	storePath := rh.c.StoreController.GetStorePath(lastEntry)
	if storePath == storage.DefaultStorePath {
		singleStore := rh.c.StoreController.DefaultStore

		repos, moreEntries, err = singleStore.GetNextRepositories(lastEntry, remainder, AuthzFilterFunc(userAc))
		if err != nil {
			return repos, false, err
		}

		remainder = maxEntries - len(repos)

		if moreEntries && remainder <= 0 && len(repos) > 0 {
			// maxEntries has been hit
			lastEntry = repos[len(repos)-1]
		} else {
			// reset for the next substores
			lastEntry = ""
		}

		combineRepoList = append(combineRepoList, repos...)
	}

	for _, subPath := range subPaths {
		imgStore := subStore[subPath]

		if lastEntry != "" && subPath != storePath {
			continue
		}

		if remainder > 0 || maxEntries == -1 {
			repos, moreEntries, err = imgStore.GetNextRepositories(lastEntry, remainder, AuthzFilterFunc(userAc))
			if err != nil {
				return combineRepoList, false, err
			}

			// compute remainder
			remainder -= len(repos)

			if moreEntries && remainder <= 0 && len(repos) > 0 {
				// maxEntries has been hit
				lastEntry = repos[len(repos)-1]
			} else {
				// reset for the next substores
				lastEntry = ""
			}

			combineRepoList = append(combineRepoList, repos...)
		}
	}

	return combineRepoList, moreEntries, nil
}

// ListRepositories godoc
// @Summary List image repositories
// @Description List all image repositories
// @Accept  json
// @Produce json
// @Success 200 {object} api.RepositoryList
// @Failure 500 {string} string "internal server error"
// @Router /v2/_catalog [get].
func (rh *RouteHandler) ListRepositories(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		return
	}

	q := request.URL.Query()

	lastEntry := q.Get("last")

	maxEntries, err := strconv.Atoi(q.Get("n"))
	if err != nil {
		maxEntries = -1
	}

	// authz context
	userAc, err := reqCtx.UserAcFromContext(request.Context())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	repos, moreEntries, err := rh.listStorageRepositories(lastEntry, maxEntries, userAc)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	if moreEntries && len(repos) > 0 {
		lastRepo := repos[len(repos)-1]

		response.Header().Set(
			"Link",
			fmt.Sprintf("</v2/_catalog?n=%d&last=%s>; rel=\"next\"",
				maxEntries,
				lastRepo,
			),
		)
	}

	is := RepositoryList{Repositories: repos}

	zcommon.WriteJSON(response, http.StatusOK, is)
}

// ListExtensions godoc
// @Summary List Registry level extensions
// @Description List all extensions present on registry
// @Accept  json
// @Produce json
// @Success 200 {object}   api.ExtensionList
// @Router /v2/_oci/ext/discover [get].
func (rh *RouteHandler) ListExtensions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	extensionList := ext.GetExtensions(rh.c.Config)

	zcommon.WriteJSON(w, http.StatusOK, extensionList)
}

// The following routes are specific to zot and NOT part of the OCI dist-spec

// Logout godoc
// @Summary Logout by removing current session
// @Description Logout by removing current session
// @Router  /zot/auth/logout [post]
// @Accept  json
// @Produce json
// @Success 200 {string} string "ok".
// @Failure 500 {string} string "internal server error".
func (rh *RouteHandler) Logout(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		return
	}

	session, _ := rh.c.CookieStore.Get(request, "session")
	session.Options.MaxAge = -1

	err := session.Save(request, response)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	response.WriteHeader(http.StatusOK)
}

// GithubCodeExchangeCallback is a github Oauth2 CodeExchange callback.
func (rh *RouteHandler) GithubCodeExchangeCallback() rp.CodeExchangeCallback[*oidc.IDTokenClaims] {
	return func(w http.ResponseWriter, r *http.Request,
		tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, relyingParty rp.RelyingParty,
	) {
		ctx := r.Context()

		client := github.NewClient(relyingParty.OAuthConfig().Client(ctx, tokens.Token))

		email, groups, err := GetGithubUserInfo(ctx, client, rh.c.Log)
		if email == "" || err != nil {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		callbackUI, err := OAuth2Callback(rh.c, w, r, state, email, groups) //nolint: contextcheck
		if err != nil {
			if errors.Is(err, zerr.ErrInvalidStateCookie) {
				w.WriteHeader(http.StatusUnauthorized)
			}

			w.WriteHeader(http.StatusInternalServerError)
		}

		if callbackUI != "" {
			http.Redirect(w, r, callbackUI, http.StatusFound)

			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// OpenIDCodeExchangeCallback is an Openid CodeExchange callback (legacy, kept for compatibility).
func (rh *RouteHandler) OpenIDCodeExchangeCallback() rp.CodeExchangeUserinfoCallback[
	*oidc.IDTokenClaims,
	*oidc.UserInfo,
] {
	return rh.OpenIDCodeExchangeCallbackWithProvider("")
}

// OpenIDCodeExchangeCallbackWithProvider is the OIDC CodeExchange callback that supports configurable claim mapping.
// The providerName parameter is used to lookup provider-specific claim mapping configuration.
// This differs from the legacy version by allowing per-provider claim mapping based on the providerName.
func (rh *RouteHandler) OpenIDCodeExchangeCallbackWithProvider(providerName string) rp.CodeExchangeUserinfoCallback[
	*oidc.IDTokenClaims,
	*oidc.UserInfo,
] {
	return func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string,
		relyingParty rp.RelyingParty, info *oidc.UserInfo,
	) {
		// Extract username based on claim mapping configuration
		var username string
		authConfig := rh.c.Config.CopyAuthConfig()

		if authConfig != nil && authConfig.OpenID != nil && providerName != "" {
			if providerConfig, ok := authConfig.OpenID.Providers[providerName]; ok {
				// Check if claim mapping is configured
				if providerConfig.ClaimMapping != nil && providerConfig.ClaimMapping.Username != "" {
					claimName := providerConfig.ClaimMapping.Username

					// Use the configured claim
					switch claimName {
					case "preferred_username":
						username = info.PreferredUsername
					case "email":
						username = info.UserInfoEmail.Email
					case "sub":
						username = info.Subject
					case "name":
						username = info.Name
					default:
						// Try to get from custom claims in UserInfo
						if val, ok := info.Claims[claimName].(string); ok {
							username = val
						}
					}

					if username != "" {
						rh.c.Log.Debug().
							Str("provider", providerName).
							Str("claim", claimName).
							Str("username", username).
							Msg("extracted username from configured claim")
					}
				}
			}
		}

		// Fallback to email if no username was extracted
		if username == "" {
			username = info.UserInfoEmail.Email
			rh.c.Log.Debug().
				Str("provider", providerName).
				Str("username", username).
				Msg("using email as username (fallback)")
		}

		if username == "" {
			rh.c.Log.Error().Msg("failed to set user record for empty username value")
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		var groups []string

		val, ok := info.Claims["groups"].([]any)
		if !ok {
			rh.c.Log.Info().Msgf("failed to find any 'groups' claim for user %s in UserInfo", username)
		}

		for _, group := range val {
			groups = append(groups, fmt.Sprint(group))
		}

		val, ok = tokens.IDTokenClaims.Claims["groups"].([]any)
		if !ok {
			rh.c.Log.Info().Msgf("failed to find any 'groups' claim for user %s in IDTokenClaimsToken", username)
		}

		for _, group := range val {
			groups = append(groups, fmt.Sprint(group))
		}

		slices.Sort(groups)
		groups = slices.Compact(groups)

		callbackUI, err := OAuth2Callback(rh.c, w, r, state, username, groups)
		if err != nil {
			if errors.Is(err, zerr.ErrInvalidStateCookie) {
				w.WriteHeader(http.StatusUnauthorized)
			}

			w.WriteHeader(http.StatusInternalServerError)
		}

		if callbackUI != "" {
			http.Redirect(w, r, callbackUI, http.StatusFound)

			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// helper routines

func getContentRange(r *http.Request) (int64 /* from */, int64 /* to */, error) {
	contentRange := r.Header.Get("Content-Range")
	tokens := strings.Split(contentRange, "-")

	rangeStart, err := strconv.ParseInt(tokens[0], 10, 64)
	if err != nil {
		return -1, -1, zerr.ErrBadUploadRange
	}

	rangeEnd, err := strconv.ParseInt(tokens[1], 10, 64)
	if err != nil {
		return -1, -1, zerr.ErrBadUploadRange
	}

	if rangeStart > rangeEnd {
		return -1, -1, zerr.ErrBadUploadRange
	}

	return rangeStart, rangeEnd, nil
}

func WriteDataFromReader(response http.ResponseWriter, status int, length int64, mediaType string,
	reader io.Reader, logger log.Logger,
) {
	response.Header().Set("Content-Type", mediaType)
	response.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	response.WriteHeader(status)

	const maxSize = 10 * 1024 * 1024

	for {
		_, err := io.CopyN(response, reader, maxSize)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			// other kinds of intermittent errors can occur, e.g, io.ErrShortWrite
			logger.Error().Err(err).Msg("failed to copy data into http response")

			return
		}
	}
}

// will return image storage corresponding to subpath provided in config.
func (rh *RouteHandler) getImageStore(name string) storageTypes.ImageStore {
	return rh.c.StoreController.GetImageStore(name)
}

// will sync on demand if an image is not found, in case sync extensions is enabled.
func getImageManifest(ctx context.Context, routeHandler *RouteHandler, imgStore storageTypes.ImageStore, name,
	reference string,
) ([]byte, godigest.Digest, string, error) {
	syncEnabled := isSyncOnDemandEnabled(routeHandler.c)

	_, digestErr := godigest.Parse(reference)
	if digestErr == nil {
		// if it's a digest then return local cached image, if not found and sync enabled, then try to sync
		content, digest, mediaType, err := imgStore.GetImageManifest(name, reference)
		if err == nil || !syncEnabled {
			return content, digest, mediaType, err
		}
	}

	if syncEnabled {
		routeHandler.c.Log.Info().Str("repository", name).Str("reference", reference).
			Msg("trying to get updated image by syncing on demand")

		extConf := routeHandler.c.Config.CopyExtensionsConfig()

		// if streaming enabled, return manifest immediately, start sync in background
		if extConf.IsStreamingEnabled() {
			routeHandler.c.Log.Info().Str("repository", name).Str("reference", reference).
				Msg("streaming is enabled. Direct fetching manifest.")

			m, err := routeHandler.c.SyncOnDemand.FetchManifest(ctx, name, reference)
			if err != nil {
				routeHandler.c.Log.Err(err).Str("repository", name).Str("reference", reference).
					Msg("failed to fetch manifest")
				return imgStore.GetImageManifest(name, reference)
			}

			content, err := m.RawBody()
			if err != nil {
				routeHandler.c.Log.Err(err).Str("repository", name).Str("reference", reference).
					Msg("failed to read manifest")
				return imgStore.GetImageManifest(name, reference)
			}

			go func() {
				if errSync := routeHandler.c.SyncOnDemand.SyncImage(ctx, name, reference); errSync != nil {
					routeHandler.c.Log.Err(errSync).Str("repository", name).Str("reference", reference).
						Msg("failed to sync image")
				}
			}()

			return content, m.GetDescriptor().Digest, m.GetDescriptor().MediaType, nil
		}

		if errSync := routeHandler.c.SyncOnDemand.SyncImage(ctx, name, reference); errSync != nil {
			routeHandler.c.Log.Err(errSync).Str("repository", name).Str("reference", reference).
				Msg("failed to sync image")
		}
	}

	return imgStore.GetImageManifest(name, reference)
}

type APIKeyPayload struct { //nolint:revive
	Label          string   `json:"label"`
	Scopes         []string `json:"scopes"`
	ExpirationDate string   `json:"expirationDate"`
}

// GetAPIKeys godoc
// @Summary Get list of API keys for the current user
// @Description Get list of all API keys for a logged in user
// @Accept  json
// @Produce json
// @Success 200 {string} string "ok"
// @Failure 401 {string} string "unauthorized"
// @Failure 500 {string} string "internal server error"
// @Router  /zot/auth/apikey  [get].
func (rh *RouteHandler) GetAPIKeys(resp http.ResponseWriter, req *http.Request) {
	apiKeys, err := rh.c.MetaDB.GetUserAPIKeys(req.Context())
	if err != nil {
		rh.c.Log.Error().Err(err).Msg("failed to get list of api keys for user")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	apiKeyResponse := struct {
		APIKeys []mTypes.APIKeyDetails `json:"apiKeys"`
	}{
		APIKeys: apiKeys,
	}

	json := jsoniter.ConfigCompatibleWithStandardLibrary

	data, err := json.Marshal(apiKeyResponse)
	if err != nil {
		rh.c.Log.Error().Err(err).Msg("failed to marshal api key response")

		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp.Header().Set("Content-Type", constants.DefaultMediaType)
	resp.WriteHeader(http.StatusOK)
	_, _ = resp.Write(data)
}

// CreateAPIKey godoc
// @Summary Create an API key for the current user
// @Description Can create an api key for a logged in user, based on the provided label and scopes.
// @Accept  json
// @Produce json
// @Param   id  body  APIKeyPayload  true  "api token id (UUID)"
// @Success 201 {string} string "created"
// @Failure 400 {string} string "bad request"
// @Failure 401 {string} string "unauthorized"
// @Failure 500 {string} string "internal server error"
// @Router  /zot/auth/apikey  [post].
func (rh *RouteHandler) CreateAPIKey(resp http.ResponseWriter, req *http.Request) {
	var payload APIKeyPayload

	body, err := io.ReadAll(req.Body)
	if err != nil {
		rh.c.Log.Error().Msg("failed to read request body")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = json.Unmarshal(body, &payload)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)

		return
	}

	apiKey, apiKeyID, err := GenerateAPIKey(guuid.DefaultGenerator, rh.c.Log)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	hashedAPIKey := hashUUID(apiKey)

	createdAt := time.Now()

	// won't expire if no value provided
	expirationDate := time.Time{}

	if payload.ExpirationDate != "" {
		//nolint: gosmopolitan
		expirationDate, err = time.ParseInLocation(constants.APIKeyTimeFormat, payload.ExpirationDate, time.Local)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)

			return
		}

		if createdAt.After(expirationDate) {
			resp.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	apiKeyDetails := &mTypes.APIKeyDetails{
		CreatedAt:      createdAt,
		ExpirationDate: expirationDate,
		IsExpired:      false,
		CreatorUA:      req.UserAgent(),
		GeneratedBy:    "manual",
		Label:          payload.Label,
		Scopes:         payload.Scopes,
		UUID:           apiKeyID,
	}

	err = rh.c.MetaDB.AddUserAPIKey(req.Context(), hashedAPIKey, apiKeyDetails)
	if err != nil {
		rh.c.Log.Error().Err(err).Msg("failed to store api key")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	apiKeyResponse := struct {
		mTypes.APIKeyDetails

		APIKey string `json:"apiKey"`
	}{
		APIKey:        fmt.Sprintf("%s%s", constants.APIKeysPrefix, apiKey),
		APIKeyDetails: *apiKeyDetails,
	}

	json := jsoniter.ConfigCompatibleWithStandardLibrary

	data, err := json.Marshal(apiKeyResponse)
	if err != nil {
		rh.c.Log.Error().Err(err).Msg("failed to marshal api key response")

		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp.Header().Set("Content-Type", constants.DefaultMediaType)
	resp.WriteHeader(http.StatusCreated)
	_, _ = resp.Write(data)
}

// RevokeAPIKey godoc
// @Summary Revokes one current user API key
// @Description Revokes one current user API key based on given key ID
// @Accept  json
// @Produce json
// @Param   id  query  string   true   "api token id (UUID)"
// @Success 200 {string} string "ok"
// @Failure 500 {string} string "internal server error"
// @Failure 401 {string} string "unauthorized"
// @Failure 400 {string} string "bad request"
// @Router  /zot/auth/apikey [delete].
func (rh *RouteHandler) RevokeAPIKey(resp http.ResponseWriter, req *http.Request) {
	ids, ok := req.URL.Query()["id"]
	if !ok || len(ids) != 1 {
		resp.WriteHeader(http.StatusBadRequest)

		return
	}

	keyID := ids[0]

	err := rh.c.MetaDB.DeleteUserAPIKey(req.Context(), keyID)
	if err != nil {
		rh.c.Log.Error().Err(err).Str("keyID", keyID).Msg("failed to delete api key")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp.WriteHeader(http.StatusOK)
}

// GetBlobUploadSessionLocation returns actual blob location to start/resume uploading blobs.
// e.g. /v2/<name>/blobs/uploads/<session-id>.
func getBlobUploadSessionLocation(url *url.URL, sessionID string) string {
	url.RawQuery = ""

	if !strings.Contains(url.Path, sessionID) {
		url.Path = path.Join(url.Path, sessionID)
	}

	return url.String()
}

// GetBlobUploadLocation returns actual blob location on registry
// e.g /v2/<name>/blobs/<digest>.
func getBlobUploadLocation(url *url.URL, name string, digest godigest.Digest) string {
	url.RawQuery = ""

	// we are relying on request URL to set location and
	// if request URL contains uploads either we are resuming blob upload or starting a new blob upload.
	// getBlobUploadLocation will be called only when blob upload is completed and
	// location should be set as blob url <v2/<name>/blobs/<digest>>.
	if strings.Contains(url.Path, "uploads") {
		url.Path = path.Join(constants.RoutePrefix, name, constants.Blobs, digest.String())
	}

	return url.String()
}

func isSyncOnDemandEnabled(ctlr *Controller) bool {
	if ctlr == nil {
		return false
	}

	extensionsConfig := ctlr.Config.CopyExtensionsConfig()
	if extensionsConfig.IsSyncEnabled() &&
		fmt.Sprintf("%v", ctlr.SyncOnDemand) != fmt.Sprintf("%v", nil) {
		return true
	}

	return false
}
