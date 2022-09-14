// @title Open Container Initiative Distribution Specification
// @version v1.1.0-dev
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
	"sort"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	gqlPlayground "zotregistry.io/zot/pkg/debug/gqlplayground"
	debug "zotregistry.io/zot/pkg/debug/swagger"
	ext "zotregistry.io/zot/pkg/extensions"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/log"
	repoDBUpdate "zotregistry.io/zot/pkg/meta/repodb/update"
	zreg "zotregistry.io/zot/pkg/regexp"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test" //nolint:goimports
)

type RouteHandler struct {
	c *Controller
}

func NewRouteHandler(c *Controller) *RouteHandler {
	rh := &RouteHandler{c: c}
	rh.SetupRoutes()

	return rh
}

func allowedMethods(method string) []string {
	return []string{http.MethodOptions, method}
}

func (rh *RouteHandler) SetupRoutes() {
	rh.c.Router.Use(AuthHandler(rh.c))
	// authz is being enabled if AccessControl is specified
	// if Authn is not present AccessControl will have only default policies
	if rh.c.Config.AccessControl != nil && !isBearerAuthEnabled(rh.c.Config) {
		if isAuthnEnabled(rh.c.Config) {
			rh.c.Log.Info().Msg("access control is being enabled")
		} else {
			rh.c.Log.Info().Msg("default policy only access control is being enabled")
		}

		rh.c.Router.Use(AuthzHandler(rh.c))
	}

	// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#endpoints
	prefixedRouter := rh.c.Router.PathPrefix(constants.RoutePrefix).Subrouter()
	{
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/tags/list", zreg.NameRegexp.String()),
			rh.ListTags).Methods(allowedMethods("GET")...)
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			rh.CheckManifest).Methods(allowedMethods("HEAD")...)
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			rh.GetManifest).Methods(allowedMethods("GET")...)
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			rh.UpdateManifest).Methods("PUT")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", zreg.NameRegexp.String()),
			rh.DeleteManifest).Methods("DELETE")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", zreg.NameRegexp.String()),
			rh.CheckBlob).Methods("HEAD")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", zreg.NameRegexp.String()),
			rh.GetBlob).Methods("GET")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", zreg.NameRegexp.String()),
			rh.DeleteBlob).Methods("DELETE")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/", zreg.NameRegexp.String()),
			rh.CreateBlobUpload).Methods("POST")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			rh.GetBlobUpload).Methods("GET")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			rh.PatchBlobUpload).Methods("PATCH")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			rh.UpdateBlobUpload).Methods("PUT")
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", zreg.NameRegexp.String()),
			rh.DeleteBlobUpload).Methods("DELETE")
		// support for OCI artifact references
		prefixedRouter.HandleFunc(fmt.Sprintf("/{name:%s}/referrers/{digest}", zreg.NameRegexp.String()),
			rh.GetReferrers).Methods(allowedMethods("GET")...)
		prefixedRouter.HandleFunc(constants.ExtCatalogPrefix,
			rh.ListRepositories).Methods(allowedMethods("GET")...)
		prefixedRouter.HandleFunc(constants.ExtOciDiscoverPrefix,
			rh.ListExtensions).Methods(allowedMethods("GET")...)
		prefixedRouter.HandleFunc("/",
			rh.CheckVersionSupport).Methods(allowedMethods("GET")...)
	}

	// support for ORAS artifact reference types (alpha 1) - image signature use case
	rh.c.Router.HandleFunc(fmt.Sprintf("%s/{name:%s}/manifests/{digest}/referrers",
		constants.ArtifactSpecRoutePrefix, zreg.NameRegexp.String()), rh.GetOrasReferrers).Methods("GET")

	// swagger
	debug.SetupSwaggerRoutes(rh.c.Config, rh.c.Router, rh.c.Log)

	// Setup Extensions Routes
	if rh.c.Config != nil {
		if rh.c.Config.Extensions == nil {
			// minimal build
			prefixedRouter.HandleFunc("/metrics", rh.GetMetrics).Methods("GET")
		} else {
			// extended build
			// AuthHandler(rh.c), ??? no auth??
			ext.SetupMetricsRoutes(rh.c.Config, rh.c.Router, rh.c.StoreController, rh.c.Log)
			// ext.SetupSearchRoutes(rh.c.Config, prefixedRouter, rh.c.StoreController, rh.c.RepoDB, rh.c.Log)
			ext.SetupSearchRoutes(rh.c.Config, prefixedRouter, rh.c.StoreController,
				rh.c.RepoDB, rh.c.MetaStore, rh.c.Log)
			// UI not declared
			// ext.SetupUIRoutes(rh.c.Config, rh.c.Router, rh.c.StoreController, rh.c.Log)
			gqlPlayground.SetupGQLPlaygroundRoutes(rh.c.Config, prefixedRouter, rh.c.StoreController, rh.c.Log)
		}
	}
}

// Method handlers

// CheckVersionSupport godoc
// @Summary Check API support
// @Description Check if this API version is supported
// @Router 	/v2/ [get]
// @Accept  json
// @Produce json
// @Success 200 {string} string	"ok".
func (rh *RouteHandler) CheckVersionSupport(response http.ResponseWriter, request *http.Request) {
	response.Header().Set(constants.DistAPIVersion, "registry/2.0")
	// NOTE: compatibility workaround - return this header in "allowed-read" mode to allow for clients to
	// work correctly
	if rh.c.Config.HTTP.Auth != nil {
		if rh.c.Config.HTTP.Auth.Bearer != nil {
			response.Header().Set("WWW-Authenticate", fmt.Sprintf("bearer realm=%s", rh.c.Config.HTTP.Auth.Bearer.Realm))
		} else {
			response.Header().Set("WWW-Authenticate", fmt.Sprintf("basic realm=%s", rh.c.Config.HTTP.Realm))
		}
	}

	WriteData(response, http.StatusOK, "application/json", []byte{})
}

type ImageTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// ListTags godoc
// @Summary List image tags
// @Description List all image tags in a repository
// @Router 	/v2/{name}/tags/list [get]
// @Accept  json
// @Produce json
// @Param   name     path    string     true        "test"
// @Param 	n	 			 query 	 integer 		true				"limit entries for pagination"
// @Param 	last	 	 query 	 string 		true				"last tag value for pagination"
// @Success 200 {object} 	api.ImageTags
// @Failure 404 {string} 	string 				"not found"
// @Failure 400 {string} 	string 				"bad request".
func (rh *RouteHandler) ListTags(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)

	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

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

	tags, err := imgStore.GetImageTags(name)
	if err != nil {
		WriteJSON(response, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))

		return
	}

	if paginate && (numTags < len(tags)) {
		sort.Strings(tags)

		pTags := ImageTags{Name: name}

		if last == "" {
			// first
			pTags.Tags = tags[:numTags]
		} else {
			// next
			var i int
			found := false
			for idx, tag := range tags {
				if tag == last {
					found = true
					i = idx

					break
				}
			}

			if !found {
				response.WriteHeader(http.StatusNotFound)

				return
			}

			if numTags >= len(tags)-i {
				pTags.Tags = tags[i+1:]
				WriteJSON(response, http.StatusOK, pTags)

				return
			}

			pTags.Tags = tags[i+1 : i+1+numTags]
		}

		if len(pTags.Tags) == 0 {
			last = ""
		} else {
			last = pTags.Tags[len(pTags.Tags)-1]
		}

		response.Header().Set("Link", fmt.Sprintf("/v2/%s/tags/list?n=%d&last=%s; rel=\"next\"", name, numTags, last))
		WriteJSON(response, http.StatusOK, pTags)

		return
	}

	WriteJSON(response, http.StatusOK, ImageTags{Name: name, Tags: tags})
}

// CheckManifest godoc
// @Summary Check image manifest
// @Description Check an image's manifest given a reference or a digest
// @Router 	/v2/{name}/manifests/{reference} [head]
// @Accept  json
// @Produce json
// @Param   name     			path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Success 200 {string} string	"ok"
// @Header  200 {object} cosntants.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error".
func (rh *RouteHandler) CheckManifest(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(response,
			http.StatusNotFound,
			NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))

		return
	}

	content, digest, mediaType, err := getImageManifest(request.Context(), rh, imgStore,
		name, reference) //nolint:contextcheck
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"reference": reference})))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			WriteJSON(response, http.StatusInternalServerError,
				NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		}

		return
	}

	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	response.Header().Set("Content-Type", mediaType)
	response.WriteHeader(http.StatusOK)
}

// NOTE: https://github.com/swaggo/swag/issues/387.
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
// @Param   name     			path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Success 200 {object} 	api.ImageManifest
// @Header  200 {object} constants.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/manifests/{reference} [get].
func (rh *RouteHandler) GetManifest(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	name, ok := vars["name"]

	if !ok || name == "" {
		response.WriteHeader(http.StatusNotFound)

		return
	}

	imgStore := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(response,
			http.StatusNotFound,
			NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))

		return
	}

	content, digest, mediaType, err := getImageManifest(request.Context(), rh,
		imgStore, name, reference) //nolint: contextcheck
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrRepoBadVersion) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if rh.c.RepoDB != nil {
		err := repoDBUpdate.OnGetManifest(name, reference, digest, content, rh.c.StoreController, rh.c.RepoDB, rh.c.Log)

		if errors.Is(err, zerr.ErrOrphanSignature) {
			rh.c.Log.Error().Err(err).Msgf("image is an orphan signature")
		} else if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}
	}

	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	response.Header().Set("Content-Type", mediaType)
	WriteData(response, http.StatusOK, mediaType, content)
}

type ImageIndex struct {
	ispec.Index
}

func getReferrers(ctx context.Context, routeHandler *RouteHandler,
	imgStore storage.ImageStore, name string, digest godigest.Digest,
	artifactTypes []string,
) (ispec.Index, error) {
	references, err := imgStore.GetReferrers(name, digest, artifactTypes)
	if err != nil {
		if routeHandler.c.Config.Extensions != nil &&
			routeHandler.c.Config.Extensions.Sync != nil &&
			*routeHandler.c.Config.Extensions.Sync.Enable {
			routeHandler.c.Log.Info().Msgf("referrers not found, trying to get referrers to %s:%s by syncing on demand",
				name, digest)

			errSync := ext.SyncOneImage(ctx, routeHandler.c.Config, routeHandler.c.StoreController,
				name, digest.String(), sync.OCIReference, routeHandler.c.Log)
			if errSync != nil {
				routeHandler.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("unable to get references")

				return ispec.Index{}, err
			}

			references, err = imgStore.GetReferrers(name, digest, artifactTypes)
		}
	}

	return references, err
}

// GetReferrers godoc
// @Summary Get references for a given digest
// @Description Get references given a digest
// @Accept  json
// @Produce application/vnd.oci.image.index.v1+json
// @Param   name     			path    string     true        "repository name"
// @Param   digest     path    string     true        "digest"
// @Success 200 {object} 	api.ImageIndex
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/references/{digest} [get].
func (rh *RouteHandler) GetReferrers(response http.ResponseWriter, request *http.Request) {
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
			rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("manifest not found")
			response.WriteHeader(http.StatusNotFound)
		}

		rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("unable to get references")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	out, err := json.Marshal(referrers)
	if err != nil {
		rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("unable to marshal json")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	WriteData(response, http.StatusOK, ispec.MediaTypeImageIndex, out)
}

// UpdateManifest godoc
// @Summary Update image manifest
// @Description Update an image's manifest given a reference or a digest
// @Accept  json
// @Produce json
// @Param   name     			path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Header  201 {object} constants.DistContentDigestKey
// @Success 201 {string} string	"created"
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
		WriteJSON(response,
			http.StatusNotFound,
			NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))

		return
	}

	mediaType := request.Header.Get("Content-Type")
	if !storage.IsSupportedMediaType(mediaType) {
		// response.WriteHeader(http.StatusUnsupportedMediaType)
		WriteJSON(response, http.StatusUnsupportedMediaType,
			NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"mediaType": mediaType})))

		return
	}

	body, err := io.ReadAll(request.Body)
	// hard to reach test case, injected error (simulates an interrupted image manifest upload)
	// err could be io.ErrUnexpectedEOF
	if err := test.Error(err); err != nil {
		rh.c.Log.Error().Err(err).Msg("unexpected error")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	digest, err := imgStore.PutImageManifest(name, reference, mediaType, body)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		} else if errors.Is(err, zerr.ErrBadManifest) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"blob": digest.String()})))
		} else if errors.Is(err, zerr.ErrRepoBadVersion) {
			WriteJSON(response, http.StatusInternalServerError,
				NewErrorList(NewError(INVALID_INDEX, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrImageLintAnnotations) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		} else {
			// could be syscall.EMFILE (Err:0x18 too many opened files), etc
			rh.c.Log.Error().Err(err).Msg("unexpected error: performing cleanup")

			if err = imgStore.DeleteImageManifest(name, reference, false); err != nil {
				// deletion of image manifest is important, but not critical for image repo consistancy
				// in the worst scenario a partial manifest file written to disk will not affect the repo because
				// the new manifest was not added to "index.json" file (it is possible that GC will take care of it)
				rh.c.Log.Error().Err(err).Msgf("couldn't remove image manifest %s in repo %s", reference, name)
			}

			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if rh.c.RepoDB != nil {
		err := repoDBUpdate.OnUpdateManifest(name, reference, mediaType, digest, body, rh.c.StoreController, rh.c.RepoDB,
			rh.c.Log)
		if errors.Is(err, zerr.ErrOrphanSignature) {
			rh.c.Log.Error().Err(err).Msgf("pushed image is an orphan signature")
		} else if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}
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
// @Param   name     			path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Success 200 {string} string	"ok"
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

	// authz request context (set in authz middleware)
	acCtx, err := localCtx.GetAccessControlContext(request.Context())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	var detectCollision bool
	if acCtx != nil {
		detectCollision = acCtx.CanDetectManifestCollision(name)
	}

	manifestBlob, manifestDigest, mediaType, err := imgStore.GetImageManifest(name, reference)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		} else if errors.Is(err, zerr.ErrBadManifest) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(UNSUPPORTED, map[string]string{"reference": reference})))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	err = imgStore.DeleteImageManifest(name, reference, detectCollision)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrManifestNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		} else if errors.Is(err, zerr.ErrManifestConflict) {
			WriteJSON(response, http.StatusConflict,
				NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		} else if errors.Is(err, zerr.ErrBadManifest) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(UNSUPPORTED, map[string]string{"reference": reference})))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if rh.c.RepoDB != nil {
		err := repoDBUpdate.OnDeleteManifest(name, reference, mediaType, manifestDigest, manifestBlob,
			rh.c.StoreController, rh.c.RepoDB, rh.c.Log)
		if errors.Is(err, zerr.ErrOrphanSignature) {
			rh.c.Log.Error().Err(err).Msgf("pushed image is an orphan signature")
		} else if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}
	}

	response.WriteHeader(http.StatusAccepted)
}

// CheckBlob godoc
// @Summary Check image blob/layer
// @Description Check an image's blob/layer given a digest
// @Accept  json
// @Produce json
// @Param   name				path    string     true        "repository name"
// @Param   digest     	path    string     true        "blob/layer digest"
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

	ok, blen, err := imgStore.CheckBlob(name, digest)
	if err != nil {
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response,
				http.StatusBadRequest,
				NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest.String()})))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			WriteJSON(response, http.StatusNotFound, NewErrorList(NewError(BLOB_UNKNOWN,
				map[string]string{"digest": digest.String()})))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if !ok {
		WriteJSON(response, http.StatusNotFound, NewErrorList(NewError(BLOB_UNKNOWN,
			map[string]string{"digest": digest.String()})))

		return
	}

	response.Header().Set("Content-Length", fmt.Sprintf("%d", blen))
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
// @Param   name				path    string     true        "repository name"
// @Param   digest     	path    string     true        "blob/layer digest"
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
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response,
				http.StatusBadRequest,
				NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest.String()})))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response,
				http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			WriteJSON(response,
				http.StatusNotFound,
				NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"digest": digest.String()})))
		} else {
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}
	defer repo.Close()

	response.Header().Set("Content-Length", fmt.Sprintf("%d", blen))

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
// @Param   name				path    string     true        "repository name"
// @Param   digest     	path    string     true        "blob/layer digest"
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
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response,
				http.StatusBadRequest,
				NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest.String()})))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response,
				http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrBlobNotFound) {
			WriteJSON(response,
				http.StatusNotFound,
				NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{".String()": digest.String()})))
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
// @Param   name				path    string     true        "repository name"
// @Success 202 {string} string	"accepted"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{session_id}"
// @Header  202 {string} Range "0-0"
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
		// zot does not support cross mounting directly and do a workaround creating using hard link.
		// check blob looks for actual path (name+mountDigests[0]) first then look for cache and
		// if found in cache, will do hard link and if fails we will start new upload.
		_, _, err := imgStore.CheckBlob(name, mountDigest)
		if err != nil {
			upload, err := imgStore.NewBlobUpload(name)
			if err != nil {
				if errors.Is(err, zerr.ErrRepoNotFound) {
					WriteJSON(response, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
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

		rh.c.Log.Info().Int64("r.ContentLength", request.ContentLength).Msg("DEBUG")

		digestStr := digests[0]

		digest := godigest.Digest(digestStr)

		var contentLength int64

		contentLength, err := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64)
		if err != nil || contentLength <= 0 {
			rh.c.Log.Warn().Str("actual", request.Header.Get("Content-Length")).Msg("invalid content length")
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"digest": digest.String()})))

			return
		}

		sessionID, size, err := imgStore.FullBlobUpload(name, request.Body, digest)
		if err != nil {
			rh.c.Log.Error().Err(err).Int64("actual", size).Int64("expected", contentLength).Msg("failed full upload")
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
		if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
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
// @Param   name     path    string     true        "repository name"
// @Param   session_id     path    string     true        "upload session_id"
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
		if errors.Is(err, zerr.ErrBadUploadRange) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		} else if errors.Is(err, zerr.ErrBadBlobDigest) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
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
// @Param   name     path    string     true        "repository name"
// @Param   session_id     path    string     true        "upload session_id"
// @Success 202 {string} string	"accepted"
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

	if err != nil {
		if errors.Is(err, zerr.ErrBadUploadRange) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusRequestedRangeNotSatisfiable,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
		} else {
			// could be io.ErrUnexpectedEOF, syscall.EMFILE (Err:0x18 too many opened files), etc
			rh.c.Log.Error().Err(err).Msg("unexpected error: removing .uploads/ files")

			if err = imgStore.DeleteBlobUpload(name, sessionID); err != nil {
				rh.c.Log.Error().Err(err).Msgf("couldn't remove blobUpload %s in repo %s", sessionID, name)
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
// @Param   name     path    string     true        "repository name"
// @Param   session_id     path    string     true        "upload session_id"
// @Param 	digest	 query 	 string 		true				"blob/layer digest"
// @Success 201 {string} string	"created"
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

	rh.c.Log.Info().Int64("r.ContentLength", request.ContentLength).Msg("DEBUG")

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
		if err != nil {
			if errors.Is(err, zerr.ErrBadUploadRange) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
				WriteJSON(response, http.StatusBadRequest,
					NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
			} else if errors.Is(err, zerr.ErrRepoNotFound) {
				WriteJSON(response, http.StatusNotFound,
					NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
			} else if errors.Is(err, zerr.ErrUploadNotFound) {
				WriteJSON(response, http.StatusNotFound,
					NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
			} else {
				// could be io.ErrUnexpectedEOF, syscall.EMFILE (Err:0x18 too many opened files), etc
				rh.c.Log.Error().Err(err).Msg("unexpected error: removing .uploads/ files")

				if err = imgStore.DeleteBlobUpload(name, sessionID); err != nil {
					rh.c.Log.Error().Err(err).Msgf("couldn't remove blobUpload %s in repo %s", sessionID, name)
				}
				response.WriteHeader(http.StatusInternalServerError)
			}

			return
		}
	}

finish:
	// blob chunks already transferred, just finish
	if err := imgStore.FinishBlobUpload(name, sessionID, request.Body, digest); err != nil {
		if errors.Is(err, zerr.ErrBadBlobDigest) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest.String()})))
		} else if errors.Is(err, zerr.ErrBadUploadRange) {
			WriteJSON(response, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		} else if errors.Is(err, zerr.ErrRepoNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
		} else {
			// could be io.ErrUnexpectedEOF, syscall.EMFILE (Err:0x18 too many opened files), etc
			rh.c.Log.Error().Err(err).Msg("unexpected error: removing .uploads/ files")

			if err = imgStore.DeleteBlobUpload(name, sessionID); err != nil {
				rh.c.Log.Error().Err(err).Msgf("couldn't remove blobUpload %s in repo %s", sessionID, name)
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
// @Param   name     path    string     true        "repository name"
// @Param   session_id     path    string     true        "upload session_id"
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
		if errors.Is(err, zerr.ErrRepoNotFound) { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		} else if errors.Is(err, zerr.ErrUploadNotFound) {
			WriteJSON(response, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
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

// ListRepositories godoc
// @Summary List image repositories
// @Description List all image repositories
// @Accept  json
// @Produce json
// @Success 200 {object} 	api.RepositoryList
// @Failure 500 {string} string "internal server error"
// @Router /v2/_catalog [get].
func (rh *RouteHandler) ListRepositories(response http.ResponseWriter, request *http.Request) {
	combineRepoList := make([]string, 0)

	subStore := rh.c.StoreController.SubStore

	for _, imgStore := range subStore {
		repos, err := imgStore.GetRepositories()
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}

		combineRepoList = append(combineRepoList, repos...)
	}

	singleStore := rh.c.StoreController.DefaultStore
	if singleStore != nil {
		repos, err := singleStore.GetRepositories()
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)

			return
		}

		combineRepoList = append(combineRepoList, repos...)
	}

	var repos []string

	// authz context
	acCtx, err := localCtx.GetAccessControlContext(request.Context())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	if acCtx != nil {
		for _, r := range combineRepoList {
			if acCtx.IsAdmin || acCtx.CanReadRepo(r) {
				repos = append(repos, r)
			}
		}
	} else {
		repos = combineRepoList
	}

	is := RepositoryList{Repositories: repos}

	WriteJSON(response, http.StatusOK, is)
}

// ListExtensions godoc
// @Summary List Registry level extensions
// @Description List all extensions present on registry
// @Accept  json
// @Produce json
// @Success 200 {object} 	api.ExtensionList
// @Router /v2/_oci/ext/discover [get].
func (rh *RouteHandler) ListExtensions(w http.ResponseWriter, r *http.Request) {
	extensionList := ext.GetExtensions(rh.c.Config)

	WriteJSON(w, http.StatusOK, extensionList)
}

func (rh *RouteHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	m := rh.c.Metrics.ReceiveMetrics()
	WriteJSON(w, http.StatusOK, m)
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

func WriteJSON(response http.ResponseWriter, status int, data interface{}) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	WriteData(response, status, constants.DefaultMediaType, body)
}

func WriteData(w http.ResponseWriter, status int, mediaType string, data []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
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
			logger.Error().Err(err).Msg("copying data into http response")

			return
		}
	}
}

// will return image storage corresponding to subpath provided in config.
func (rh *RouteHandler) getImageStore(name string) storage.ImageStore {
	return rh.c.StoreController.GetImageStore(name)
}

// will sync on demand if an image is not found, in case sync extensions is enabled.
func getImageManifest(ctx context.Context, routeHandler *RouteHandler, imgStore storage.ImageStore, name,
	reference string,
) ([]byte, godigest.Digest, string, error) {
	content, digest, mediaType, err := imgStore.GetImageManifest(name, reference)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrManifestNotFound) {
			if routeHandler.c.Config.Extensions != nil &&
				routeHandler.c.Config.Extensions.Sync != nil &&
				*routeHandler.c.Config.Extensions.Sync.Enable {
				routeHandler.c.Log.Info().Msgf("image not found, trying to get image %s:%s by syncing on demand",
					name, reference)

				errSync := ext.SyncOneImage(ctx, routeHandler.c.Config, routeHandler.c.StoreController,
					name, reference, "", routeHandler.c.Log)
				if errSync != nil {
					routeHandler.c.Log.Err(errSync).Msgf("error encounter while syncing image %s:%s",
						name, reference)
				} else {
					content, digest, mediaType, err = imgStore.GetImageManifest(name, reference)
				}
			}
		} else {
			return []byte{}, "", "", err
		}
	}

	return content, digest, mediaType, err
}

// will sync referrers on demand if they are not found, in case sync extensions is enabled.
func getOrasReferrers(ctx context.Context, routeHandler *RouteHandler,
	imgStore storage.ImageStore, name string, digest godigest.Digest,
	artifactType string,
) ([]artifactspec.Descriptor, error) {
	refs, err := imgStore.GetOrasReferrers(name, digest, artifactType)
	if err != nil {
		if routeHandler.c.Config.Extensions != nil &&
			routeHandler.c.Config.Extensions.Sync != nil &&
			*routeHandler.c.Config.Extensions.Sync.Enable {
			routeHandler.c.Log.Info().Msgf("signature not found, trying to get signature %s:%s by syncing on demand",
				name, digest.String())

			errSync := ext.SyncOneImage(ctx, routeHandler.c.Config, routeHandler.c.StoreController,
				name, digest.String(), sync.OrasArtifact, routeHandler.c.Log)
			if errSync != nil {
				routeHandler.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("unable to get references")

				return []artifactspec.Descriptor{}, err
			}

			refs, err = imgStore.GetOrasReferrers(name, digest, artifactType)
		}
	}

	return refs, err
}

type ReferenceList struct {
	References []artifactspec.Descriptor `json:"references"`
}

// GetOrasReferrers godoc
// @Summary Get references for an image
// @Description Get references for an image given a digest and artifact type
// @Accept  json
// @Produce json
// @Param   name     path    string     true        "repository name"
// @Param   digest   path    string     true        "image digest"
// @Param 	artifactType	 query 	 string 	true	    "artifact type"
// @Success 200 {string} string "ok"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /oras/artifacts/v1/{name:%s}/manifests/{digest}/referrers [get].
func (rh *RouteHandler) GetOrasReferrers(response http.ResponseWriter, request *http.Request) {
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

	// filter by artifact type
	artifactType := ""

	artifactTypes, ok := request.URL.Query()["artifactType"]
	if ok {
		if len(artifactTypes) != 1 {
			rh.c.Log.Error().Msg("invalid artifact types")
			response.WriteHeader(http.StatusBadRequest)

			return
		}

		artifactType = artifactTypes[0]
	}

	imgStore := rh.getImageStore(name)

	rh.c.Log.Info().Str("digest", digest.String()).Str("artifactType", artifactType).Msg("getting manifest")

	refs, err := getOrasReferrers(request.Context(), rh, imgStore, name, digest, artifactType) //nolint:contextcheck
	if err != nil {
		rh.c.Log.Error().Err(err).Str("name", name).Str("digest", digest.String()).Msg("unable to get references")
		response.WriteHeader(http.StatusNotFound)

		return
	}

	rs := ReferenceList{References: refs}

	WriteJSON(response, http.StatusOK, rs)
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
