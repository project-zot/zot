// @title Open Container Initiative Distribution Specification
// @version v0.1.0-dev
// @description APIs for Open Container Initiative Distribution Specification

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

package api

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"

	_ "github.com/anuvu/zot/docs" // as required by swaggo
	"github.com/anuvu/zot/errors"
	ext "github.com/anuvu/zot/pkg/extensions"
	"github.com/anuvu/zot/pkg/extensions/monitoring"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	httpSwagger "github.com/swaggo/http-swagger"
)

const (
	RoutePrefix          = "/v2"
	DistAPIVersion       = "Docker-Distribution-API-Version"
	DistContentDigestKey = "Docker-Content-Digest"
	BlobUploadUUID       = "Blob-Upload-UUID"
	DefaultMediaType     = "application/json"
	BinaryMediaType      = "application/octet-stream"
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
	rh.c.Router.Use(AuthHandler(rh.c))

	if !isBearerAuthEnabled(rh.c.Config) && rh.c.Config.AccessControl != nil {
		rh.c.Router.Use(AuthzHandler(rh.c))
	}

	g := rh.c.Router.PathPrefix(RoutePrefix).Subrouter()
	{
		g.HandleFunc(fmt.Sprintf("/{name:%s}/tags/list", NameRegexp.String()),
			rh.ListTags).Methods("GET")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", NameRegexp.String()),
			rh.CheckManifest).Methods("HEAD")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", NameRegexp.String()),
			rh.GetManifest).Methods("GET")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", NameRegexp.String()),
			rh.UpdateManifest).Methods("PUT")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/manifests/{reference}", NameRegexp.String()),
			rh.DeleteManifest).Methods("DELETE")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", NameRegexp.String()),
			rh.CheckBlob).Methods("HEAD")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", NameRegexp.String()),
			rh.GetBlob).Methods("GET")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/{digest}", NameRegexp.String()),
			rh.DeleteBlob).Methods("DELETE")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/", NameRegexp.String()),
			rh.CreateBlobUpload).Methods("POST")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", NameRegexp.String()),
			rh.GetBlobUpload).Methods("GET")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", NameRegexp.String()),
			rh.PatchBlobUpload).Methods("PATCH")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", NameRegexp.String()),
			rh.UpdateBlobUpload).Methods("PUT")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{session_id}", NameRegexp.String()),
			rh.DeleteBlobUpload).Methods("DELETE")
		g.HandleFunc("/_catalog",
			rh.ListRepositories).Methods("GET")
		g.HandleFunc("/",
			rh.CheckVersionSupport).Methods("GET")
	}
	// swagger docs "/swagger/v2/index.html"
	rh.c.Router.PathPrefix("/swagger/v2/").Methods("GET").Handler(httpSwagger.WrapHandler)
	// Setup Extensions Routes
	if rh.c.Config != nil {
		if rh.c.Config.Extensions == nil {
			// minimal install
			g.HandleFunc("/metrics", rh.GetMetrics).Methods("GET")
		} else {
			ext.SetupRoutes(rh.c.Config.Extensions, rh.c.Router, rh.c.StoreController, rh.c.Log)
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
func (rh *RouteHandler) CheckVersionSupport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(DistAPIVersion, "registry/2.0")
	// NOTE: compatibility workaround - return this header in "allowed-read" mode to allow for clients to
	// work correctly
	if rh.c.Config.HTTP.AllowReadAccess {
		if rh.c.Config.HTTP.Auth != nil {
			if rh.c.Config.HTTP.Auth.Bearer != nil {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("bearer realm=%s", rh.c.Config.HTTP.Auth.Bearer.Realm))
			} else {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("basic realm=%s", rh.c.Config.HTTP.Realm))
			}
		}
	}

	WriteData(w, http.StatusOK, "application/json", []byte{})
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
func (rh *RouteHandler) ListTags(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	paginate := false
	n := -1

	nQuery, ok := r.URL.Query()["n"]

	if ok {
		if len(nQuery) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var n1 int64

		var err error

		if n1, err = strconv.ParseInt(nQuery[0], 10, 0); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		n = int(n1)
		paginate = true
	}

	last := ""
	lastQuery, ok := r.URL.Query()["last"]

	if ok {
		if len(lastQuery) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		last = lastQuery[0]
	}

	tags, err := is.GetImageTags(name)
	if err != nil {
		WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		return
	}

	if paginate && (n < len(tags)) {
		sort.Strings(tags)

		pTags := ImageTags{Name: name}

		if last == "" {
			// first
			pTags.Tags = tags[:n]
		} else {
			// next
			i := -1
			tag := ""
			found := false
			for i, tag = range tags {
				if tag == last {
					found = true
					break
				}
			}
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if n >= len(tags)-i {
				pTags.Tags = tags[i+1:]
				WriteJSON(w, http.StatusOK, pTags)
				return
			}
			pTags.Tags = tags[i+1 : i+1+n]
		}

		if len(pTags.Tags) == 0 {
			last = ""
		} else {
			last = pTags.Tags[len(pTags.Tags)-1]
		}

		w.Header().Set("Link", fmt.Sprintf("/v2/%s/tags/list?n=%d&last=%s; rel=\"next\"", name, n, last))
		WriteJSON(w, http.StatusOK, pTags)

		return
	}

	WriteJSON(w, http.StatusOK, ImageTags{Name: name, Tags: tags})
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
// @Header  200 {object} api.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error".
func (rh *RouteHandler) CheckManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		return
	}

	_, digest, mediaType, err := is.GetImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"reference": reference})))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			WriteJSON(w, http.StatusInternalServerError,
				NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		}

		return
	}

	w.Header().Set(DistContentDigestKey, digest)
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusOK)
}

// NOTE: https://github.com/swaggo/swag/issues/387.
type ImageManifest struct {
	ispec.Manifest
}

// GetManifest godoc
// @Summary Get image manifest
// @Description Get an image's manifest given a reference or a digest
// @Accept  json
// @Produce application/vnd.oci.image.manifest.v1+json
// @Param   name     			path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Success 200 {object} 	api.ImageManifest
// @Header  200 {object} api.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/manifests/{reference} [get].
func (rh *RouteHandler) GetManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		return
	}

	content, digest, mediaType, err := is.GetImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrRepoBadVersion:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set(DistContentDigestKey, digest)
	WriteData(w, http.StatusOK, mediaType, content)
}

// UpdateManifest godoc
// @Summary Update image manifest
// @Description Update an image's manifest given a reference or a digest
// @Accept  json
// @Produce json
// @Param   name     			path    string     true        "repository name"
// @Param   reference     path    string     true        "image reference or digest"
// @Header  201 {object} api.DistContentDigestKey
// @Success 201 {string} string	"created"
// @Failure 400 {string} string "bad request"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/manifests/{reference} [put].
func (rh *RouteHandler) UpdateManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		return
	}

	mediaType := r.Header.Get("Content-Type")
	if mediaType != ispec.MediaTypeImageManifest {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		rh.c.Log.Error().Err(err).Msg("unexpected error")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	digest, err := is.PutImageManifest(name, reference, mediaType, body)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		case errors.ErrBadManifest:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(MANIFEST_INVALID, map[string]string{"reference": reference})))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"blob": digest})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))
	w.Header().Set(DistContentDigestKey, digest)
	w.WriteHeader(http.StatusCreated)
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
func (rh *RouteHandler) DeleteManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	err := is.DeleteImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference})))
		case errors.ErrBadManifest:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(UNSUPPORTED, map[string]string{"reference": reference})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// CheckBlob godoc
// @Summary Check image blob/layer
// @Description Check an image's blob/layer given a digest
// @Accept  json
// @Produce json
// @Param   name				path    string     true        "repository name"
// @Param   digest     	path    string     true        "blob/layer digest"
// @Success 200 {object} api.ImageManifest
// @Header  200 {object} api.DistContentDigestKey
// @Router /v2/{name}/blobs/{digest} [head].
func (rh *RouteHandler) CheckBlob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	digest, ok := vars["digest"]
	if !ok || digest == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ok, blen, err := is.CheckBlob(name, digest)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest})))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"digest": digest})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if !ok {
		WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"digest": digest})))
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", blen))
	w.Header().Set(DistContentDigestKey, digest)
	w.WriteHeader(http.StatusOK)
}

// GetBlob godoc
// @Summary Get image blob/layer
// @Description Get an image's blob/layer given a digest
// @Accept  json
// @Produce application/vnd.oci.image.layer.v1.tar+gzip
// @Param   name				path    string     true        "repository name"
// @Param   digest     	path    string     true        "blob/layer digest"
// @Header  200 {object} api.DistContentDigestKey
// @Success 200 {object} api.ImageManifest
// @Router /v2/{name}/blobs/{digest} [get].
func (rh *RouteHandler) GetBlob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	digest, ok := vars["digest"]
	if !ok || digest == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	mediaType := r.Header.Get("Accept")

	br, blen, err := is.GetBlob(name, digest, mediaType)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest})))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"digest": digest})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", blen))
	w.Header().Set(DistContentDigestKey, digest)
	// return the blob data
	WriteDataFromReader(w, http.StatusOK, blen, mediaType, br, rh.c.Log)
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
func (rh *RouteHandler) DeleteBlob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	digest, ok := vars["digest"]
	if !ok || digest == "" {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	is := rh.getImageStore(name)

	err := is.DeleteBlob(name, digest)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest})))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(BLOB_UNKNOWN, map[string]string{"digest": digest})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// CreateBlobUpload godoc
// @Summary Create image blob/layer upload
// @Description Create a new image blob/layer upload
// @Accept  json
// @Produce json
// @Param   name				path    string     true        "repository name"
// @Success 202 {string} string	"accepted"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{session_id}"
// @Header  202 {string} Range "bytes=0-0"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads [post].
func (rh *RouteHandler) CreateBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	// currently zot does not support cross-repository mounting, following dist-spec and returning 202
	if mountDigests, ok := r.URL.Query()["mount"]; ok {
		if len(mountDigests) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		from, ok := r.URL.Query()["from"]
		if !ok || len(from) != 1 {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// zot does not support cross mounting directly and do a workaround creating using hard link.
		// check blob looks for actual path (name+mountDigests[0]) first then look for cache and
		// if found in cache, will do hard link and if fails we will start new upload.
		_, _, err := is.CheckBlob(name, mountDigests[0])
		if err != nil {
			u, err := is.NewBlobUpload(name)
			if err != nil {
				switch err {
				case errors.ErrRepoNotFound:
					WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
				default:
					rh.c.Log.Error().Err(err).Msg("unexpected error")
					w.WriteHeader(http.StatusInternalServerError)
				}

				return
			}

			w.Header().Set("Location", path.Join(r.URL.String(), u))
			w.Header().Set("Range", "bytes=0-0")
			w.WriteHeader(http.StatusAccepted)

			return
		}

		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, mountDigests[0]))
		w.WriteHeader(http.StatusCreated)

		return
	}

	if _, ok := r.URL.Query()["from"]; ok {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// a full blob upload if "digest" is present
	digests, ok := r.URL.Query()["digest"]
	if ok {
		if len(digests) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		digest := digests[0]

		if contentType := r.Header.Get("Content-Type"); contentType != BinaryMediaType {
			rh.c.Log.Warn().Str("actual", contentType).Str("expected", BinaryMediaType).Msg("invalid media type")
			w.WriteHeader(http.StatusUnsupportedMediaType)

			return
		}

		rh.c.Log.Info().Int64("r.ContentLength", r.ContentLength).Msg("DEBUG")

		var contentLength int64

		var err error

		if contentLength, err = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64); err != nil || contentLength <= 0 {
			rh.c.Log.Warn().Str("actual", r.Header.Get("Content-Length")).Msg("invalid content length")
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"digest": digest})))

			return
		}

		sessionID, size, err := is.FullBlobUpload(name, r.Body, digest)
		if err != nil {
			rh.c.Log.Error().Err(err).Int64("actual", size).Int64("expected", contentLength).Msg("failed full upload")
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		if size != contentLength {
			rh.c.Log.Warn().Int64("actual", size).Int64("expected", contentLength).Msg("invalid content length")
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
		w.Header().Set(BlobUploadUUID, sessionID)
		w.WriteHeader(http.StatusCreated)

		return
	}

	u, err := is.NewBlobUpload(name)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", path.Join(r.URL.String(), u))
	w.Header().Set("Range", "bytes=0-0")
	w.WriteHeader(http.StatusAccepted)
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
// @Header  202 {string} Range "bytes=0-128"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [get].
func (rh *RouteHandler) GetBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	size, err := is.GetBlobUpload(name, sessionID)
	if err != nil {
		switch err {
		case errors.ErrBadUploadRange:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", path.Join(r.URL.String(), sessionID))
	w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", size-1))
	w.WriteHeader(http.StatusNoContent)
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
// @Header  202 {string} Range "bytes=0-128"
// @Header  200 {object} api.BlobUploadUUID
// @Failure 400 {string} string "bad request"
// @Failure 404 {string} string "not found"
// @Failure 416 {string} string "range not satisfiable"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [patch].
func (rh *RouteHandler) PatchBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var clen int64

	var err error

	if r.Header.Get("Content-Length") == "" || r.Header.Get("Content-Range") == "" {
		// streamed blob upload
		clen, err = is.PutBlobChunkStreamed(name, sessionID, r.Body)
	} else {
		// chunked blob upload

		var contentLength int64

		if contentLength, err = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64); err != nil {
			rh.c.Log.Warn().Str("actual", r.Header.Get("Content-Length")).Msg("invalid content length")
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		contentRange := r.Header.Get("Content-Range")
		if contentRange == "" {
			rh.c.Log.Warn().Str("actual", r.Header.Get("Content-Range")).Msg("invalid content range")
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return
		}

		var from, to int64
		if from, to, err = getContentRange(r); err != nil || (to-from)+1 != contentLength {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}

		clen, err = is.PutBlobChunk(name, sessionID, from, to, r.Body)
	}

	if err != nil {
		switch err {
		case errors.ErrBadUploadRange:
			WriteJSON(w, http.StatusRequestedRangeNotSatisfiable,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", r.URL.String())
	w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", clen-1))
	w.Header().Set("Content-Length", "0")
	w.Header().Set(BlobUploadUUID, sessionID)
	w.WriteHeader(http.StatusAccepted)
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
// @Header  200 {object} api.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{session_id} [put].
func (rh *RouteHandler) UpdateBlobUpload(w http.ResponseWriter, r *http.Request) {
	rh.c.Log.Info().Interface("headers", r.Header).Msg("HEADERS")
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	digests, ok := r.URL.Query()["digest"]
	if !ok || len(digests) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	digest := digests[0]

	rh.c.Log.Info().Int64("r.ContentLength", r.ContentLength).Msg("DEBUG")

	contentPresent := true

	contentLen, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		contentPresent = false
	}

	contentRangePresent := true

	if r.Header.Get("Content-Range") == "" {
		contentRangePresent = false
	}

	// we expect at least one of "Content-Length" or "Content-Range" to be
	// present
	if !contentPresent && !contentRangePresent {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var from, to int64

	if contentPresent {
		contentRange := r.Header.Get("Content-Range")
		if contentRange == "" { // monolithic upload
			from = 0

			if contentLen == 0 {
				goto finish // FIXME:
			}

			to = contentLen
		} else if from, to, err = getContentRange(r); err != nil { // finish chunked upload
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}

		_, err = is.PutBlobChunk(name, sessionID, from, to, r.Body)
		if err != nil {
			switch err {
			case errors.ErrBadUploadRange:
				WriteJSON(w, http.StatusBadRequest,
					NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
			case errors.ErrRepoNotFound:
				WriteJSON(w, http.StatusNotFound,
					NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
			case errors.ErrUploadNotFound:
				WriteJSON(w, http.StatusNotFound,
					NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
			default:
				rh.c.Log.Error().Err(err).Msg("unexpected error")
				w.WriteHeader(http.StatusInternalServerError)
			}

			return
		}
	}

finish:
	// blob chunks already transferred, just finish
	if err := is.FinishBlobUpload(name, sessionID, r.Body, digest); err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(DIGEST_INVALID, map[string]string{"digest": digest})))
		case errors.ErrBadUploadRange:
			WriteJSON(w, http.StatusBadRequest,
				NewErrorList(NewError(BLOB_UPLOAD_INVALID, map[string]string{"session_id": sessionID})))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.Header().Set("Content-Length", "0")
	w.Header().Set(DistContentDigestKey, digest)
	w.WriteHeader(http.StatusCreated)
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
func (rh *RouteHandler) DeleteBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	is := rh.getImageStore(name)

	sessionID, ok := vars["session_id"]
	if !ok || sessionID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := is.DeleteBlobUpload(name, sessionID); err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(NAME_UNKNOWN, map[string]string{"name": name})))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound,
				NewErrorList(NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"session_id": sessionID})))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.WriteHeader(http.StatusNoContent)
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
func (rh *RouteHandler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	combineRepoList := make([]string, 0)

	subStore := rh.c.StoreController.SubStore

	for _, imgStore := range subStore {
		repos, err := imgStore.GetRepositories()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		combineRepoList = append(combineRepoList, repos...)
	}

	singleStore := rh.c.StoreController.DefaultStore
	if singleStore != nil {
		repos, err := singleStore.GetRepositories()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		combineRepoList = append(combineRepoList, repos...)
	}

	var repos []string
	// get passed context from authzHandler and filter out repos based on permissions
	if authCtx := r.Context().Value(authzCtxKey); authCtx != nil {
		acCtx := authCtx.(AccessControlContext)
		for _, r := range combineRepoList {
			if containsRepo(acCtx.userAllowedRepos, r) || acCtx.isAdmin {
				repos = append(repos, r)
			}
		}
	} else {
		repos = combineRepoList
	}

	is := RepositoryList{Repositories: repos}

	WriteJSON(w, http.StatusOK, is)
}

func (rh *RouteHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	m := monitoring.GetMetrics()
	WriteJSON(w, http.StatusOK, m)
}

// helper routines

func getContentRange(r *http.Request) (int64 /* from */, int64 /* to */, error) {
	contentRange := r.Header.Get("Content-Range")
	tokens := strings.Split(contentRange, "-")

	from, err := strconv.ParseInt(tokens[0], 10, 64)
	if err != nil {
		return -1, -1, errors.ErrBadUploadRange
	}

	to, err := strconv.ParseInt(tokens[1], 10, 64)
	if err != nil {
		return -1, -1, errors.ErrBadUploadRange
	}

	if from > to {
		return -1, -1, errors.ErrBadUploadRange
	}

	return from, to, nil
}

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	WriteData(w, status, DefaultMediaType, body)
}

func WriteData(w http.ResponseWriter, status int, mediaType string, data []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func WriteDataFromReader(w http.ResponseWriter, status int, length int64, mediaType string,
	reader io.Reader, logger log.Logger) {
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(status)

	const maxSize = 10 * 1024 * 1024

	for {
		_, err := io.CopyN(w, reader, maxSize)
		if err == io.EOF {
			break
		} else if err != nil {
			// other kinds of intermittent errors can occur, e.g, io.ErrShortWrite
			logger.Error().Err(err).Msg("copying data into http response")
			return
		}
	}
}

// will return image storage corresponding to subpath provided in config.
func (rh *RouteHandler) getImageStore(name string) *storage.ImageStore {
	return rh.c.StoreController.GetImageStore(name)
}
