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
	"strconv"
	"strings"

	_ "github.com/anuvu/zot/docs" // nolint (golint) - as required by swaggo
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
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
	rh.c.Router.Use(BasicAuthHandler(rh.c))
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
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{uuid}", NameRegexp.String()),
			rh.GetBlobUpload).Methods("GET")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{uuid}", NameRegexp.String()),
			rh.PatchBlobUpload).Methods("PATCH")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{uuid}", NameRegexp.String()),
			rh.UpdateBlobUpload).Methods("PUT")
		g.HandleFunc(fmt.Sprintf("/{name:%s}/blobs/uploads/{uuid}", NameRegexp.String()),
			rh.DeleteBlobUpload).Methods("DELETE")
		g.HandleFunc("/_catalog",
			rh.ListRepositories).Methods("GET")
		g.HandleFunc("/",
			rh.CheckVersionSupport).Methods("GET")
	}
	// swagger docs "/swagger/v2/index.html"
	rh.c.Router.PathPrefix("/swagger/v2/").Methods("GET").Handler(httpSwagger.WrapHandler)
}

// Method handlers

// CheckVersionSupport godoc
// @Summary Check API support
// @Description Check if this API version is supported
// @Router 	/v2/ [get]
// @Accept  json
// @Produce json
// @Success 200 {string} string	"ok"
func (rh *RouteHandler) CheckVersionSupport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(DistAPIVersion, "registry/2.0")
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
// @Success 200 {object} 	api.ImageTags
// @Failure 404 {string} 	string 				"not found"
func (rh *RouteHandler) ListTags(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	tags, err := rh.c.ImageStore.GetImageTags(name)
	if err != nil {
		WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
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
// @Failure 500 {string} string "internal server error"
func (rh *RouteHandler) CheckManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		return
	}

	_, digest, _, err := rh.c.ImageStore.GetImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			WriteJSON(w, http.StatusInternalServerError, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		}

		return
	}

	w.Header().Set(DistContentDigestKey, digest)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

// NOTE: https://github.com/swaggo/swag/issues/387
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
// @Router /v2/{name}/manifests/{reference} [get]
func (rh *RouteHandler) GetManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		return
	}

	content, digest, mediaType, err := rh.c.ImageStore.GetImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrRepoBadVersion:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
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
// @Router /v2/{name}/manifests/{reference} [put]
func (rh *RouteHandler) UpdateManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		return
	}

	mediaType := r.Header.Get("Content-Type")
	if mediaType != ispec.MediaTypeImageManifest {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	digest, err := rh.c.ImageStore.PutImageManifest(name, reference, mediaType, body)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		case errors.ErrBadManifest:
			WriteJSON(w, http.StatusBadRequest, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusBadRequest, NewError(BLOB_UNKNOWN, map[string]string{"blob": digest}))
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
// @Router /v2/{name}/manifests/{reference} [delete]
func (rh *RouteHandler) DeleteManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	reference, ok := vars["reference"]
	if !ok || reference == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	err := rh.c.ImageStore.DeleteImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrManifestNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.WriteHeader(http.StatusOK)
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
// @Router /v2/{name}/blobs/{digest} [head]
func (rh *RouteHandler) CheckBlob(w http.ResponseWriter, r *http.Request) {
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

	mediaType := r.Header.Get("Accept")

	ok, blen, err := rh.c.ImageStore.CheckBlob(name, digest, mediaType)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	if !ok {
		WriteJSON(w, http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
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
// @Router /v2/{name}/blobs/{digest} [get]
func (rh *RouteHandler) GetBlob(w http.ResponseWriter, r *http.Request) {
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

	mediaType := r.Header.Get("Accept")

	br, blen, err := rh.c.ImageStore.GetBlob(name, digest, mediaType)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
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
// @Router /v2/{name}/blobs/{digest} [delete]
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

	err := rh.c.ImageStore.DeleteBlob(name, digest)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrBlobNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
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
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{uuid}"
// @Header  202 {string} Range "bytes=0-0"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads [post]
func (rh *RouteHandler) CreateBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// blob mounts not allowed since we don't have access control yet, and this
	// may be a uncommon use case, but remain compliant
	if _, ok := r.URL.Query()["mount"]; ok {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if _, ok := r.URL.Query()["from"]; ok {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	u, err := rh.c.ImageStore.NewBlobUpload(name)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
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
// @Description Get an image's blob/layer upload given a uuid
// @Accept  json
// @Produce json
// @Param   name     path    string     true        "repository name"
// @Param   uuid     path    string     true        "upload uuid"
// @Success 204 {string} string "no content"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{uuid}"
// @Header  202 {string} Range "bytes=0-128"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{uuid} [get]
func (rh *RouteHandler) GetBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	uuid, ok := vars["uuid"]
	if !ok || uuid == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	size, err := rh.c.ImageStore.GetBlobUpload(name, uuid)
	if err != nil {
		switch err {
		case errors.ErrBadUploadRange:
			WriteJSON(w, http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", path.Join(r.URL.String(), uuid))
	w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", size))
	w.WriteHeader(http.StatusNoContent)
}

// PatchBlobUpload godoc
// @Summary Resume image blob/layer upload
// @Description Resume an image's blob/layer upload given an uuid
// @Accept  json
// @Produce json
// @Param   name     path    string     true        "repository name"
// @Param   uuid     path    string     true        "upload uuid"
// @Success 202 {string} string	"accepted"
// @Header  202 {string} Location "/v2/{name}/blobs/uploads/{uuid}"
// @Header  202 {string} Range "bytes=0-128"
// @Header  200 {object} api.BlobUploadUUID
// @Failure 400 {string} string "bad request"
// @Failure 404 {string} string "not found"
// @Failure 416 {string} string "range not satisfiable"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{uuid} [patch]
func (rh *RouteHandler) PatchBlobUpload(w http.ResponseWriter, r *http.Request) {
	rh.c.Log.Info().Interface("headers", r.Header).Msg("request headers")
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	uuid, ok := vars["uuid"]
	if !ok || uuid == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var err error

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
	if from, to, err = getContentRange(r); err != nil || (to-from) != contentLength {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	if contentType := r.Header.Get("Content-Type"); contentType != "application/octet-stream" {
		rh.c.Log.Warn().Str("actual", contentType).Str("expected", "application/octet-stream").Msg("invalid media type")
		w.WriteHeader(http.StatusUnsupportedMediaType)

		return
	}

	clen, err := rh.c.ImageStore.PutBlobChunk(name, uuid, from, to, r.Body)
	if err != nil {
		switch err {
		case errors.ErrBadUploadRange:
			WriteJSON(w, http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
		default:
			rh.c.Log.Error().Err(err).Msg("unexpected error")
			w.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	w.Header().Set("Location", path.Join(r.URL.String(), uuid))
	w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", clen))
	w.Header().Set("Content-Length", "0")
	w.Header().Set(BlobUploadUUID, uuid)
	w.WriteHeader(http.StatusAccepted)
}

// UpdateBlobUpload godoc
// @Summary Update image blob/layer upload
// @Description Update and finish an image's blob/layer upload given a digest
// @Accept  json
// @Produce json
// @Param   name     path    string     true        "repository name"
// @Param   uuid     path    string     true        "upload uuid"
// @Param 	digest	 query 	 string 		true				"blob/layer digest"
// @Success 201 {string} string	"created"
// @Header  202 {string} Location "/v2/{name}/blobs/{digest}"
// @Header  200 {object} api.DistContentDigestKey
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{uuid} [put]
func (rh *RouteHandler) UpdateBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	uuid, ok := vars["uuid"]
	if !ok || uuid == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	digests, ok := r.URL.Query()["digest"]
	if !ok || len(digests) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	digest := digests[0]

	contentPresent := true
	contentLen, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)

	if err != nil || contentLen == 0 {
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
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}

		contentRange := r.Header.Get("Content-Range")
		if contentRange == "" { // monolithic upload
			from = 0

			if contentLen == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			to = contentLen
		} else if from, to, err = getContentRange(r); err != nil { // finish chunked upload
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}

		_, err = rh.c.ImageStore.PutBlobChunk(name, uuid, from, to, r.Body)
		if err != nil {
			switch err {
			case errors.ErrBadUploadRange:
				WriteJSON(w, http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
			case errors.ErrRepoNotFound:
				WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
			case errors.ErrUploadNotFound:
				WriteJSON(w, http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
			default:
				rh.c.Log.Error().Err(err).Msg("unexpected error")
				w.WriteHeader(http.StatusInternalServerError)
			}

			return
		}
	}

	// blob chunks already transferred, just finish
	if err := rh.c.ImageStore.FinishBlobUpload(name, uuid, r.Body, digest); err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			WriteJSON(w, http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrBadUploadRange:
			WriteJSON(w, http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
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
// @Param   uuid     path    string     true        "upload uuid"
// @Success 200 {string} string "ok"
// @Failure 404 {string} string "not found"
// @Failure 500 {string} string "internal server error"
// @Router /v2/{name}/blobs/uploads/{uuid} [delete]
func (rh *RouteHandler) DeleteBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, ok := vars["name"]

	if !ok || name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	uuid, ok := vars["uuid"]
	if !ok || uuid == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := rh.c.ImageStore.DeleteBlobUpload(name, uuid); err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			WriteJSON(w, http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
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
// @Router /v2/_catalog [get]
func (rh *RouteHandler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	repos, err := rh.c.ImageStore.GetRepositories()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	is := RepositoryList{Repositories: repos}

	WriteJSON(w, http.StatusOK, is)
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
		w.WriteHeader(http.StatusInternalServerError)
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
			logger.Panic().Err(err).Msg("copying data into http response")
		}
	}
}
