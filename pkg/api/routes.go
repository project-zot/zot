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
	"net/http"
	"path"
	"strconv"
	"strings"

	_ "github.com/anuvu/zot/docs" // nolint (golint) - as required by swaggo
	"github.com/anuvu/zot/errors"
	"github.com/gin-gonic/gin"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/swaggo/gin-swagger/swaggerFiles"
)

const RoutePrefix = "/v2"
const DistContentDigestKey = "Docker-Content-Digest"
const BlobUploadUUID = "Blob-Upload-UUID"

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
	g := rh.c.Router.Group(RoutePrefix)
	{
		g.GET("/", rh.CheckVersionSupport)
		g.GET("/:name/tags/list", rh.ListTags)
		g.HEAD("/:name/manifests/:reference", rh.CheckManifest)
		g.GET("/:name/manifests/:reference", rh.GetManifest)
		g.PUT("/:name/manifests/:reference", rh.UpdateManifest)
		g.DELETE("/:name/manifests/:reference", rh.DeleteManifest)
		g.HEAD("/:name/blobs/:digest", rh.CheckBlob)
		g.GET("/:name/blobs/:digest", rh.GetBlob)
		g.DELETE("/:name/blobs/:digest", rh.DeleteBlob)

		// NOTE: some routes as per the spec need to be setup with URL params which
		// must equal specific keywords

		// route for POST "/v2/:name/blobs/uploads/" and param ":digest"="uploads"
		g.POST("/:name/blobs/:digest/", rh.CreateBlobUpload)
		// route for GET "/v2/:name/blobs/uploads/:uuid" and param ":digest"="uploads"
		g.GET("/:name/blobs/:digest/:uuid", rh.GetBlobUpload)
		// route for PATCH "/v2/:name/blobs/uploads/:uuid" and param ":digest"="uploads"
		g.PATCH("/:name/blobs/:digest/:uuid", rh.PatchBlobUpload)
		// route for PUT "/v2/:name/blobs/uploads/:uuid" and param ":digest"="uploads"
		g.PUT("/:name/blobs/:digest/:uuid", rh.UpdateBlobUpload)
		// route for DELETE "/v2/:name/blobs/uploads/:uuid" and param ":digest"="uploads"
		g.DELETE("/:name/blobs/:digest/:uuid", rh.DeleteBlobUpload)
		// route for GET "/v2/_catalog" and param ":name"="_catalog"
		g.GET("/:name", rh.ListRepositories)
	}
	// swagger docs "/swagger/v2/index.html"
	rh.c.Router.GET("/swagger/v2/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}

// Method handlers

// CheckVersionSupport godoc
// @Summary Check API support
// @Description Check if this API version is supported
// @Router 	/v2/ [get]
// @Accept  json
// @Produce json
// @Success 200 {string} string	"ok"
func (rh *RouteHandler) CheckVersionSupport(ginCtx *gin.Context) {
	ginCtx.Data(http.StatusOK, "application/json; charset=utf-8", []byte{})
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
func (rh *RouteHandler) ListTags(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	tags, err := rh.c.ImageStore.GetImageTags(name)
	if err != nil {
		ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		return
	}

	ginCtx.JSON(http.StatusOK, ImageTags{Name: name, Tags: tags})
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
func (rh *RouteHandler) CheckManifest(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	reference := ginCtx.Param("reference")
	if reference == "" {
		ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		return
	}

	_, digest, _, err := rh.c.ImageStore.GetImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrManifestNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		default:
			ginCtx.JSON(http.StatusInternalServerError, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		}
		return
	}

	ginCtx.Status(http.StatusOK)
	ginCtx.Header(DistContentDigestKey, digest)
	ginCtx.Header("Content-Length", "0")
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
func (rh *RouteHandler) GetManifest(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	reference := ginCtx.Param("reference")
	if reference == "" {
		ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		return
	}

	content, digest, mediaType, err := rh.c.ImageStore.GetImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
		case errors.ErrRepoBadVersion:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrManifestNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Data(http.StatusOK, mediaType, content)
	ginCtx.Header(DistContentDigestKey, digest)
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
func (rh *RouteHandler) UpdateManifest(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	reference := ginCtx.Param("reference")
	if reference == "" {
		ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		return
	}

	mediaType := ginCtx.ContentType()
	if mediaType != ispec.MediaTypeImageManifest {
		ginCtx.Status(http.StatusUnsupportedMediaType)
		return
	}

	body, err := ginCtx.GetRawData()
	if err != nil {
		ginCtx.Status(http.StatusInternalServerError)
		return
	}

	digest, err := rh.c.ImageStore.PutImageManifest(name, reference, mediaType, body)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrManifestNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		case errors.ErrBadManifest:
			ginCtx.JSON(http.StatusBadRequest, NewError(MANIFEST_INVALID, map[string]string{"reference": reference}))
		case errors.ErrBlobNotFound:
			ginCtx.JSON(http.StatusBadRequest, NewError(BLOB_UNKNOWN, map[string]string{"blob": digest}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusCreated)
	ginCtx.Header("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))
	ginCtx.Header(DistContentDigestKey, digest)
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
func (rh *RouteHandler) DeleteManifest(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	reference := ginCtx.Param("reference")
	if reference == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	err := rh.c.ImageStore.DeleteImageManifest(name, reference)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrManifestNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(MANIFEST_UNKNOWN, map[string]string{"reference": reference}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusOK)
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
func (rh *RouteHandler) CheckBlob(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	digest := ginCtx.Param("digest")
	if digest == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	mediaType := ginCtx.Request.Header.Get("Accept")

	ok, blen, err := rh.c.ImageStore.CheckBlob(name, digest, mediaType)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			ginCtx.JSON(http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrBlobNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	if !ok {
		ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
		return
	}

	ginCtx.Status(http.StatusOK)
	ginCtx.Header("Content-Length", fmt.Sprintf("%d", blen))
	ginCtx.Header(DistContentDigestKey, digest)
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
func (rh *RouteHandler) GetBlob(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	digest := ginCtx.Param("digest")
	if digest == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	mediaType := ginCtx.Request.Header.Get("Accept")

	br, blen, err := rh.c.ImageStore.GetBlob(name, digest, mediaType)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			ginCtx.JSON(http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrBlobNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusOK)
	ginCtx.Header("Content-Length", fmt.Sprintf("%d", blen))
	ginCtx.Header(DistContentDigestKey, digest)
	// return the blob data
	ginCtx.DataFromReader(http.StatusOK, blen, mediaType, br, map[string]string{})
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
func (rh *RouteHandler) DeleteBlob(ginCtx *gin.Context) {
	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	digest := ginCtx.Param("digest")
	if digest == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	err := rh.c.ImageStore.DeleteBlob(name, digest)
	if err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			ginCtx.JSON(http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrBlobNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UNKNOWN, map[string]string{"digest": digest}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusAccepted)
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
func (rh *RouteHandler) CreateBlobUpload(ginCtx *gin.Context) {
	if paramIsNot(ginCtx, "digest", "uploads") {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	u, err := rh.c.ImageStore.NewBlobUpload(name)
	if err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusAccepted)
	ginCtx.Header("Location", path.Join(ginCtx.Request.URL.String(), u))
	ginCtx.Header("Range", "bytes=0-0")
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
func (rh *RouteHandler) GetBlobUpload(ginCtx *gin.Context) {
	if paramIsNot(ginCtx, "digest", "uploads") {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	uuid := ginCtx.Param("uuid")
	if uuid == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	size, err := rh.c.ImageStore.GetBlobUpload(name, uuid)
	if err != nil {
		switch err {
		case errors.ErrBadUploadRange:
		case errors.ErrBadBlobDigest:
			ginCtx.JSON(http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusNoContent)
	ginCtx.Header("Location", path.Join(ginCtx.Request.URL.String(), uuid))
	ginCtx.Header("Range", fmt.Sprintf("bytes=0-%d", size))
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
func (rh *RouteHandler) PatchBlobUpload(ginCtx *gin.Context) {

	rh.c.Log.Info().Interface("headers", ginCtx.Request.Header).Msg("request headers")
	if paramIsNot(ginCtx, "digest", "uploads") {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}
	uuid := ginCtx.Param("uuid")
	if uuid == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	var err error
	var contentLength int64
	if contentLength, err = strconv.ParseInt(ginCtx.Request.Header.Get("Content-Length"), 10, 64); err != nil {
		rh.c.Log.Warn().Str("actual", ginCtx.Request.Header.Get("Content-Length")).Msg("invalid content length")
		ginCtx.Status(http.StatusBadRequest)
		return
	}

	contentRange := ginCtx.Request.Header.Get("Content-Range")
	if contentRange == "" {
		rh.c.Log.Warn().Str("actual", ginCtx.Request.Header.Get("Content-Range")).Msg("invalid content range")
		ginCtx.Status(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	var from, to int64
	if from, to, err = getContentRange(ginCtx); err != nil || (to-from) != contentLength {
		ginCtx.Status(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	if ginCtx.ContentType() != "application/octet-stream" {
		rh.c.Log.Warn().Str("actual", ginCtx.ContentType()).Msg("invalid media type")
		ginCtx.Status(http.StatusUnsupportedMediaType)
		return
	}

	clen, err := rh.c.ImageStore.PutBlobChunk(name, uuid, from, to, ginCtx.Request.Body)
	if err != nil {
		switch err {
		case errors.ErrBadUploadRange:
			ginCtx.JSON(http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusAccepted)
	ginCtx.Header("Location", path.Join(ginCtx.Request.URL.String(), uuid))
	ginCtx.Header("Range", fmt.Sprintf("bytes=0-%d", clen))
	ginCtx.Header("Content-Length", "0")
	ginCtx.Header(BlobUploadUUID, uuid)
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
func (rh *RouteHandler) UpdateBlobUpload(ginCtx *gin.Context) {
	if paramIsNot(ginCtx, "digest", "uploads") {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	name := ginCtx.Param("name")
	if name == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	uuid := ginCtx.Param("uuid")
	if uuid == "" {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	digest := ginCtx.Query("digest")
	if digest == "" {
		ginCtx.Status(http.StatusBadRequest)
		return
	}

	contentPresent := true
	contentLen, err := strconv.ParseInt(ginCtx.Request.Header.Get("Content-Length"), 10, 64)
	if err != nil || contentLen == 0 {
		contentPresent = false
	}
	contentRangePresent := true
	if ginCtx.Request.Header.Get("Content-Range") == "" {
		contentRangePresent = false
	}

	// we expect at least one of "Content-Length" or "Content-Range" to be
	// present
	if !contentPresent && !contentRangePresent {
		ginCtx.Status(http.StatusBadRequest)
		return
	}

	var from, to int64

	if contentPresent {
		if ginCtx.ContentType() != "application/octet-stream" {
			ginCtx.Status(http.StatusUnsupportedMediaType)
			return
		}

		contentRange := ginCtx.Request.Header.Get("Content-Range")
		if contentRange == "" { // monolithic upload
			from = 0
			if contentLen == 0 {
				ginCtx.Status(http.StatusBadRequest)
				return
			}
			to = contentLen
		} else if from, to, err = getContentRange(ginCtx); err != nil { // finish chunked upload
			ginCtx.Status(http.StatusRequestedRangeNotSatisfiable)
			return
		}

		_, err = rh.c.ImageStore.PutBlobChunk(name, uuid, from, to, ginCtx.Request.Body)
		if err != nil {
			switch err {
			case errors.ErrBadUploadRange:
				ginCtx.JSON(http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
			case errors.ErrRepoNotFound:
				ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
			case errors.ErrUploadNotFound:
				ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
			default:
				ginCtx.Status(http.StatusInternalServerError)
			}
			return
		}
	}

	// blob chunks already transferred, just finish
	if err := rh.c.ImageStore.FinishBlobUpload(name, uuid, ginCtx.Request.Body, digest); err != nil {
		switch err {
		case errors.ErrBadBlobDigest:
			ginCtx.JSON(http.StatusBadRequest, NewError(DIGEST_INVALID, map[string]string{"digest": digest}))
		case errors.ErrBadUploadRange:
			ginCtx.JSON(http.StatusBadRequest, NewError(BLOB_UPLOAD_INVALID, map[string]string{"uuid": uuid}))
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusCreated)
	ginCtx.Header("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	ginCtx.Header("Content-Length", "0")
	ginCtx.Header(DistContentDigestKey, digest)
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
func (rh *RouteHandler) DeleteBlobUpload(ginCtx *gin.Context) {
	if paramIsNot(ginCtx, "digest", "uploads") {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	name := ginCtx.Param("name")
	uuid := ginCtx.Param("uuid")

	if err := rh.c.ImageStore.DeleteBlobUpload(name, uuid); err != nil {
		switch err {
		case errors.ErrRepoNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(NAME_UNKNOWN, map[string]string{"name": name}))
		case errors.ErrUploadNotFound:
			ginCtx.JSON(http.StatusNotFound, NewError(BLOB_UPLOAD_UNKNOWN, map[string]string{"uuid": uuid}))
		default:
			ginCtx.Status(http.StatusInternalServerError)
		}
		return
	}

	ginCtx.Status(http.StatusOK)
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
func (rh *RouteHandler) ListRepositories(ginCtx *gin.Context) {
	if paramIsNot(ginCtx, "name", "_catalog") {
		ginCtx.Status(http.StatusNotFound)
		return
	}

	repos, err := rh.c.ImageStore.GetRepositories()
	if err != nil {
		ginCtx.Status(http.StatusInternalServerError)
		return
	}

	is := RepositoryList{Repositories: repos}

	ginCtx.JSON(http.StatusOK, is)
}

// helper routines

func paramIsNot(ginCtx *gin.Context, name string, expected string) bool {
	actual := ginCtx.Param(name)
	return actual != expected
}

func getContentRange(ginCtx *gin.Context) (int64 /* from */, int64 /* to */, error) {
	contentRange := ginCtx.Request.Header.Get("Content-Range")
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
