//go:build imagetrust
// +build imagetrust

package extensions

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/imagetrust"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
)

func IsBuiltWithImageTrustExtension() bool {
	return true
}

func SetupImageTrustRoutes(conf *config.Config, router *mux.Router, metaDB mTypes.MetaDB, log log.Logger) {
	if !conf.IsImageTrustEnabled() || (!conf.IsCosignEnabled() && !conf.IsNotationEnabled()) {
		log.Info().Msg("skip enabling the image trust routes as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up image trust routes")

	imgTrustStore, _ := metaDB.ImageTrustStore().(*imagetrust.ImageTrustStore)
	trust := ImageTrust{Conf: conf, ImageTrustStore: imgTrustStore, Log: log}
	allowedMethods := zcommon.AllowedMethods(http.MethodPost)

	if conf.IsNotationEnabled() {
		log.Info().Msg("setting up notation route")

		notationRouter := router.PathPrefix(constants.ExtNotation).Subrouter()
		notationRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
		notationRouter.Use(zcommon.AddExtensionSecurityHeaders())
		notationRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
		// The endpoints for uploading signatures should be available only to admins
		notationRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
		notationRouter.Methods(allowedMethods...).HandlerFunc(trust.HandleNotationCertificateUpload)
	}

	if conf.IsCosignEnabled() {
		log.Info().Msg("setting up cosign route")

		cosignRouter := router.PathPrefix(constants.ExtCosign).Subrouter()
		cosignRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
		cosignRouter.Use(zcommon.AddExtensionSecurityHeaders())
		cosignRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
		// The endpoints for uploading signatures should be available only to admins
		cosignRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
		cosignRouter.Methods(allowedMethods...).HandlerFunc(trust.HandleCosignPublicKeyUpload)
	}

	log.Info().Msg("finished setting up image trust routes")
}

type ImageTrust struct {
	Conf            *config.Config
	ImageTrustStore *imagetrust.ImageTrustStore
	Log             log.Logger
}

// Cosign handler godoc
// @Summary Upload cosign public keys for verifying signatures
// @Description Upload cosign public keys for verifying signatures
// @Router   /v2/_zot/ext/cosign [post]
// @Accept  octet-stream
// @Produce json
// @Param   requestBody     body     string   true   "Public key content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request".
// @Failure 500 {string}   string    "internal server error".
func (trust *ImageTrust) HandleCosignPublicKeyUpload(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to read cosign key body")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = imagetrust.UploadPublicKey(trust.ImageTrustStore.CosignStorage, body)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidPublicKeyContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to save cosign key")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusOK)
}

// Notation handler godoc
// @Summary Upload notation certificates for verifying signatures
// @Description Upload notation certificates for verifying signatures
// @Router  /v2/_zot/ext/notation [post]
// @Accept  octet-stream
// @Produce json
// @Param   truststoreType  query    string   false  "truststore type"
// @Param   requestBody     body     string   true   "Certificate content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request".
// @Failure 500 {string}   string    "internal server error".
func (trust *ImageTrust) HandleNotationCertificateUpload(response http.ResponseWriter, request *http.Request) {
	var truststoreType string

	if zcommon.QueryHasParams(request.URL.Query(), []string{"truststoreType"}) {
		truststoreType = request.URL.Query().Get("truststoreType")
	} else {
		truststoreType = "ca" // default value of "truststoreType" query param
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to read notation certificate body")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = imagetrust.UploadCertificate(trust.ImageTrustStore.NotationStorage, body, truststoreType)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidTruststoreType) ||
			errors.Is(err, zerr.ErrInvalidCertificateContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to save notation certificate")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusOK)
}

func EnableImageTrustVerification(conf *config.Config, taskScheduler *scheduler.Scheduler,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	if !conf.IsImageTrustEnabled() {
		return
	}

	generator := imagetrust.NewTaskGenerator(metaDB, log)

	numberOfHours := 2
	interval := time.Duration(numberOfHours) * time.Hour
	taskScheduler.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

func SetupImageTrustExtension(conf *config.Config, metaDB mTypes.MetaDB, log log.Logger) error {
	if !conf.IsImageTrustEnabled() {
		return nil
	}

	var imgTrustStore mTypes.ImageTrustStore

	var err error

	if conf.Storage.RemoteCache {
		endpoint, _ := conf.Storage.CacheDriver["endpoint"].(string)
		region, _ := conf.Storage.CacheDriver["region"].(string)
		imgTrustStore, err = imagetrust.NewAWSImageTrustStore(region, endpoint)

		if err != nil {
			return err
		}
	} else {
		imgTrustStore, err = imagetrust.NewLocalImageTrustStore(conf.Storage.RootDirectory)
		if err != nil {
			return err
		}
	}

	metaDB.SetImageTrustStore(imgTrustStore)

	return nil
}
