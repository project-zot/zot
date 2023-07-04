//go:build imagetrust
// +build imagetrust

package extensions

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/signatures"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
)

func IsBuiltWithImageTrustExtension() bool {
	return true
}

func SetupImageTrustRoutes(conf *config.Config, metaDB mTypes.MetaDB, router *mux.Router, log log.Logger) {
	if !conf.IsImageTrustEnabled() || (!conf.IsCosignEnabled() && !conf.IsNotationEnabled()) {
		log.Info().Msg("skip enabling the image trust routes as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up image trust routes")

	sigStore, _ := metaDB.SignatureStorage().(*signatures.SigStore)
	trust := ImageTrust{Conf: conf, SigStore: sigStore, Log: log}
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
	Conf     *config.Config
	SigStore *signatures.SigStore
	Log      log.Logger
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
		trust.Log.Error().Err(err).Msg("image trust: couldn't read cosign key body")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = signatures.UploadPublicKey(trust.SigStore.CosignStorage, body)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidPublicKeyContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			trust.Log.Error().Err(err).Msg("image trust: failed to save cosign key")
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
// @Param   truststoreName  query    string   false  "truststore name"
// @Param   requestBody     body     string   true   "Certificate content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request".
// @Failure 500 {string}   string    "internal server error".
func (trust *ImageTrust) HandleNotationCertificateUpload(response http.ResponseWriter, request *http.Request) {
	var truststoreType string

	if !zcommon.QueryHasParams(request.URL.Query(), []string{"truststoreName"}) {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	if zcommon.QueryHasParams(request.URL.Query(), []string{"truststoreType"}) {
		truststoreType = request.URL.Query().Get("truststoreType")
	} else {
		truststoreType = "ca" // default value of "truststoreType" query param
	}

	truststoreName := request.URL.Query().Get("truststoreName")

	if truststoreType == "" || truststoreName == "" {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		trust.Log.Error().Err(err).Msg("image trust: couldn't read notation certificate body")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = signatures.UploadCertificate(trust.SigStore.NotationStorage, body, truststoreType, truststoreName)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidTruststoreType) ||
			errors.Is(err, zerr.ErrInvalidTruststoreName) ||
			errors.Is(err, zerr.ErrInvalidCertificateContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			trust.Log.Error().Err(err).Msg("image trust: failed to save notation certificate")
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

	generator := signatures.NewTaskGenerator(metaDB, log)

	numberOfHours := 2
	interval := time.Duration(numberOfHours) * time.Hour
	taskScheduler.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}
