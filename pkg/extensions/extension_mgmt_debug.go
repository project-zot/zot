//go:build mgmt && debug
// +build mgmt,debug

package extensions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
)

type MgmtResponse struct {
	Auth config.AuthInfo `json:"auth"`
}

type mgmtHandler struct {
	config *config.Config
	log    log.Logger
}

func (mgmtHandler *mgmtHandler) getAuthInfo(response http.ResponseWriter, request *http.Request) {
	authInfo := mgmtHandler.config.GetAuthInfo()

	resp := MgmtResponse{Auth: authInfo}

	buf, err := json.Marshal(resp)
	if err != nil {
		mgmtHandler.log.Error().Err(err).Msg("mgmt auth query: couldn't marshal auth type response")
		response.WriteHeader(http.StatusInternalServerError)
	}

	_, _ = response.Write(buf)
}

func SetupMgmtRoutes(config *config.Config, router *mux.Router, log log.Logger) {
	if config.Extensions.Mgmt != nil && *config.Extensions.Mgmt.Enable {
		log.Info().Msg("setting up mgmt routes")

		handler := mgmtHandler{config: config, log: log}

		router.PathPrefix(constants.FullMgmtPrefix).Methods("GET").HandlerFunc(handler.getAuthInfo)
	}
}
