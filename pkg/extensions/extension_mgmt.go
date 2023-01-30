//go:build mgmt && !debug
// +build mgmt,!debug

package extensions

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
)

var ErrInvalidIP = errors.New("invalid ip")

type MgmtResponse struct {
	Auth    config.AuthInfo `json:"auth"`
	Version string          `json:"serverVersion"`
}

type mgmtHandler struct {
	config *config.Config
	log    log.Logger
}

func (mgmtHandler *mgmtHandler) getAuthInfo(response http.ResponseWriter, request *http.Request) {
	remoteAddr, err := getIP(request)
	if err != nil {
		mgmtHandler.log.Error().Err(err).Msg("mgmt auth query: couldn't obtain request ip")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	if !strings.Contains(remoteAddr, "127.0.0.1") {
		mgmtHandler.log.Error().Msg("mgmt auth query: only local requests are allowed")
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	authInfo := mgmtHandler.config.GetAuthInfo()
	version := config.Commit

	resp := MgmtResponse{Auth: authInfo, Version: version}

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

func getIP(request *http.Request) (string, error) {
	// Get IP from the X-REAL-IP header
	ip := request.Header.Get("X-REAL-IP") //nolint: varnamelen

	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	// Get IP from X-FORWARDED-FOR header from the right to left (to get proxy added address)
	ips := request.Header.Get("X-FORWARDED-FOR")

	splitIps := strings.Split(ips, ",")
	for i := len(splitIps) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(splitIps[i])

		// header can contain spaces too, strip those out.
		netIP = net.ParseIP(ip)
		if netIP != nil {
			return ip, nil
		}
	}

	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "", err
	}

	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	return "", ErrInvalidIP
}
