package sync

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/anuvu/zot/pkg/log"
)

type PostHandler struct {
	Address    string
	Port       string
	ServerCert string
	ServerKey  string
	CACert     string
	Cfg        Config
	Log        log.Logger
}

func (h *PostHandler) Handler(w http.ResponseWriter, r *http.Request) {
	upstreamCtx, policyCtx, err := getLocalContexts(h.ServerCert, h.ServerKey, h.CACert, h.Log)
	if err != nil {
		WriteData(w, http.StatusInternalServerError, err.Error())

		return
	}

	defer policyCtx.Destroy() //nolint: errcheck

	var credentialsFile CredentialsFile

	if h.Cfg.CredentialsFile != "" {
		credentialsFile, err = getFileCredentials(h.Cfg.CredentialsFile)
		if err != nil {
			h.Log.Error().Err(err).Msgf("couldn't get registry credentials from %s", h.Cfg.CredentialsFile)
			WriteData(w, http.StatusInternalServerError, err.Error())
		}
	}

	localRegistryName := strings.Replace(fmt.Sprintf("%s:%s", h.Address, h.Port), "0.0.0.0", "127.0.0.1", 1)

	for _, regCfg := range h.Cfg.Registries {
		upstreamRegistryName := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

		if err := syncRegistry(regCfg, h.Log, localRegistryName, upstreamCtx, policyCtx,
			credentialsFile[upstreamRegistryName]); err != nil {
			h.Log.Err(err).Msg("error while syncing")
			WriteData(w, http.StatusInternalServerError, err.Error())
		}
	}

	WriteData(w, http.StatusOK, "")
}

func WriteData(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
