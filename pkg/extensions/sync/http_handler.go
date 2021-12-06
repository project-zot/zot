package sync

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	guuid "github.com/gofrs/uuid"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type PostHandler struct {
	StoreController storage.StoreController
	Cfg             Config
	Log             log.Logger
}

func (h *PostHandler) Handler(w http.ResponseWriter, r *http.Request) {
	var credentialsFile CredentialsFile

	var err error

	if h.Cfg.CredentialsFile != "" {
		credentialsFile, err = getFileCredentials(h.Cfg.CredentialsFile)
		if err != nil {
			h.Log.Error().Err(err).Msgf("sync http handler: couldn't get registry credentials from %s", h.Cfg.CredentialsFile)
			WriteData(w, http.StatusInternalServerError, err.Error())

			return
		}
	}

	localCtx, policyCtx, err := getLocalContexts(h.Log)
	if err != nil {
		WriteData(w, http.StatusInternalServerError, err.Error())

		return
	}

	defer policyCtx.Destroy() //nolint: errcheck

	uuid, err := guuid.NewV4()
	if err != nil {
		WriteData(w, http.StatusInternalServerError, err.Error())

		return
	}

	for _, regCfg := range h.Cfg.Registries {
		if len(regCfg.Content) == 0 {
			h.Log.Info().Msgf("no content found for %s, will not run periodically sync", regCfg.URL)
			continue
		}

		upstreamRegistryName := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

		if err := syncRegistry(context.Background(), regCfg, h.StoreController, h.Log, localCtx, policyCtx,
			credentialsFile[upstreamRegistryName], uuid.String()); err != nil {
			h.Log.Err(err).Msg("sync http handler: error while syncing in")
			WriteData(w, http.StatusInternalServerError, err.Error())

			return
		}
	}

	WriteData(w, http.StatusOK, "")
}

func WriteData(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf("error: %s", msg)))
}
