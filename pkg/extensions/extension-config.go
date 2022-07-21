//go:build config
// +build config

package extensions

import (
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type ConfigHandler struct {
	configPath string
	lock       *sync.RWMutex
	log        log.Logger
}

func NewConfigHandler(configPath string, log log.Logger) ConfigHandler {
	return ConfigHandler{
		configPath: configPath,
		lock:       &sync.RWMutex{},
		log:        log,
	}
}

func (handler *ConfigHandler) Handler(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		handler.log.Info().Msg("config ext: GET request")
		handler.lock.RLock()
		defer handler.lock.RUnlock()

		config, err := os.ReadFile(handler.configPath)
		if err != nil {
			handler.log.Error().Err(err).Msg("config ext: couldn't read config file")
			response.WriteHeader(http.StatusInternalServerError)

			return
		}

		_, _ = response.Write(config)

		return
	case http.MethodPost:
		handler.log.Info().Msg("config ext: POST request")
		handler.lock.Lock()
		defer handler.lock.Unlock()

		cfg := &config.Config{}

		writeConfig, err := config.LoadFromBufferWithWriter(handler.configPath, request.Body, cfg)
		if err != nil {
			handler.log.Error().Err(err).Msg("config ext: invalid config")
			http.Error(response, "Invalid config", http.StatusBadRequest)

			return
		}

		if err := writeConfig(); err != nil {
			handler.log.Error().Err(err).Msg("config ext: couldn't write config")
			http.Error(response, "Invalid config", http.StatusInternalServerError)

			return
		}

		response.WriteHeader(http.StatusAccepted)
	}
}

func SetupConfigRoutes(config *config.Config, configPath string, router *mux.Router,
	storeController storage.StoreController, l log.Logger,
) {
	if config.Extensions.SysConfig != nil && *config.Extensions.SysConfig.Enable {
		log := log.Logger{Logger: l.With().Caller().Timestamp().Logger()}
		log.Info().Msg("setting up extensions routes")

		handler := NewConfigHandler(configPath, log)

		router.PathPrefix(constants.ExtConfigPrefix).Methods("GET", "POST").HandlerFunc(handler.Handler)
	}
}
