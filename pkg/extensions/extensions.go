// +build extended

package extensions

import (
	"github.com/anuvu/zot/pkg/api/config"
	"github.com/anuvu/zot/pkg/extensions/search"
	"github.com/anuvu/zot/pkg/extensions/sync"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"

	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"

	"github.com/anuvu/zot/pkg/log"
)

// DownloadTrivyDB ...
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	for {
		log.Info().Msg("updating the CVE database")

		err := cveinfo.UpdateCVEDb(dbDir, log)
		if err != nil {
			return err
		}

		log.Info().Str("DB update completed, next update scheduled after", updateInterval.String()).Msg("")

		time.Sleep(updateInterval)
	}
}

func EnableExtensions(config *config.Config, log log.Logger, rootDir string) {
	if config.Extensions.Search != nil && config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
			config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval <= 1, changing update duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			err := downloadTrivyDB(rootDir, log,
				config.Extensions.Search.CVE.UpdateInterval)
			if err != nil {
				log.Error().Err(err).Msg("error while downloading TrivyDB")
			}
		}()
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}

	if config.Extensions.Sync != nil {
		defaultPollInterval, _ := time.ParseDuration("1h")
		for id, registryCfg := range config.Extensions.Sync.Registries {
			if registryCfg.PollInterval < defaultPollInterval {
				config.Extensions.Sync.Registries[id].PollInterval = defaultPollInterval

				log.Warn().Msg("Sync registries interval set to too-short interval <= 1h, changing update duration to 1 hour and continuing.") // nolint: lll
			}
		}

		var serverCert string

		var serverKey string

		var CACert string

		if config.HTTP.TLS != nil {
			serverCert = config.HTTP.TLS.Cert
			serverKey = config.HTTP.TLS.Key
			CACert = config.HTTP.TLS.CACert
		}

		if err := sync.Run(*config.Extensions.Sync, log, config.HTTP.Address,
			config.HTTP.Port, serverCert, serverKey, CACert); err != nil {
			log.Error().Err(err).Msg("Error encountered while setting up syncing")
		}
	} else {
		log.Info().Msg("Sync registries config not provided, skipping sync")
	}
}

// SetupRoutes ...
func SetupRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	log log.Logger) {
	log.Info().Msg("setting up extensions routes")

	if config.Extensions.Search != nil && config.Extensions.Search.Enable {
		var resConfig search.Config

		if config.Extensions.Search.CVE != nil {
			resConfig = search.GetResolverConfig(log, storeController, true)
		} else {
			resConfig = search.GetResolverConfig(log, storeController, false)
		}

		router.PathPrefix("/query").Methods("GET", "POST").
			Handler(gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig)))
	}

	var serverCert string

	var serverKey string

	var CACert string

	if config.HTTP.TLS != nil {
		serverCert = config.HTTP.TLS.Cert
		serverKey = config.HTTP.TLS.Key
		CACert = config.HTTP.TLS.CACert
	}

	if config.Extensions.Sync != nil {
		postSyncer := sync.PostHandler{
			Address:    config.HTTP.Address,
			Port:       config.HTTP.Port,
			ServerCert: serverCert,
			ServerKey:  serverKey,
			CACert:     CACert,
			Cfg:        *config.Extensions.Sync,
			Log:        log,
		}

		router.HandleFunc("/sync", postSyncer.Handler).Methods("POST")
	}
}

// SyncOneImage syncs one image.
func SyncOneImage(config *config.Config, log log.Logger, repoName, reference string) (bool, error) {
	log.Info().Msgf("syncing image %s:%s", repoName, reference)

	var serverCert string

	var serverKey string

	var CACert string

	if config.HTTP.TLS != nil {
		serverCert = config.HTTP.TLS.Cert
		serverKey = config.HTTP.TLS.Key
		CACert = config.HTTP.TLS.CACert
	}

	ok, err := sync.OneImage(*config.Extensions.Sync, log, config.HTTP.Address, config.HTTP.Port,
		serverCert, serverKey, CACert, repoName, reference)

	return ok, err
}
