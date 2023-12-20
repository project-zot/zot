package server

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
)

type HotReloader struct {
	watcher  *fsnotify.Watcher
	filePath string
	ctlr     *api.Controller
}

func NewHotReloader(ctlr *api.Controller, filePath string) (*HotReloader, error) {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	hotReloader := &HotReloader{
		watcher:  watcher,
		filePath: filePath,
		ctlr:     ctlr,
	}

	return hotReloader, nil
}

func signalHandler(ctlr *api.Controller, sigCh chan os.Signal) {
	// if signal then shutdown
	if sig, ok := <-sigCh; ok {
		ctlr.Log.Info().Interface("signal", sig).Msg("received signal")

		// gracefully shutdown http server
		ctlr.Shutdown() //nolint: contextcheck
	}
}

func initShutDownRoutine(ctlr *api.Controller) {
	sigCh := make(chan os.Signal, 1)

	go signalHandler(ctlr, sigCh)

	// block all async signals to this server
	signal.Ignore()

	// handle SIGINT and SIGHUP.
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

func (hr *HotReloader) Start() {
	done := make(chan bool)

	// run watcher
	go func() {
		defer hr.watcher.Close()

		go func() {
			for {
				select {
				// watch for events
				case event := <-hr.watcher.Events:
					if event.Op == fsnotify.Write {
						log.Info().Msg("config file changed, trying to reload config")

						newConfig := config.New()

						err := LoadConfiguration(newConfig, hr.filePath)
						if err != nil {
							log.Error().Err(err).Msg("failed to reload config, retry writing it.")

							continue
						}

						// stop background tasks gracefully
						hr.ctlr.StopBackgroundTasks()

						// load new config
						hr.ctlr.LoadNewConfig(newConfig)

						// start background tasks based on new loaded config
						hr.ctlr.StartBackgroundTasks()
					}
				// watch for errors
				case err := <-hr.watcher.Errors:
					log.Panic().Err(err).Str("config", hr.filePath).Msg("fsnotfy error while watching config")
				}
			}
		}()

		if err := hr.watcher.Add(hr.filePath); err != nil {
			log.Panic().Err(err).Str("config", hr.filePath).Msg("failed to add config file to fsnotity watcher")
		}

		<-done
	}()
}
