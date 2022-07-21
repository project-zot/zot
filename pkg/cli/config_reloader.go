package cli

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
)

const fsnotifyRateLimit = 500 * time.Millisecond

type HotReloader struct {
	watcher    *fsnotify.Watcher
	configPath string
}

func NewHotReloader(configPath string) (*HotReloader, error) {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	hotReloader := &HotReloader{
		watcher:    watcher,
		configPath: configPath,
	}

	return hotReloader, nil
}

func (hr *HotReloader) Start() {
	defer hr.watcher.Close()
	done := make(chan bool)

	cfg := config.New()
	if err := config.LoadFromFile(hr.configPath, cfg); err != nil {
		panic(err)
	}

	ctlr := api.NewController(cfg)
	ctlr.SetConfigPath(hr.configPath)

	reloadCtx, cancelOnReloadFunc := context.WithCancel(context.Background())

	// start server
	go func() {
		if err := ctlr.Run(reloadCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	go func() {
		var (
			timer     *time.Timer
			lastEvent fsnotify.Event
		)

		// this is an workaround for fsnotify firing 2 write events instead of 1
		timer = time.NewTimer(time.Millisecond)
		<-timer.C // timer should be expired at first

		for {
			select {
			// watch for events
			case event := <-hr.watcher.Events:
				lastEvent = event

				timer.Reset(fsnotifyRateLimit)
			case <-timer.C:
				if lastEvent.Op == fsnotify.Write {
					log.Info().Msg("reloader: config file changed, trying to hot reload config")

					newConfig := &config.Config{}
					if err := config.LoadFromFile(hr.configPath, newConfig); err != nil {
						log.Error().Err(err).Msg("reloader: couldn't hot reload config, retry writing it.")

						continue
					}

					// create new context
					reloadCtx, cancelOnReloadFunc = context.WithCancel(context.Background())

					shutdownFunc := ctlr.Shutdown
					ctlr = api.NewController(newConfig)
					ctlr.SetConfigPath(hr.configPath)

					// if valid config then reload
					// stop go routines
					cancelOnReloadFunc()
					// stop server
					shutdownFunc()

					// wait for server to shutdown
					//nolint: contextcheck
					for isServerRunning(cfg.HTTP.Address, cfg.HTTP.Port) {
						continue
					}

					// start new server
					go func() {
						if err := ctlr.Run(reloadCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
							panic(err)
						}
					}()
				}
			// watch for errors
			case err := <-hr.watcher.Errors:
				log.Error().Err(err).Msgf("reloader: fsnotfy error while watching config %s", hr.configPath)
				panic(err)
			}
		}
	}()

	if err := hr.watcher.Add(hr.configPath); err != nil {
		log.Error().Err(err).Msgf("reloader: error adding config file %s to FsNotify watcher", hr.configPath)
		panic(err)
	}

	<-done
}
