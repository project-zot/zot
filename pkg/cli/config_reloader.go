package cli

import (
	"context"

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

func (hr *HotReloader) Start() context.Context {
	done := make(chan bool)

	reloadCtx, cancelOnReloadFunc := context.WithCancel(context.Background())
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
							log.Error().Err(err).Msg("couldn't reload config, retry writing it.")

							continue
						}
						// if valid config then reload
						cancelOnReloadFunc()

						// create new context
						reloadCtx, cancelOnReloadFunc = context.WithCancel(context.Background())
						hr.ctlr.LoadNewConfig(reloadCtx, newConfig)
					}
				// watch for errors
				case err := <-hr.watcher.Errors:
					log.Error().Err(err).Msgf("fsnotfy error while watching config %s", hr.filePath)
					panic(err)
				}
			}
		}()

		if err := hr.watcher.Add(hr.filePath); err != nil {
			log.Error().Err(err).Msgf("error adding config file %s to FsNotify watcher", hr.filePath)
			panic(err)
		}

		<-done
	}()

	return reloadCtx
}
