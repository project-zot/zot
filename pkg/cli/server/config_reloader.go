package server

import (
	"context"
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

func signalHandler(ctlr *api.Controller, sigCh chan os.Signal, ctx context.Context, cancel context.CancelFunc) {
	select {
	// if signal then shutdown
	case sig := <-sigCh:
		defer cancel()

		ctlr.Log.Info().Interface("signal", sig).Msg("received signal")

		// gracefully shutdown http server
		ctlr.Shutdown() //nolint: contextcheck

		close(sigCh)
	// if reload then return
	case <-ctx.Done():
		return
	}
}

func initShutDownRoutine(ctlr *api.Controller, ctx context.Context, cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)

	go signalHandler(ctlr, sigCh, ctx, cancel)

	// block all async signals to this server
	signal.Ignore()

	// handle SIGINT and SIGHUP.
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

func (hr *HotReloader) Start() context.Context {
	reloadCtx, cancelFunc := context.WithCancel(context.Background())

	done := make(chan bool)

	initShutDownRoutine(hr.ctlr, reloadCtx, cancelFunc)

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
						cancelFunc()

						// create new context
						reloadCtx, cancelFunc = context.WithCancel(context.Background())

						// init shutdown routine
						initShutDownRoutine(hr.ctlr, reloadCtx, cancelFunc)

						hr.ctlr.LoadNewConfig(reloadCtx, newConfig)
					}
				// watch for errors
				case err := <-hr.watcher.Errors:
					log.Error().Err(err).Str("config", hr.filePath).Msg("fsnotfy error while watching config")
					panic(err)
				}
			}
		}()

		if err := hr.watcher.Add(hr.filePath); err != nil {
			log.Error().Err(err).Str("config", hr.filePath).Msg("error adding config file to FsNotify watcher")
			panic(err)
		}

		<-done
	}()

	return reloadCtx
}
