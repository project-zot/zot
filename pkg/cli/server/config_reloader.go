package server

import (
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

type HotReloader struct {
	watcher             *fsnotify.Watcher
	configPath          string
	ldapCredentialsPath string
	ctlr                *api.Controller
	logger              log.Logger

	done     chan struct{}
	stopOnce sync.Once
}

func NewHotReloader(ctlr *api.Controller, filePath, ldapCredentialsPath string) (*HotReloader, error) {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	hotReloader := &HotReloader{
		watcher:             watcher,
		configPath:          filePath,
		ldapCredentialsPath: ldapCredentialsPath,
		ctlr:                ctlr,
		logger:              log.NewLogger("info", ""),
		done:                make(chan struct{}),
	}

	return hotReloader, nil
}

func signalHandler(ctlr *api.Controller, hr *HotReloader, sigCh chan os.Signal) {
	// if signal then shutdown
	if sig, ok := <-sigCh; ok {
		ctlr.Log.Info().Interface("signal", sig).Msg("received signal")

		hr.Stop()
		// gracefully shutdown http server
		ctlr.Shutdown() //nolint: contextcheck
	}
}

func initShutDownRoutine(ctlr *api.Controller, hr *HotReloader) {
	sigCh := make(chan os.Signal, 1)

	go signalHandler(ctlr, hr, sigCh)

	// block all async signals to this server
	signal.Ignore()

	// handle SIGINT and SIGHUP.
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

func (hr *HotReloader) Stop() {
	hr.stopOnce.Do(func() {
		if hr.done != nil {
			close(hr.done)
		}
		if hr.watcher != nil {
			_ = hr.watcher.Close()
		}
	})
}

func (hr *HotReloader) Start() {
	// run watcher
	go func() {
		defer hr.watcher.Close()

		go func() {
			for {
				select {
				case <-hr.done:
					return
				// watch for events
				case event, ok := <-hr.watcher.Events:
					if !ok {
						return
					}
					if event.Op == fsnotify.Write {
						hr.logger.Info().Msg("config file changed, trying to reload config")

						newConfig := config.New()

						err := LoadConfiguration(newConfig, hr.configPath)
						if err != nil {
							hr.logger.Error().Err(err).Msg("failed to reload config, retry writing it.")

							continue
						}

						authConfig := hr.ctlr.Config.CopyAuthConfig()
						if authConfig.IsLdapAuthEnabled() &&
							authConfig.LDAP.CredentialsFile != newConfig.HTTP.Auth.LDAP.CredentialsFile {
							err = hr.watcher.Remove(authConfig.LDAP.CredentialsFile)
							if err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
								hr.logger.Error().Err(err).Msg("failed to remove old watch for the credentials file")
							}

							err = hr.watcher.Add(newConfig.HTTP.Auth.LDAP.CredentialsFile)
							if err != nil {
								hr.logger.Panic().Err(err).Str("ldap-credentials-file", newConfig.HTTP.Auth.LDAP.CredentialsFile).
									Msg("failed to watch ldap credentials file")
							}
						}

						// stop background tasks gracefully
						hr.ctlr.StopBackgroundTasks()

						// load new config
						hr.ctlr.LoadNewConfig(newConfig)

						// start background tasks based on new loaded config
						hr.ctlr.StartBackgroundTasks()
					}
				// watch for errors
				case err, ok := <-hr.watcher.Errors:
					if !ok {
						return
					}
					hr.logger.Panic().Err(err).Str("config", hr.configPath).Msg("fsnotfy error while watching config")
				}
			}
		}()

		if err := hr.watcher.Add(hr.configPath); err != nil {
			hr.logger.Panic().Err(err).Str("config", hr.configPath).Msg("failed to add config file to fsnotity watcher")
		}

		if hr.ldapCredentialsPath != "" {
			if err := hr.watcher.Add(hr.ldapCredentialsPath); err != nil {
				hr.logger.Panic().Err(err).Str("ldap-credentials", hr.ldapCredentialsPath).
					Msg("failed to add ldap-credentials to fsnotity watcher")
			}
		}

		<-hr.done
	}()
}
