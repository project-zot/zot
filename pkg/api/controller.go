package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	goSync "sync"
	"time"

	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	ext "zotregistry.io/zot/pkg/extensions"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/s3"
)

const (
	idleTimeout = 120 * time.Second
)

type Controller struct {
	Config          *config.Config
	Router          *mux.Router
	StoreController storage.StoreController
	Log             log.Logger
	Audit           *log.Logger
	Server          *http.Server
	Metrics         monitoring.MetricServer
	wgShutDown      *goSync.WaitGroup // use it to gracefully shutdown goroutines
}

func NewController(config *config.Config) *Controller {
	var controller Controller

	logger := log.NewLogger(config.Log.Level, config.Log.Output)

	controller.Config = config
	controller.Log = logger
	controller.wgShutDown = new(goSync.WaitGroup)

	if config.Log.Audit != "" {
		audit := log.NewAuditLogger(config.Log.Level, config.Log.Audit)
		controller.Audit = audit
	}

	return &controller
}

func DefaultHeaders() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// CORS
			response.Header().Set("Access-Control-Allow-Origin", "*")
			response.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

			// handle the request
			next.ServeHTTP(response, request)
		})
	}
}

func (c *Controller) Run() error {
	// validate configuration
	if err := c.Config.Validate(c.Log); err != nil {
		c.Log.Error().Err(err).Msg("configuration validation failed")

		return err
	}

	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	engine := mux.NewRouter()
	engine.Use(DefaultHeaders(),
		SessionLogger(c),
		handlers.RecoveryHandler(handlers.RecoveryLogger(c.Log),
			handlers.PrintRecoveryStack(false)))

	if c.Audit != nil {
		engine.Use(SessionAuditLogger(c.Audit))
	}

	c.Router = engine
	c.Router.UseEncodedPath()

	var enabled bool
	if c.Config != nil &&
		c.Config.Extensions != nil &&
		c.Config.Extensions.Metrics != nil &&
		c.Config.Extensions.Metrics.Enable {
		enabled = true
	}

	c.Metrics = monitoring.NewMetricsServer(enabled, c.Log)

	if err := c.InitImageStore(); err != nil {
		return err
	}

	monitoring.SetServerInfo(c.Metrics, c.Config.Commit, c.Config.BinaryType, c.Config.GoVersion, c.Config.Version)
	_ = NewRouteHandler(c)

	addr := fmt.Sprintf("%s:%s", c.Config.HTTP.Address, c.Config.HTTP.Port)
	server := &http.Server{
		Addr:        addr,
		Handler:     c.Router,
		IdleTimeout: idleTimeout,
	}
	c.Server = server

	// Create the listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if c.Config.HTTP.TLS != nil && c.Config.HTTP.TLS.Key != "" && c.Config.HTTP.TLS.Cert != "" {
		if c.Config.HTTP.TLS.CACert != "" {
			clientAuth := tls.VerifyClientCertIfGiven
			if (c.Config.HTTP.Auth == nil || c.Config.HTTP.Auth.HTPasswd.Path == "") && !c.Config.HTTP.AllowReadAccess {
				clientAuth = tls.RequireAndVerifyClientCert
			}

			caCert, err := ioutil.ReadFile(c.Config.HTTP.TLS.CACert)
			if err != nil {
				panic(err)
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				panic(errors.ErrBadCACert)
			}

			server.TLSConfig = &tls.Config{
				ClientAuth:               clientAuth,
				ClientCAs:                caCertPool,
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS12,
			}
			server.TLSConfig.BuildNameToCertificate()
		}

		return server.ServeTLS(listener, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
	}

	return server.Serve(listener)
}

func (c *Controller) InitImageStore() error {
	c.StoreController = storage.StoreController{}

	if c.Config.Storage.RootDirectory != "" {
		if c.Config.Storage.Dedupe {
			err := storage.ValidateHardLink(c.Config.Storage.RootDirectory)
			if err != nil {
				c.Log.Warn().Msg("input storage root directory filesystem does not supports hardlinking," +
					"disabling dedupe functionality")

				c.Config.Storage.Dedupe = false
			}
		}

		var defaultStore storage.ImageStore
		if len(c.Config.Storage.StorageDriver) == 0 {
			defaultStore = storage.NewImageStore(c.Config.Storage.RootDirectory,
				c.Config.Storage.GC, c.Config.Storage.Dedupe, c.Log, c.Metrics)
		} else {
			storeName := fmt.Sprintf("%v", c.Config.Storage.StorageDriver["name"])
			if storeName != storage.S3StorageDriverName {
				c.Log.Fatal().Err(errors.ErrBadConfig).Msgf("unsupported storage driver: %s",
					c.Config.Storage.StorageDriver["name"])
			}
			// Init a Storager from connection string.
			store, err := factory.Create(storeName, c.Config.Storage.StorageDriver)
			if err != nil {
				c.Log.Error().Err(err).Str("rootDir", c.Config.Storage.RootDirectory).Msg("unable to create s3 service")

				return err
			}

			defaultStore = s3.NewImageStore(c.Config.Storage.RootDirectory,
				c.Config.Storage.GC, c.Config.Storage.Dedupe, c.Log, c.Metrics, store)
		}

		c.StoreController.DefaultStore = defaultStore

		// Enable extensions if extension config is provided
		if c.Config != nil && c.Config.Extensions != nil {
			ext.EnableExtensions(c.Config, c.Log, c.Config.Storage.RootDirectory)
		}
	} else {
		// we can't proceed without global storage
		c.Log.Error().Err(errors.ErrImgStoreNotFound).Msg("controller: no storage config provided")

		return errors.ErrImgStoreNotFound
	}

	if c.Config.Storage.SubPaths != nil {
		if len(c.Config.Storage.SubPaths) > 0 {
			subPaths := c.Config.Storage.SubPaths

			subImageStore := make(map[string]storage.ImageStore)

			// creating image store per subpaths
			for route, storageConfig := range subPaths {
				if storageConfig.Dedupe {
					err := storage.ValidateHardLink(storageConfig.RootDirectory)
					if err != nil {
						c.Log.Warn().Msg("input storage root directory filesystem does not supports hardlinking, " +
							"disabling dedupe functionality")

						storageConfig.Dedupe = false
					}
				}

				if len(storageConfig.StorageDriver) == 0 {
					subImageStore[route] = storage.NewImageStore(storageConfig.RootDirectory,
						storageConfig.GC, storageConfig.Dedupe, c.Log, c.Metrics)
				} else {
					storeName := fmt.Sprintf("%v", storageConfig.StorageDriver["name"])
					if storeName != storage.S3StorageDriverName {
						c.Log.Fatal().Err(errors.ErrBadConfig).Msgf("unsupported storage driver: %s", storageConfig.StorageDriver["name"])
					}

					// Init a Storager from connection string.
					store, err := factory.Create(storeName, storageConfig.StorageDriver)
					if err != nil {
						c.Log.Error().Err(err).Str("rootDir", storageConfig.RootDirectory).Msg("Unable to create s3 service")

						return err
					}

					subImageStore[route] = s3.NewImageStore(storageConfig.RootDirectory,
						storageConfig.GC, storageConfig.Dedupe, c.Log, c.Metrics, store)
				}

				// Enable extensions if extension config is provided
				if c.Config != nil && c.Config.Extensions != nil {
					ext.EnableExtensions(c.Config, c.Log, storageConfig.RootDirectory)
				}
			}

			c.StoreController.SubStore = subImageStore
		}
	}

	// Enable extensions if extension config is provided
	if c.Config.Extensions != nil && c.Config.Extensions.Sync != nil && c.Config.Extensions.Sync.Enable {
		ext.EnableSyncExtension(c.Config, c.wgShutDown, c.StoreController, c.Log)
	}

	return nil
}

func (c *Controller) Shutdown() {
	// wait gracefully
	c.wgShutDown.Wait()

	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
