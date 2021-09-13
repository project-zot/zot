package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/anuvu/zot/errors"
	ext "github.com/anuvu/zot/pkg/extensions"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	idleTimeout = 120 * time.Second
)

type Controller struct {
	Config          *Config
	Router          *mux.Router
	StoreController storage.StoreController
	Log             log.Logger
	Audit           *log.Logger
	Server          *http.Server
}

func NewController(config *Config) *Controller {
	var controller Controller

	logger := log.NewLogger(config.Log.Level, config.Log.Output)

	controller.Config = config
	controller.Log = logger

	if config.Log.Audit != "" {
		audit := log.NewAuditLogger(config.Log.Level, config.Log.Audit)
		controller.Audit = audit
	}

	return &controller
}

func DefaultHeaders() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

			// handle the request
			next.ServeHTTP(w, r)
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
		SessionLogger(c.Log),
		handlers.RecoveryHandler(handlers.RecoveryLogger(c.Log),
			handlers.PrintRecoveryStack(false)))

	if c.Audit != nil {
		engine.Use(SessionAuditLogger(c.Audit))
	}

	c.Router = engine
	c.Router.UseEncodedPath()

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

		defaultStore := storage.NewImageStore(c.Config.Storage.RootDirectory,
			c.Config.Storage.GC, c.Config.Storage.Dedupe, c.Log)

		c.StoreController.DefaultStore = defaultStore

		// Enable extensions if extension config is provided
		if c.Config != nil && c.Config.Extensions != nil {
			ext.EnableExtensions(c.Config.Extensions, c.Log, c.Config.Storage.RootDirectory)
		}
	} else {
		// we can't proceed without global storage
		c.Log.Error().Err(errors.ErrImgStoreNotFound).Msg("controller: no storage config provided")

		return errors.ErrImgStoreNotFound
	}

	if c.Config.Storage.SubPaths != nil {
		if len(c.Config.Storage.SubPaths) > 0 {
			subPaths := c.Config.Storage.SubPaths

			subImageStore := make(map[string]*storage.ImageStore)

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

				subImageStore[route] = storage.NewImageStore(storageConfig.RootDirectory,
					storageConfig.GC, storageConfig.Dedupe, c.Log)

				// Enable extensions if extension config is provided
				if c.Config != nil && c.Config.Extensions != nil {
					ext.EnableExtensions(c.Config.Extensions, c.Log, storageConfig.RootDirectory)
				}
			}

			c.StoreController.SubStore = subImageStore
		}
	}

	_ = NewRouteHandler(c)

	addr := fmt.Sprintf("%s:%s", c.Config.HTTP.Address, c.Config.HTTP.Port)
	server := &http.Server{
		Addr:        addr,
		Handler:     c.Router,
		IdleTimeout: idleTimeout,
	}
	c.Server = server

	// Create the listener
	l, err := net.Listen("tcp", addr)
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
			server.TLSConfig.BuildNameToCertificate() // nolint: staticcheck
		}

		return server.ServeTLS(l, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
	}

	return server.Serve(l)
}
