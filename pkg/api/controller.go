package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	ext "zotregistry.io/zot/pkg/extensions"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/meta/repodb/repodbfactory"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
)

const (
	idleTimeout       = 120 * time.Second
	readHeaderTimeout = 5 * time.Second
)

type Controller struct {
	Config          *config.Config
	Router          *mux.Router
	RepoDB          repodb.RepoDB
	StoreController storage.StoreController
	Log             log.Logger
	Audit           *log.Logger
	Server          *http.Server
	Metrics         monitoring.MetricServer
	CveInfo         ext.CveInfo
	SyncOnDemand    SyncOnDemand
	// runtime params
	chosenPort int // kernel-chosen port
}

func NewController(config *config.Config) *Controller {
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

func DumpRuntimeParams(log log.Logger) {
	var rLimit syscall.Rlimit

	evt := log.Info().Int("cpus", runtime.NumCPU())

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err == nil {
		evt = evt.Uint64("max. open files", rLimit.Cur)
	}

	if content, err := os.ReadFile("/proc/sys/net/core/somaxconn"); err == nil {
		evt = evt.Str("listen backlog", strings.TrimSuffix(string(content), "\n"))
	}

	if content, err := os.ReadFile("/proc/sys/user/max_inotify_watches"); err == nil {
		evt = evt.Str("max. inotify watches", strings.TrimSuffix(string(content), "\n"))
	}

	evt.Msg("runtime params")
}

func (c *Controller) GetPort() int {
	return c.chosenPort
}

func (c *Controller) Run(reloadCtx context.Context) error {
	c.StartBackgroundTasks(reloadCtx)

	// setup HTTP API router
	engine := mux.NewRouter()

	// rate-limit HTTP requests if enabled
	if c.Config.HTTP.Ratelimit != nil {
		if c.Config.HTTP.Ratelimit.Rate != nil {
			engine.Use(RateLimiter(c, *c.Config.HTTP.Ratelimit.Rate))
		}

		for _, mrlim := range c.Config.HTTP.Ratelimit.Methods {
			engine.Use(MethodRateLimiter(c, mrlim.Method, mrlim.Rate))
		}
	}

	engine.Use(
		SessionLogger(c),
		handlers.RecoveryHandler(handlers.RecoveryLogger(c.Log),
			handlers.PrintRecoveryStack(false)))

	if c.Audit != nil {
		engine.Use(SessionAuditLogger(c.Audit))
	}

	c.Router = engine
	c.Router.UseEncodedPath()

	monitoring.SetServerInfo(c.Metrics, c.Config.Commit, c.Config.BinaryType, c.Config.GoVersion,
		c.Config.DistSpecVersion)

	//nolint: contextcheck
	_ = NewRouteHandler(c)

	addr := fmt.Sprintf("%s:%s", c.Config.HTTP.Address, c.Config.HTTP.Port)
	server := &http.Server{
		Addr:              addr,
		Handler:           c.Router,
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	c.Server = server

	// Create the listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if c.Config.HTTP.Port == "0" || c.Config.HTTP.Port == "" {
		chosenAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			c.Log.Error().Str("port", c.Config.HTTP.Port).Msg("invalid addr type")

			return errors.ErrBadType
		}

		c.chosenPort = chosenAddr.Port

		c.Log.Info().Int("port", chosenAddr.Port).IPAddr("address", chosenAddr.IP).Msg(
			"port is unspecified, listening on kernel chosen port",
		)
	} else {
		chosenPort, _ := strconv.ParseInt(c.Config.HTTP.Port, 10, 64)

		c.chosenPort = int(chosenPort)
	}

	if c.Config.HTTP.TLS != nil && c.Config.HTTP.TLS.Key != "" && c.Config.HTTP.TLS.Cert != "" {
		server.TLSConfig = &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
		}

		if c.Config.HTTP.TLS.CACert != "" {
			clientAuth := tls.VerifyClientCertIfGiven
			if (c.Config.HTTP.Auth == nil || c.Config.HTTP.Auth.HTPasswd.Path == "") &&
				!c.Config.HTTP.AccessControl.AnonymousPolicyExists() {
				clientAuth = tls.RequireAndVerifyClientCert
			}

			caCert, err := os.ReadFile(c.Config.HTTP.TLS.CACert)
			if err != nil {
				panic(err)
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				panic(errors.ErrBadCACert)
			}

			server.TLSConfig.ClientAuth = clientAuth
			server.TLSConfig.ClientCAs = caCertPool
		}

		return server.ServeTLS(listener, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
	}

	return server.Serve(listener)
}

func (c *Controller) Init(reloadCtx context.Context) error {
	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	// print the current runtime environment
	DumpRuntimeParams(c.Log)

	var enabled bool
	if c.Config != nil &&
		c.Config.Extensions != nil &&
		c.Config.Extensions.Metrics != nil &&
		*c.Config.Extensions.Metrics.Enable {
		enabled = true
	}

	c.Metrics = monitoring.NewMetricsServer(enabled, c.Log)

	if err := c.InitImageStore(); err != nil { //nolint:contextcheck
		return err
	}

	if err := c.InitRepoDB(reloadCtx); err != nil {
		return err
	}

	c.InitCVEInfo()

	return nil
}

func (c *Controller) InitCVEInfo() {
	// Enable CVE extension if extension config is provided
	if c.Config != nil && c.Config.Extensions != nil {
		c.CveInfo = ext.GetCVEInfo(c.Config, c.StoreController, c.RepoDB, c.Log)
	}
}

func (c *Controller) InitImageStore() error {
	linter := ext.GetLinter(c.Config, c.Log)

	storeController, err := storage.New(c.Config, linter, c.Metrics, c.Log)
	if err != nil {
		return err
	}

	c.StoreController = storeController

	return nil
}

func (c *Controller) InitRepoDB(reloadCtx context.Context) error {
	if c.Config.Extensions != nil && c.Config.Extensions.Search != nil && *c.Config.Extensions.Search.Enable {
		driver, err := repodbfactory.New(c.Config.Storage.StorageConfig, c.Log) //nolint:contextcheck
		if err != nil {
			return err
		}

		err = driver.PatchDB()
		if err != nil {
			return err
		}

		err = repodb.ParseStorage(driver, c.StoreController, c.Log)
		if err != nil {
			return err
		}

		c.RepoDB = driver
	}

	return nil
}

func (c *Controller) LoadNewConfig(reloadCtx context.Context, config *config.Config) {
	// reload access control config
	c.Config.HTTP.AccessControl = config.HTTP.AccessControl

	// reload periodical gc interval
	c.Config.Storage.GCInterval = config.Storage.GCInterval

	// reload background tasks
	if config.Extensions != nil {
		// reload sync extension
		c.Config.Extensions.Sync = config.Extensions.Sync
		// reload search cve extension
		if c.Config.Extensions.Search != nil {
			// reload only if search is enabled and reloaded config has search extension
			if *c.Config.Extensions.Search.Enable && config.Extensions.Search != nil {
				c.Config.Extensions.Search.CVE = config.Extensions.Search.CVE
			}
		}
		// reload scrub extension
		c.Config.Extensions.Scrub = config.Extensions.Scrub
	} else {
		c.Config.Extensions = nil
	}

	c.StartBackgroundTasks(reloadCtx)

	c.Log.Info().Interface("reloaded params", c.Config.Sanitize()).
		Msg("loaded new configuration settings")
}

func (c *Controller) Shutdown() {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}

func (c *Controller) StartBackgroundTasks(reloadCtx context.Context) {
	taskScheduler := scheduler.NewScheduler(c.Config, c.Log)
	taskScheduler.RunScheduler(reloadCtx)

	// Enable running garbage-collect periodically for DefaultStore
	if c.Config.Storage.GC && c.Config.Storage.GCInterval != 0 {
		c.StoreController.DefaultStore.RunGCPeriodically(c.Config.Storage.GCInterval, taskScheduler)
	}

	// Enable running dedupe blobs both ways (dedupe or restore deduped blobs)
	c.StoreController.DefaultStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

	// Enable extensions if extension config is provided for DefaultStore
	if c.Config != nil && c.Config.Extensions != nil {
		ext.EnableMetricsExtension(c.Config, c.Log, c.Config.Storage.RootDirectory)
		ext.EnableSearchExtension(c.Config, c.StoreController, c.RepoDB, taskScheduler, c.CveInfo, c.Log)
	}

	if c.Config.Storage.SubPaths != nil {
		for route, storageConfig := range c.Config.Storage.SubPaths {
			// Enable running garbage-collect periodically for subImageStore
			if storageConfig.GC && storageConfig.GCInterval != 0 {
				c.StoreController.SubStore[route].RunGCPeriodically(storageConfig.GCInterval, taskScheduler)
			}

			// Enable extensions if extension config is provided for subImageStore
			if c.Config != nil && c.Config.Extensions != nil {
				ext.EnableMetricsExtension(c.Config, c.Log, storageConfig.RootDirectory)
			}

			// Enable running dedupe blobs both ways (dedupe or restore deduped blobs) for subpaths
			substore := c.StoreController.SubStore[route]
			if substore != nil {
				substore.RunDedupeBlobs(time.Duration(0), taskScheduler)
			}
		}
	}

	if c.Config.Extensions != nil {
		ext.EnableScrubExtension(c.Config, c.Log, c.StoreController, taskScheduler)

		syncOnDemand, err := ext.EnableSyncExtension(c.Config, c.RepoDB, c.StoreController, taskScheduler, c.Log)
		if err != nil {
			c.Log.Error().Err(err).Msg("unable to start sync extension")
		}

		c.SyncOnDemand = syncOnDemand
	}

	if c.Config.Extensions != nil {
		if c.Config.Extensions.Mgmt != nil && *c.Config.Extensions.Mgmt.Enable {
			ext.EnablePeriodicSignaturesVerification(c.Config, taskScheduler, c.RepoDB, c.Log) //nolint: contextcheck
		}
	}
}

type SyncOnDemand interface {
	SyncImage(repo, reference string) error
	SyncReference(repo string, subjectDigestStr string, referenceType string) error
}
