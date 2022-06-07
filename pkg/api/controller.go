package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	goSync "sync"
	"syscall"
	"time"

	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	ext "zotregistry.io/zot/pkg/extensions"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/database"
<<<<<<< HEAD
=======
	"zotregistry.io/zot/pkg/storage/dynamodatabase"
>>>>>>> 3a28012 (Added dynamoDB integration)
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

func (c *Controller) CORSHeaders() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// CORS
			c.CORSHandler(response, request)

			next.ServeHTTP(response, request)
		})
	}
}

func (c *Controller) CORSHandler(response http.ResponseWriter, request *http.Request) {
	// allow origin as specified in config if not accept request from anywhere.
	if c.Config.HTTP.AllowOrigin == "" {
		response.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		response.Header().Set("Access-Control-Allow-Origin", c.Config.HTTP.AllowOrigin)
	}

	response.Header().Set("Access-Control-Allow-Methods", "HEAD,GET,POST,OPTIONS")
	response.Header().Set("Access-Control-Allow-Headers", "Authorization")
}

func DumpRuntimeParams(log log.Logger) {
	var rLimit syscall.Rlimit

	evt := log.Info().Int("cpus", runtime.NumCPU())

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err == nil {
		evt = evt.Uint64("max. open files", rLimit.Cur)
	}

	if content, err := ioutil.ReadFile("/proc/sys/net/core/somaxconn"); err == nil {
		evt = evt.Str("listen backlog", strings.TrimSuffix(string(content), "\n"))
	}

	if content, err := ioutil.ReadFile("/proc/sys/user/max_inotify_watches"); err == nil {
		evt = evt.Str("max. inotify watches", strings.TrimSuffix(string(content), "\n"))
	}

	evt.Msg("runtime params")
}

func (c *Controller) Run(reloadCtx context.Context) error {
	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	// print the current runtime environment
	DumpRuntimeParams(c.Log)

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
		c.CORSHeaders(),
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
		*c.Config.Extensions.Metrics.Enable {
		enabled = true
	}

	c.Metrics = monitoring.NewMetricsServer(enabled, c.Log)

	if err := c.InitImageStore(reloadCtx); err != nil {
		return err
	}

	monitoring.SetServerInfo(c.Metrics, c.Config.Commit, c.Config.BinaryType, c.Config.GoVersion,
		c.Config.DistSpecVersion)

	// nolint: contextcheck
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

			server.TLSConfig.ClientAuth = clientAuth
			server.TLSConfig.ClientCAs = caCertPool
		}

		return server.ServeTLS(listener, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
	}

	return server.Serve(listener)
}

// Will create a cache database using the configuration file.
// Pass a non-nil first argument to override the config (for testing purposes, mostly).
func (c *Controller) CreateCacheDatabaseDriver(configOverride interface{}, log log.Logger) (database.Driver, error) {
	if configOverride == nil {
		c.Log.Info().Msg("Loading cache db config from zot config file")

		if val, ok := c.Config.Storage.CacheDatabaseDriver["name"]; ok && len(c.Config.Storage.CacheDatabaseDriver) != 0 {
			switch val {
<<<<<<< HEAD

=======
			case "dynamodb":
				dynEndpointCfgVarName := "endpoint"
				dynRegionCfgVarName := "region"
				dynTableNameCfgVarName := "tablename"

				params := dynamodatabase.DynamoDBDriverParameters{}

				if endpointVal, ok := c.Config.Storage.CacheDatabaseDriver[dynEndpointCfgVarName]; ok && len(endpointVal) != 0 {
					params.Endpoint = endpointVal
				} else {
					panic(fmt.Sprintf("Incomplete config for %v, missing %v zot config var", val, dynEndpointCfgVarName))
				}

				if tableNameVal, ok := c.Config.Storage.CacheDatabaseDriver[dynTableNameCfgVarName]; ok && len(tableNameVal) != 0 {
					params.TableName = tableNameVal
				} else {
					panic(fmt.Sprintf("Incomplete config for %v, missing %v zot config var", val, dynEndpointCfgVarName))
				}

				if valRegion := os.Getenv("AWS_REGION"); valRegion == "" {
					if regionVal, ok := c.Config.Storage.CacheDatabaseDriver[dynRegionCfgVarName]; ok && len(regionVal) != 0 {
						params.Region = regionVal
					} else {
						panic(fmt.Sprintf("Incomplete config for %v, missing %v zot config var", val, dynEndpointCfgVarName))
					}
				}

				return database.Create("dynamodb", params, log)
>>>>>>> 3a28012 (Added dynamoDB integration)
			case "boltdb":
				params := storage.BoltDBDriverParameters{}
				boltRootDirCfgVarName := "rootDirectory"
				boltNameCfgVarName := "name"
				boltbdUseRelCfg := "useRelPaths"

				if rootDirVal, ok := c.Config.Storage.CacheDatabaseDriver[boltRootDirCfgVarName]; ok && len(rootDirVal) != 0 {
					params.RootDir = rootDirVal
				} else {
					panic(fmt.Sprintf("Incomplete config for %v, missing %v zot config var", val, boltRootDirCfgVarName))
				}

				if nameVal, ok := c.Config.Storage.CacheDatabaseDriver[boltNameCfgVarName]; ok && len(nameVal) != 0 {
					params.RootDir = nameVal
				} else {
					panic(fmt.Sprintf("Incomplete config for %v, missing %v zot config var", val, boltNameCfgVarName))
				}

				if useRelPathsVal, ok := c.Config.Storage.CacheDatabaseDriver[boltbdUseRelCfg]; ok && len(useRelPathsVal) != 0 {
					boolVal, err := strconv.ParseBool(useRelPathsVal)
					params.UseRelPaths = boolVal

					if err != nil {
						panic(fmt.Sprintf("Incorrect config for %v, unable to parse %v to a boolean", val, boltbdUseRelCfg))
					}
					params.UseRelPaths = boolVal
				} else {
					panic(fmt.Sprintf("Incomplete config for %v, missing %v zot config var", val, boltbdUseRelCfg))
				}

			default:
				c.Log.Warn().Msgf("Cache DB driver not found for %v: defaulting to boltdb (local storage)", val)

				return database.Create("boltdb", storage.BoltDBDriverParameters{
					RootDir:     c.Config.Storage.RootDirectory,
					Name:        "cache",
					UseRelPaths: true,
				}, log)
			}
		}

		c.Log.Warn().Msg(`Something went wrong when reading the cachedb config. 
		Did you set all necessary variables? Defaulting to local storage`)

		return database.Create("boltdb", storage.BoltDBDriverParameters{
			RootDir:     c.Config.Storage.RootDirectory,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
	}

	// Type assertion for overridden configs
	if dynamoParams, ok := configOverride.(dynamodatabase.DynamoDBDriverParameters); ok {
		return database.Create("dynamodb", dynamoParams, log)
	}

	if boltParams, ok := configOverride.(storage.BoltDBDriverParameters); ok {
		return database.Create("boltdb", boltParams, log)
	}

	return nil, errors.ErrBadConfig
}

func (c *Controller) InitImageStore(reloadCtx context.Context) error {
	c.StoreController = storage.StoreController{}

	cacheDriver, err := c.CreateCacheDatabaseDriver(nil, c.Log)
	if err != nil {
		c.Log.Error().Err(err).Msg("Failed to set up cache db")
	}

	if c.Config.Storage.RootDirectory != "" {
		// no need to validate hard links work on s3
		if c.Config.Storage.Dedupe && c.Config.Storage.StorageDriver == nil {
			err := storage.ValidateHardLink(c.Config.Storage.RootDirectory)
			if err != nil {
				c.Log.Warn().Msg("input storage root directory filesystem does not supports hardlinking," +
					"disabling dedupe functionality")

				c.Config.Storage.Dedupe = false
			}
		}

		var defaultStore storage.ImageStore

		if c.Config.Storage.StorageDriver == nil {
			defaultStore = storage.NewImageStore(c.Config.Storage.RootDirectory,
				c.Config.Storage.GC, c.Config.Storage.GCDelay, c.Config.Storage.Dedupe,
				c.Config.Storage.Commit, c.Log, c.Metrics, cacheDriver)
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

			/* in the case of s3 c.Config.Storage.RootDirectory is used for caching blobs locally and
			c.Config.Storage.StorageDriver["rootdirectory"] is the actual rootDir in s3 */
			rootDir := "/"
			if c.Config.Storage.StorageDriver["rootdirectory"] != nil {
				rootDir = fmt.Sprintf("%v", c.Config.Storage.StorageDriver["rootdirectory"])
			}

			defaultStore = s3.NewImageStore(rootDir, c.Config.Storage.RootDirectory,
				c.Config.Storage.GC, c.Config.Storage.GCDelay, c.Config.Storage.Dedupe,
				c.Config.Storage.Commit, c.Log, c.Metrics, store, cacheDriver)
		}

		c.StoreController.DefaultStore = defaultStore
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
				// no need to validate hard links work on s3
				if storageConfig.Dedupe && storageConfig.StorageDriver == nil {
					err := storage.ValidateHardLink(storageConfig.RootDirectory)
					if err != nil {
						c.Log.Warn().Msg("input storage root directory filesystem does not supports hardlinking, " +
							"disabling dedupe functionality")

						storageConfig.Dedupe = false
					}
				}

				if storageConfig.StorageDriver == nil {
					subImageStore[route] = storage.NewImageStore(storageConfig.RootDirectory,
						storageConfig.GC, storageConfig.GCDelay, storageConfig.Dedupe,
						storageConfig.Commit, c.Log, c.Metrics, cacheDriver)
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

					/* in the case of s3 c.Config.Storage.RootDirectory is used for caching blobs locally and
					c.Config.Storage.StorageDriver["rootdirectory"] is the actual rootDir in s3 */
					rootDir := "/"
					if c.Config.Storage.StorageDriver["rootdirectory"] != nil {
						rootDir = fmt.Sprintf("%v", c.Config.Storage.StorageDriver["rootdirectory"])
					}

					subImageStore[route] = s3.NewImageStore(rootDir, storageConfig.RootDirectory,
						storageConfig.GC, storageConfig.GCDelay, storageConfig.Dedupe,
						storageConfig.Commit, c.Log, c.Metrics, store, cacheDriver)
				}
			}

			c.StoreController.SubStore = subImageStore
		}
	}

	c.StartBackgroundTasks(reloadCtx)

	return nil
}

func (c *Controller) LoadNewConfig(reloadCtx context.Context, config *config.Config) {
	// reload access control config
	c.Config.AccessControl = config.AccessControl
	c.Config.HTTP.RawAccessControl = config.HTTP.RawAccessControl

	// Enable extensions if extension config is provided
	if config.Extensions != nil && config.Extensions.Sync != nil {
		// reload sync config
		c.Config.Extensions.Sync = config.Extensions.Sync
		ext.EnableSyncExtension(reloadCtx, c.Config, c.wgShutDown, c.StoreController, c.Log)
	} else if c.Config.Extensions != nil {
		c.Config.Extensions.Sync = nil
	}

	c.Log.Info().Interface("reloaded params", c.Config.Sanitize()).Msg("new configuration settings")
}

func (c *Controller) Shutdown() {
	// wait gracefully
	c.wgShutDown.Wait()

	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}

func (c *Controller) StartBackgroundTasks(reloadCtx context.Context) {
	// Enable extensions if extension config is provided for DefaultStore
	if c.Config != nil && c.Config.Extensions != nil {
		ext.EnableMetricsExtension(c.Config, c.Log, c.Config.Storage.RootDirectory)
		ext.EnableSearchExtension(c.Config, c.Log, c.Config.Storage.RootDirectory)
	}

	if c.Config.Storage.SubPaths != nil {
		for _, storageConfig := range c.Config.Storage.SubPaths {
			// Enable extensions if extension config is provided for subImageStore
			if c.Config != nil && c.Config.Extensions != nil {
				ext.EnableMetricsExtension(c.Config, c.Log, storageConfig.RootDirectory)
				ext.EnableSearchExtension(c.Config, c.Log, storageConfig.RootDirectory)
			}
		}
	}

	// Enable extensions if extension config is provided for storeController
	if c.Config.Extensions != nil {
		if c.Config.Extensions.Sync != nil {
			ext.EnableSyncExtension(reloadCtx, c.Config, c.wgShutDown, c.StoreController, c.Log)
		}
	}

	if c.Config.Extensions != nil {
		ext.EnableScrubExtension(c.Config, c.Log, false, nil, "")
	}

	go StartPeriodicTasks(c.StoreController.DefaultStore, c.StoreController.SubStore, c.Config.Storage.SubPaths,
		c.Config.Storage.GC, c.Config.Storage.GCInterval, c.Config.Extensions, c.Log)
}

func StartPeriodicTasks(defaultStore storage.ImageStore, subStore map[string]storage.ImageStore,
	subPaths map[string]config.StorageConfig, gcEnabled bool, gcInterval time.Duration,
	extensions *extconf.ExtensionConfig, log log.Logger,
) {
	// start periodic gc and/or scrub for DefaultStore
	StartPeriodicTasksForImageStore(defaultStore, gcEnabled, gcInterval, extensions, log)

	for route, storageConfig := range subPaths {
		// Enable running garbage-collect or/and scrub periodically for subImageStore
		StartPeriodicTasksForImageStore(subStore[route], storageConfig.GC, storageConfig.GCInterval, extensions, log)
	}
}

func StartPeriodicTasksForImageStore(imageStore storage.ImageStore, configGC bool, configGCInterval time.Duration,
	extensions *extconf.ExtensionConfig, log log.Logger,
) {
	scrubInterval := time.Duration(0)
	gcInterval := time.Duration(0)

	gc := false
	scrub := false

	if configGC && configGCInterval != 0 {
		gcInterval = configGCInterval
		gc = true
	}

	if extensions != nil && extensions.Scrub != nil && extensions.Scrub.Interval != 0 {
		scrubInterval = extensions.Scrub.Interval
		scrub = true
	}

	interval := minPeriodicInterval(scrub, gc, scrubInterval, gcInterval)
	if interval == time.Duration(0) {
		return
	}

	log.Info().Msg(fmt.Sprintf("Periodic interval for %s set to %s", imageStore.RootDir(), interval))

	var lastGC, lastScrub time.Time

	for {
		log.Info().Msg(fmt.Sprintf("Starting periodic background tasks for %s", imageStore.RootDir()))

		// Enable running garbage-collect or/and scrub periodically for imageStore
		RunBackgroundTasks(imageStore, gc, scrub, log)

		log.Info().Msg(fmt.Sprintf("Finishing periodic background tasks for %s", imageStore.RootDir()))

		if gc {
			lastGC = time.Now()
		}

		if scrub {
			lastScrub = time.Now()
		}

		time.Sleep(interval)

		if !lastGC.IsZero() && time.Since(lastGC) >= gcInterval {
			gc = true
		}

		if !lastScrub.IsZero() && time.Since(lastScrub) >= scrubInterval {
			scrub = true
		}
	}
}

func RunBackgroundTasks(imgStore storage.ImageStore, gc, scrub bool, log log.Logger) {
	repos, err := imgStore.GetRepositories()
	if err != nil {
		log.Error().Err(err).Msg(fmt.Sprintf("error while running background task for %s", imgStore.RootDir()))

		return
	}

	for _, repo := range repos {
		if gc {
			start := time.Now()

			// run gc for this repo
			imgStore.RunGCRepo(repo)

			elapsed := time.Since(start)
			log.Info().Msg(fmt.Sprintf("gc for %s executed in %s", repo, elapsed))
			time.Sleep(1 * time.Minute)
		}

		if scrub {
			start := time.Now()

			// run scrub for this repo
			ext.EnableScrubExtension(nil, log, true, imgStore, repo)

			elapsed := time.Since(start)
			log.Info().Msg(fmt.Sprintf("scrub for %s executed in %s", repo, elapsed))
			time.Sleep(1 * time.Minute)
		}
	}
}

func minPeriodicInterval(scrub, gc bool, scrubInterval, gcInterval time.Duration) time.Duration {
	if scrub && gc {
		if scrubInterval <= gcInterval {
			return scrubInterval
		}

		return gcInterval
	}

	if scrub {
		return scrubInterval
	}

	if gc {
		return gcInterval
	}

	return time.Duration(0)
}
