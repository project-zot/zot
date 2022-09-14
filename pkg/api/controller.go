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
	goSync "sync"
	"syscall"
	"time"

	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	ext "zotregistry.io/zot/pkg/extensions"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta" // MetadataStore   meta.MetadataStore
	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamoParams "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper/params"
	"zotregistry.io/zot/pkg/meta/repodb/repodbfactory"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/storage/s3"
)

const (
	idleTimeout       = 120 * time.Second
	readHeaderTimeout = 5 * time.Second
)

type Controller struct {
	Config          *config.Config
	Router          *mux.Router
	RepoDB          repodb.RepoDB
	MetaStore       *meta.MetadataStore
	StoreController storage.StoreController
	Log             log.Logger
	Audit           *log.Logger
	Server          *http.Server
	Metrics         monitoring.MetricServer
	wgShutDown      *goSync.WaitGroup // use it to gracefully shutdown goroutines
	// runtime params
	chosenPort int // kernel-chosen port
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
	response.Header().Set("Access-Control-Allow-Headers", "Authorization,content-type")
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
	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	// print the current runtime environment
	DumpRuntimeParams(c.Log)

	c.MetaStore = c.CreateMetadataDatabaseDriver(c.Config, c.Log)
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

	if err := c.InitRepoDB(reloadCtx); err != nil {
		return err
	}

	c.StartBackgroundTasks(reloadCtx)

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
				!anonymousPolicyExists(c.Config.AccessControl) {
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

func (c *Controller) CreateMetadataDatabaseDriver(cfg *config.Config,
	log log.Logger,
) *meta.MetadataStore {
	var metastore meta.MetadataStore

	if cfg.Extensions != nil && cfg.Extensions.Metadata != nil {
		metastore, _ = meta.FactoryBaseMetaDB(*cfg.Extensions.Metadata, log)
	}

	return &metastore
}

func (c *Controller) InitImageStore(ctx context.Context) error {
	c.StoreController = storage.StoreController{}

	linter := ext.GetLinter(c.Config, c.Log)

	if c.Config.Storage.RootDirectory != "" {
		// no need to validate hard links work on s3
		if c.Config.Storage.Dedupe && c.Config.Storage.StorageDriver == nil {
			err := local.ValidateHardLink(c.Config.Storage.RootDirectory)
			if err != nil {
				c.Log.Warn().Msg("input storage root directory filesystem does not supports hardlinking," +
					"disabling dedupe functionality")

				c.Config.Storage.Dedupe = false
			}
		}

		var defaultStore storage.ImageStore
		if c.Config.Storage.StorageDriver == nil {
			// false positive lint - linter does not implement Lint method
			//nolint:typecheck,contextcheck
			defaultStore = local.NewImageStore(c.Config.Storage.RootDirectory,
				c.Config.Storage.GC, c.Config.Storage.GCDelay,
				c.Config.Storage.Dedupe, c.Config.Storage.Commit, c.Log, c.Metrics, linter,
				CreateCacheDatabaseDriver(c.Config.Storage.StorageConfig, c.Log),
			)
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

			// false positive lint - linter does not implement Lint method
			//nolint: typecheck,contextcheck
			defaultStore = s3.NewImageStore(rootDir, c.Config.Storage.RootDirectory,
				c.Config.Storage.GC, c.Config.Storage.GCDelay, c.Config.Storage.Dedupe,
				c.Config.Storage.Commit, c.Log, c.Metrics, linter, store,
				CreateCacheDatabaseDriver(c.Config.Storage.StorageConfig, c.Log))
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

			//nolint: contextcheck
			subImageStore, err := c.getSubStore(subPaths, linter)
			if err != nil {
				c.Log.Error().Err(err).Msg("controller: error getting sub image store")

				return err
			}

			c.StoreController.SubStore = subImageStore
		}
	}

	return nil
}

func (c *Controller) getSubStore(subPaths map[string]config.StorageConfig,
	linter storage.Lint,
) (map[string]storage.ImageStore, error) {
	imgStoreMap := make(map[string]storage.ImageStore, 0)

	subImageStore := make(map[string]storage.ImageStore)

	// creating image store per subpaths
	for route, storageConfig := range subPaths {
		// no need to validate hard links work on s3
		if storageConfig.Dedupe && storageConfig.StorageDriver == nil {
			err := local.ValidateHardLink(storageConfig.RootDirectory)
			if err != nil {
				c.Log.Warn().Msg("input storage root directory filesystem does not supports hardlinking, " +
					"disabling dedupe functionality")

				storageConfig.Dedupe = false
			}
		}

		if storageConfig.StorageDriver == nil {
			// Compare if subpath root dir is same as default root dir
			isSame, _ := config.SameFile(c.Config.Storage.RootDirectory, storageConfig.RootDirectory)

			if isSame {
				c.Log.Error().Err(errors.ErrBadConfig).Msg("sub path storage directory is same as root directory")

				return nil, errors.ErrBadConfig
			}

			isUnique := true

			// Compare subpath unique files
			for file := range imgStoreMap {
				// We already have image storage for this file
				if compareImageStore(file, storageConfig.RootDirectory) {
					subImageStore[route] = imgStoreMap[file]

					isUnique = true
				}
			}

			// subpath root directory is unique
			// add it to uniqueSubFiles
			// Create a new image store and assign it to imgStoreMap
			if isUnique {
				imgStoreMap[storageConfig.RootDirectory] = local.NewImageStore(storageConfig.RootDirectory,
					storageConfig.GC, storageConfig.GCDelay, storageConfig.Dedupe,
					storageConfig.Commit, c.Log, c.Metrics, linter, CreateCacheDatabaseDriver(storageConfig, c.Log))

				subImageStore[route] = imgStoreMap[storageConfig.RootDirectory]
			}
		} else {
			storeName := fmt.Sprintf("%v", storageConfig.StorageDriver["name"])
			if storeName != storage.S3StorageDriverName {
				c.Log.Fatal().Err(errors.ErrBadConfig).Msgf("unsupported storage driver: %s", storageConfig.StorageDriver["name"])
			}

			// Init a Storager from connection string.
			store, err := factory.Create(storeName, storageConfig.StorageDriver)
			if err != nil {
				c.Log.Error().Err(err).Str("rootDir", storageConfig.RootDirectory).Msg("Unable to create s3 service")

				return nil, err
			}

			/* in the case of s3 c.Config.Storage.RootDirectory is used for caching blobs locally and
			c.Config.Storage.StorageDriver["rootdirectory"] is the actual rootDir in s3 */
			rootDir := "/"
			if c.Config.Storage.StorageDriver["rootdirectory"] != nil {
				rootDir = fmt.Sprintf("%v", c.Config.Storage.StorageDriver["rootdirectory"])
			}

			// false positive lint - linter does not implement Lint method
			//nolint: typecheck
			subImageStore[route] = s3.NewImageStore(rootDir, storageConfig.RootDirectory,
				storageConfig.GC, storageConfig.GCDelay,
				storageConfig.Dedupe, storageConfig.Commit, c.Log, c.Metrics, linter, store,
				CreateCacheDatabaseDriver(storageConfig, c.Log),
			)
		}
	}

	return subImageStore, nil
}

func compareImageStore(root1, root2 string) bool {
	isSameFile, err := config.SameFile(root1, root2)
	// This error is path error that means either of root directory doesn't exist, in that case do string match
	if err != nil {
		return strings.EqualFold(root1, root2)
	}

	return isSameFile
}

func getUseRelPaths(storageConfig *config.StorageConfig) bool {
	return storageConfig.StorageDriver == nil
}

func CreateCacheDatabaseDriver(storageConfig config.StorageConfig, log log.Logger) cache.Cache {
	if storageConfig.Dedupe {
		if !storageConfig.RemoteCache {
			params := cache.BoltDBDriverParameters{}
			params.RootDir = storageConfig.RootDirectory
			params.Name = constants.BoltdbName
			params.UseRelPaths = getUseRelPaths(&storageConfig)

			driver, _ := storage.Create("boltdb", params, log)

			return driver
		}

		// remote cache
		if storageConfig.CacheDriver != nil {
			name, ok := storageConfig.CacheDriver["name"].(string)
			if !ok {
				log.Warn().Msg("remote cache driver name missing!")

				return nil
			}

			if name != constants.DynamoDBDriverName {
				log.Warn().Str("driver", name).Msg("remote cache driver unsupported!")

				return nil
			}

			// dynamodb
			dynamoParams := cache.DynamoDBDriverParameters{}
			dynamoParams.Endpoint, _ = storageConfig.CacheDriver["endpoint"].(string)
			dynamoParams.Region, _ = storageConfig.CacheDriver["region"].(string)
			dynamoParams.TableName, _ = storageConfig.CacheDriver["cachetablename"].(string)

			driver, _ := storage.Create("dynamodb", dynamoParams, log)

			return driver
		}

		return nil
	}

	return nil
}

func (c *Controller) InitRepoDB(reloadCtx context.Context) error {
	if c.Config.Extensions != nil && c.Config.Extensions.Search != nil && *c.Config.Extensions.Search.Enable {
		driver, err := CreateRepoDBDriver(c.Config.Storage.StorageConfig, c.Log) //nolint:contextcheck
		if err != nil {
			return err
		}

		err = driver.PatchDB()
		if err != nil {
			return err
		}

		err = repodb.SyncRepoDB(driver, c.StoreController, c.Log)
		if err != nil {
			return err
		}

		c.RepoDB = driver
	}

	return nil
}

func CreateRepoDBDriver(storageConfig config.StorageConfig, log log.Logger) (repodb.RepoDB, error) {
	if storageConfig.RemoteCache {
		dynamoParams := getDynamoParams(storageConfig.CacheDriver, log)

		return repodbfactory.Create("dynamodb", dynamoParams) //nolint:contextcheck
	}

	params := bolt.DBParameters{}
	params.RootDir = storageConfig.RootDirectory

	return repodbfactory.Create("boltdb", params) //nolint:contextcheck
}

func getDynamoParams(cacheDriverConfig map[string]interface{}, log log.Logger) dynamoParams.DBDriverParameters {
	allParametersOk := true

	endpoint, ok := toStringIfOk(cacheDriverConfig, "endpoint", log)
	allParametersOk = allParametersOk && ok

	region, ok := toStringIfOk(cacheDriverConfig, "region", log)
	allParametersOk = allParametersOk && ok

	repoMetaTablename, ok := toStringIfOk(cacheDriverConfig, "repometatablename", log)
	allParametersOk = allParametersOk && ok

	manifestDataTablename, ok := toStringIfOk(cacheDriverConfig, "manifestdatatablename", log)
	allParametersOk = allParametersOk && ok

	versionTablename, ok := toStringIfOk(cacheDriverConfig, "versiontablename", log)
	allParametersOk = allParametersOk && ok

	if !allParametersOk {
		panic("dynamo parameters are not specified correctly, can't proceede")
	}

	return dynamoParams.DBDriverParameters{
		Endpoint:              endpoint,
		Region:                region,
		RepoMetaTablename:     repoMetaTablename,
		ManifestDataTablename: manifestDataTablename,
		VersionTablename:      versionTablename,
	}
}

func toStringIfOk(cacheDriverConfig map[string]interface{}, param string, log log.Logger) (string, bool) {
	val, ok := cacheDriverConfig[param]

	if !ok {
		log.Error().Msgf("parsing CacheDriver config failed, field '%s' is not present", param)

		return "", false
	}

	str, ok := val.(string)

	if !ok {
		log.Error().Msgf("parsing CacheDriver config failed, parameter '%s' isn't a string", param)

		return "", false
	}

	if str == "" {
		log.Error().Msgf("parsing CacheDriver config failed, field '%s' is is empty", param)

		return "", false
	}

	return str, ok
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
	taskScheduler := scheduler.NewScheduler(c.Log)
	taskScheduler.RunScheduler(reloadCtx)

	// Enable running garbage-collect periodically for DefaultStore
	if c.Config.Storage.GC && c.Config.Storage.GCInterval != 0 {
		c.StoreController.DefaultStore.RunGCPeriodically(c.Config.Storage.GCInterval, taskScheduler)
	}

	// Enable extensions if extension config is provided for DefaultStore
	if c.Config != nil && c.Config.Extensions != nil {
		ext.EnableMetricsExtension(c.Config, c.Log, c.Config.Storage.RootDirectory)
		ext.EnableSearchExtension(c.Config, c.StoreController, c.RepoDB, c.Log)
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
		}
	}

	// Enable extensions if extension config is provided for storeController
	if c.Config.Extensions != nil {
		if c.Config.Extensions.Sync != nil {
			ext.EnableSyncExtension(reloadCtx, c.Config, c.wgShutDown, c.StoreController, c.Log)
		}
	}

	if c.Config.Extensions != nil {
		ext.EnableScrubExtension(c.Config, c.Log, c.StoreController, taskScheduler)
	}
}
