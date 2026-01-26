package api

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	goerrors "errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/zitadel/oidc/v3/pkg/client/rp"

	"zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/common"
	ext "zotregistry.dev/zot/v2/pkg/extensions"
	events "zotregistry.dev/zot/v2/pkg/extensions/events"
	monitoring "zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	log "zotregistry.dev/zot/v2/pkg/log"
	meta "zotregistry.dev/zot/v2/pkg/meta"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	scheduler "zotregistry.dev/zot/v2/pkg/scheduler"
	storage "zotregistry.dev/zot/v2/pkg/storage"
	gc "zotregistry.dev/zot/v2/pkg/storage/gc"
)

const (
	idleTimeout       = 120 * time.Second
	readHeaderTimeout = 5 * time.Second
)

type Controller struct {
	Config          *config.Config
	Router          *mux.Router
	MetaDB          mTypes.MetaDB
	StoreController storage.StoreController
	Log             log.Logger
	Audit           *log.Logger
	Server          *http.Server
	Metrics         monitoring.MetricServer
	EventRecorder   events.Recorder
	CveScanner      ext.CveScanner
	SyncOnDemand    SyncOnDemand
	RelyingParties  map[string]rp.RelyingParty
	CookieStore     *CookieStore
	HTPasswd        *HTPasswd
	HTPasswdWatcher *HTPasswdWatcher
	LDAPClient      *LDAPClient
	taskScheduler   *scheduler.Scheduler
	Healthz         *common.Healthz
	// runtime params
	chosenPort int // kernel-chosen port
}

func NewController(appConfig *config.Config) *Controller {
	var controller Controller

	logger := log.NewLogger(appConfig.Log.Level, appConfig.Log.Output)
	controller.Healthz = common.NewHealthzServer(appConfig, logger)

	if appConfig.Cluster != nil {
		// we need the set of local sockets (IP address:port) for identifying
		// the local member cluster socket for logging and lookup.
		localSockets, err := common.GetLocalSockets(appConfig.HTTP.Port)
		if err != nil {
			logger.Error().Err(err).Msg("failed to get local sockets")
			panic("failed to get local sockets")
		}

		// memberSocket is the local member's socket
		// the index is also fetched for quick lookups during proxying
		memberSocketIdx, memberSocket, err := GetLocalMemberClusterSocket(appConfig.Cluster.Members, localSockets)
		if err != nil {
			logger.Error().Err(err).Msg("failed to get member socket")
			panic("failed to get member socket")
		}

		if memberSocketIdx < 0 || memberSocket == "" {
			// there is a misconfiguration if the memberSocket cannot be identified
			logger.Error().
				Str("members", strings.Join(appConfig.Cluster.Members, ",")).
				Str("localSockets", strings.Join(localSockets, ",")).
				Msg("failed to determine the local cluster socket")
			panic("failed to determine the local cluster socket")
		}

		internalProxyConfig := &config.ClusterRequestProxyConfig{
			LocalMemberClusterSocket:      memberSocket,
			LocalMemberClusterSocketIndex: uint64(memberSocketIdx),
		}
		appConfig.Cluster.Proxy = internalProxyConfig

		logger = logger.With().
			Str("clusterMember", memberSocket).
			Str("clusterMemberIndex", strconv.Itoa(memberSocketIdx)).Logger()
	}

	htp := NewHTPasswd(logger)

	htw, err := NewHTPasswdWatcher(htp, "")
	if err != nil {
		logger.Panic().Err(err).Msg("failed to create htpasswd watcher")
	}

	controller.Config = appConfig
	controller.Log = logger
	controller.HTPasswd = htp
	controller.HTPasswdWatcher = htw

	if appConfig.Log.Audit != "" {
		audit := log.NewAuditLogger(appConfig.Log.Level, appConfig.Log.Audit)
		controller.Audit = audit
	}

	return &controller
}

func (c *Controller) GetPort() int {
	return c.chosenPort
}

func (c *Controller) Run() error {
	if err := c.initCookieStore(); err != nil {
		return err
	}

	c.StartBackgroundTasks()

	// setup HTTP API router
	engine := mux.NewRouter()

	// rate-limit HTTP requests if enabled
	ratelimitConfig := c.Config.CopyRatelimit()
	if ratelimitConfig != nil {
		if ratelimitConfig.Rate != nil {
			engine.Use(RateLimiter(c, *ratelimitConfig.Rate))
		}

		for _, mrlim := range ratelimitConfig.Methods {
			engine.Use(MethodRateLimiter(c, mrlim.Method, mrlim.Rate))
		}
	}

	engine.Use(
		SessionLogger(c),
		RecoveryHandler(c.Log),
	)

	if c.Audit != nil {
		engine.Use(SessionAuditLogger(c.Audit))
	}

	c.Router = engine
	c.Router.UseEncodedPath()

	commit, binaryType, goVersion, distSpecVersion := c.Config.GetVersionInfo()
	monitoring.SetServerInfo(c.Metrics, commit, binaryType, goVersion, distSpecVersion)

	//nolint: contextcheck
	_ = NewRouteHandler(c)

	port := c.Config.GetHTTPPort()
	addr := fmt.Sprintf("%s:%s", c.Config.GetHTTPAddress(), port)
	server := &http.Server{
		Addr:              addr,
		Handler:           c.Router,
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	c.Server = server

	// Create the listener
	listener, err := net.Listen("tcp", addr) //nolint: noctx
	if err != nil {
		return err
	}

	if port == "0" || port == "" {
		chosenAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			c.Log.Error().Str("port", port).Msg("invalid addr type")

			return errors.ErrBadType
		}

		c.chosenPort = chosenAddr.Port

		c.Log.Info().Int("port", chosenAddr.Port).IPAddr("address", chosenAddr.IP).Msg(
			"port is unspecified, listening on kernel chosen port",
		)
	} else {
		chosenPort, _ := strconv.ParseInt(port, 10, 32)

		c.chosenPort = int(chosenPort)
	}

	tlsConfig := c.Config.CopyTLSConfig()
	if tlsConfig != nil && tlsConfig.Key != "" && tlsConfig.Cert != "" {
		// These are the same as the cipher suites in defaultCipherSuitesFIPS for TLS 1.2
		// see https://cs.opensource.google/go/go/+/refs/tags/go1.24.9:src/crypto/tls/defaults.go;l=123
		// Note: Order doesn't matter - Go 1.17+ automatically orders cipher suites based on
		// hardware capabilities and security properties. See https://go.dev/blog/tls-cipher-suites
		cipherSuites := []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
		if !fips140.Enabled() {
			// CHACHA20_POLY1305 is not FIPS-compliant
			cipherSuites = append(cipherSuites,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			)
		}

		// This is a subset of the default curve preferences in defaultCurvePreferencesFIPS for TLS 1.2
		// see https://cs.opensource.google/go/go/+/refs/tags/go1.24.9:src/crypto/tls/defaults.go;l=106
		// P-256, P-384, and P-521 are all FIPS-compliant NIST curves
		curvePreferences := []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
		if !fips140.Enabled() {
			// X25519 is not FIPS-compliant
			curvePreferences = append(curvePreferences, tls.X25519)
		}

		server.TLSConfig = &tls.Config{
			CipherSuites:     cipherSuites,
			CurvePreferences: curvePreferences,
			// PreferServerCipherSuites is ignored in Go 1.17+ - Go automatically orders cipher suites
			MinVersion: tls.VersionTLS12,
		}

		if tlsConfig.CACert != "" {
			caCert, err := os.ReadFile(tlsConfig.CACert)
			if err != nil {
				c.Log.Error().Err(err).Str("caCert", tlsConfig.CACert).Msg("failed to read file")

				return err
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				c.Log.Error().Err(errors.ErrBadCACert).Msg("failed to append certs from pem")

				return errors.ErrBadCACert
			}

			// Use VerifyClientCertIfGiven even if mTLS is enabled: clients without cert will be treated as anonymous
			// You can control permissions for mTLS anonymous requests via accessControl policies
			server.TLSConfig.ClientAuth = tls.VerifyClientCertIfGiven
			server.TLSConfig.ClientCAs = caCertPool
		}

		c.Healthz.Ready()

		return server.ServeTLS(listener, tlsConfig.Cert, tlsConfig.Key)
	}

	c.Healthz.Ready()

	return server.Serve(listener)
}

func (c *Controller) Init() error {
	// report if fips140 mode is enabled
	if fips140.Enabled() {
		c.Log.Info().Msg("fips140 is currently enabled")
	}

	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	// log authentication methods status
	authConfig := c.Config.CopyAuthConfig()
	c.Log.Info().Bool("enabled", authConfig.IsTraditionalBearerAuthEnabled()).Msg("jwt bearer authentication")
	c.Log.Info().Bool("enabled", authConfig.IsOIDCBearerAuthEnabled()).Msg("oidc bearer authentication")
	c.Log.Info().Bool("enabled", authConfig.IsHtpasswdAuthEnabled()).Msg("basic authentication (htpasswd)")
	c.Log.Info().Bool("enabled", authConfig.IsLdapAuthEnabled()).Msg("basic authentication (LDAP)")
	c.Log.Info().Bool("enabled", authConfig.IsAPIKeyEnabled()).Msg("basic authentication (API key)")
	c.Log.Info().Bool("enabled", authConfig.IsOpenIDAuthEnabled()).Msg("OpenID authentication")
	c.Log.Info().Bool("enabled", c.Config.IsMTLSAuthEnabled()).Msg("mutual TLS authentication")

	// print the current runtime environment
	DumpRuntimeParams(c.Log)

	var enabled bool
	extensionsConfig := c.Config.CopyExtensionsConfig()

	if extensionsConfig.IsMetricsEnabled() {
		enabled = true
	}

	c.Metrics = monitoring.NewMetricsServer(enabled, c.Log)

	if err := c.InitEventRecorder(); err != nil {
		return err
	}

	if err := c.InitImageStore(); err != nil { //nolint:contextcheck
		return err
	}

	if err := c.InitMetaDB(); err != nil {
		return err
	}

	c.InitCVEInfo()
	c.Healthz.Started()

	if authConfig.IsHtpasswdAuthEnabled() {
		err := c.HTPasswdWatcher.ChangeFile(authConfig.HTPasswd.Path)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) InitCVEInfo() {
	// Enable CVE extension if extension config is provided
	c.CveScanner = ext.GetCveScanner(c.Config, c.StoreController, c.MetaDB, c.Log)
}

func (c *Controller) InitImageStore() error {
	linter := ext.GetLinter(c.Config, c.Log)

	storeController, err := storage.New(c.Config, linter, c.Metrics, c.Log, c.EventRecorder)
	if err != nil {
		return err
	}

	c.StoreController = storeController

	return nil
}

func (c *Controller) initCookieStore() error {
	// setup sessions cookie store used to preserve logged in user in web sessions
	if c.Config.HTTP.Auth.IsBasicAuthnEnabled() {
		if c.Config.HTTP.Auth.SessionHashKey == nil {
			c.Log.Warn().Msg("hashKey is not set in config, generating a random one")

			key := securecookie.GenerateRandomKey(64) //nolint: gomnd
			c.Config.HTTP.Auth.SessionHashKey = key
		}

		cookieStore, err := NewCookieStore(c.Config.HTTP.Auth, c.StoreController, c.Log)
		if err != nil {
			return err
		}

		c.CookieStore = cookieStore
	}

	return nil
}

func (c *Controller) InitMetaDB() error {
	// init metaDB if search is enabled or we need to store user profiles, api keys or signatures
	// Get auth config safely
	authConfig := c.Config.CopyAuthConfig()
	extensionsConfig := c.Config.CopyExtensionsConfig()

	if extensionsConfig.IsSearchEnabled() || authConfig.IsBasicAuthnEnabled() || extensionsConfig.IsImageTrustEnabled() ||
		c.Config.IsRetentionEnabled() {
		// Get storage config safely
		storageConfig := c.Config.CopyStorageConfig()

		driver, err := meta.New(storageConfig.StorageConfig, c.Log) //nolint:contextcheck
		if err != nil {
			return err
		}

		err = ext.SetupExtensions(c.Config, driver, c.Log) //nolint:contextcheck
		if err != nil {
			return err
		}

		err = driver.PatchDB()
		if err != nil {
			return err
		}

		err = meta.ParseStorage(driver, c.StoreController, c.Log) //nolint: contextcheck
		if err != nil {
			return err
		}

		c.MetaDB = driver
	}

	return nil
}

func (c *Controller) InitEventRecorder() error {
	eventRecorder, err := ext.NewEventRecorder(c.Config, c.Log)
	if err != nil && !goerrors.Is(err, errors.ErrExtensionNotEnabled) {
		return err
	}

	c.EventRecorder = eventRecorder

	return nil
}

func (c *Controller) LoadNewConfig(newConfig *config.Config) {
	// Update only reloadable config fields atomically
	c.Config.UpdateReloadableConfig(newConfig)

	// Operations that need to happen after config update
	authConfig := c.Config.CopyAuthConfig()
	if authConfig.IsHtpasswdAuthEnabled() {
		err := c.HTPasswdWatcher.ChangeFile(authConfig.HTPasswd.Path)
		if err != nil {
			c.Log.Error().Err(err).Msg("failed to change watched htpasswd file")
		}
	} else {
		_ = c.HTPasswdWatcher.ChangeFile("")
	}

	if c.LDAPClient != nil && authConfig.IsLdapAuthEnabled() {
		c.LDAPClient.lock.Lock()
		c.LDAPClient.BindDN = authConfig.LDAP.BindDN()
		c.LDAPClient.BindPassword = authConfig.LDAP.BindPassword()
		c.LDAPClient.lock.Unlock()
	}

	c.InitCVEInfo()

	c.Log.Info().Interface("reloaded params", c.Config.Sanitize()).
		Msg("loaded new configuration settings")

	// log authentication methods status
	c.Log.Info().Bool("enabled", authConfig.IsTraditionalBearerAuthEnabled()).Msg("jwt bearer authentication")
	c.Log.Info().Bool("enabled", authConfig.IsOIDCBearerAuthEnabled()).Msg("oidc bearer authentication")
	c.Log.Info().Bool("enabled", authConfig.IsHtpasswdAuthEnabled()).Msg("basic authentication (htpasswd)")
	c.Log.Info().Bool("enabled", authConfig.IsLdapAuthEnabled()).Msg("basic authentication (LDAP)")
	c.Log.Info().Bool("enabled", authConfig.IsAPIKeyEnabled()).Msg("basic authentication (API key)")
	c.Log.Info().Bool("enabled", authConfig.IsOpenIDAuthEnabled()).Msg("OpenID authentication")
	c.Log.Info().Bool("enabled", c.Config.IsMTLSAuthEnabled()).Msg("mutual TLS authentication")
}

func (c *Controller) Shutdown() {
	// stop all background tasks
	c.StopBackgroundTasks()

	// Stop metrics server to prevent resource leaks (only during full shutdown)
	if c.Metrics != nil {
		c.Metrics.Stop()
	}

	if c.Server != nil {
		ctx := context.Background()
		_ = c.Server.Shutdown(ctx)
	}

	// close metadb
	if c.MetaDB != nil {
		c.MetaDB.Close()
	}
}

// StopBackgroundTasks will stop scheduler and wait for all tasks to finish their work.
func (c *Controller) StopBackgroundTasks() {
	if c.taskScheduler != nil {
		c.taskScheduler.Shutdown()
	}

	// Close HTPasswdWatcher to prevent resource leaks
	if c.HTPasswdWatcher != nil {
		_ = c.HTPasswdWatcher.Close()
	}
}

func (c *Controller) StartBackgroundTasks() {
	c.taskScheduler = scheduler.NewScheduler(c.Config, c.Metrics, c.Log)
	c.taskScheduler.RunScheduler()

	// Start HTPasswdWatcher goroutine
	if c.HTPasswdWatcher != nil {
		c.HTPasswdWatcher.Run()
	}

	// Run GC and retention tasks
	RunGCTasks(c.Config, c.StoreController, c.MetaDB, c.taskScheduler, c.Log, c.Audit)

	// Enable running dedupe blobs both ways (dedupe or restore deduped blobs)
	c.StoreController.DefaultStore.RunDedupeBlobs(time.Duration(0), c.taskScheduler)

	// Always call EnableSearchExtension to ensure proper logging, even when search is disabled
	ext.EnableSearchExtension(c.Config, c.StoreController, c.MetaDB, c.taskScheduler, c.CveScanner, c.Log)

	// Always call EnableMetricsExtension to ensure proper logging, even when metrics is disabled
	storageConfig := c.Config.CopyStorageConfig()
	ext.EnableMetricsExtension(c.Config, c.Log, storageConfig.RootDirectory)

	// runs once if metrics are enabled & imagestore is local
	extensionsConfig := c.Config.CopyExtensionsConfig()
	if extensionsConfig.IsMetricsEnabled() && storageConfig.StorageDriver == nil {
		c.StoreController.DefaultStore.PopulateStorageMetrics(time.Duration(0), c.taskScheduler)
	}

	if storageConfig.SubPaths != nil {
		for route, subStorageConfig := range storageConfig.SubPaths {
			// Enable extensions if extension config is provided for subImageStore
			ext.EnableMetricsExtension(c.Config, c.Log, subStorageConfig.RootDirectory)

			// Enable running dedupe blobs both ways (dedupe or restore deduped blobs) for subpaths
			substore := c.StoreController.SubStore[route]
			if substore != nil {
				substore.RunDedupeBlobs(time.Duration(0), c.taskScheduler)

				if extensionsConfig.IsMetricsEnabled() && storageConfig.StorageDriver == nil {
					substore.PopulateStorageMetrics(time.Duration(0), c.taskScheduler)
				}
			}
		}
	}

	// Always call EnableScrubExtension to ensure proper logging, even when scrub is disabled
	ext.EnableScrubExtension(c.Config, c.Log, c.StoreController, c.taskScheduler)

	// Always call EnableSyncExtension to ensure proper logging, even when sync is disabled
	//nolint: contextcheck
	syncOnDemand, err := ext.EnableSyncExtension(c.Config, c.MetaDB, c.StoreController, c.taskScheduler, c.Log)
	if err != nil {
		c.Log.Error().Err(err).Msg("failed to start sync extension")
	}

	// Only set SyncOnDemand if sync is actually enabled
	if extensionsConfig.IsSyncEnabled() {
		c.SyncOnDemand = syncOnDemand
	}

	if c.CookieStore != nil {
		c.CookieStore.RunSessionCleaner(c.taskScheduler)
	}

	// we can later move enabling the other scheduled tasks inside the call below
	ext.EnableScheduledTasks(c.Config, c.taskScheduler, c.MetaDB, c.Log) //nolint: contextcheck
}

// RunGCTasks runs minimal GC and retention tasks without full controller.
func RunGCTasks(conf *config.Config, storeController storage.StoreController, metaDB mTypes.MetaDB,
	taskScheduler *scheduler.Scheduler, logger log.Logger, audit *log.Logger,
) {
	// Enable running garbage-collect periodically for DefaultStore
	storageConfig := conf.CopyStorageConfig()
	if storageConfig.GC {
		gc := gc.NewGarbageCollect(storeController.DefaultStore, metaDB, gc.Options{
			Delay:             storageConfig.GCDelay,
			ImageRetention:    storageConfig.Retention,
			MaxSchedulerDelay: storageConfig.GCMaxSchedulerDelay,
		}, audit, logger)

		gc.CleanImageStorePeriodically(storageConfig.GCInterval, taskScheduler)
	}

	// Handle subpaths
	if storageConfig.SubPaths != nil {
		for route, subStorageConfig := range storageConfig.SubPaths {
			// Enable running garbage-collect periodically for subImageStore
			if subStorageConfig.GC {
				gc := gc.NewGarbageCollect(storeController.SubStore[route], metaDB,
					gc.Options{
						Delay:             subStorageConfig.GCDelay,
						ImageRetention:    subStorageConfig.Retention,
						MaxSchedulerDelay: subStorageConfig.GCMaxSchedulerDelay,
					}, audit, logger)

				gc.CleanImageStorePeriodically(subStorageConfig.GCInterval, taskScheduler)
			}
		}
	}
}

type SyncOnDemand interface {
	SyncImage(ctx context.Context, repo, reference string) error
	SyncReferrers(ctx context.Context, repo string, subjectDigestStr string, referenceTypes []string) error
}
