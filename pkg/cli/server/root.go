package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/go-viper/mapstructure/v2"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/pkg/extensions/config/events"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
)

var logger = zlog.NewLogger("info", "") // Global logger for configuration validation

// metadataConfig reports metadata after parsing, which we use to track
// errors.
func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}

func newServeCmd(conf *config.Config) *cobra.Command {
	// "serve"
	serveCmd := &cobra.Command{
		Use:     "serve <config>",
		Aliases: []string{"serve"},
		Short:   "`serve` stores and distributes OCI images",
		Long:    "`serve` stores and distributes OCI images",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")
			
			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					return err
				}
			}

			ctlr := api.NewController(conf)

			ldapCredentials := ""

			if conf.HTTP.Auth != nil && conf.HTTP.Auth.LDAP != nil {
				ldapCredentials = conf.HTTP.Auth.LDAP.CredentialsFile
			}
			// config reloader
			hotReloader, err := NewHotReloader(ctlr, args[0], ldapCredentials)
			if err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to create a new hot reloader")

				return err
			}

			hotReloader.Start()

			if err := ctlr.Init(); err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to init controller")

				return err
			}

			initShutDownRoutine(ctlr)

			if err := ctlr.Run(); err != nil {
				logger.Error().Err(err).Msg("failed to start controller, exiting")
			}

			return nil
		},
	}

	return serveCmd
}

func newScrubCmd(conf *config.Config) *cobra.Command {
	// "scrub"
	scrubCmd := &cobra.Command{
		Use:     "scrub <config>",
		Aliases: []string{"scrub"},
		Short:   "`scrub` checks manifest/blob integrity",
		Long:    "`scrub` checks manifest/blob integrity",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")
			
			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					return err
				}
			} else {
				if err := cmd.Usage(); err != nil {
					return err
				}

				return nil
			}

			// Do not show usage on errors which are not related to cummand line arguments
			cmd.SilenceUsage = true

			// checking if the server is  already running
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodGet,
				fmt.Sprintf("http://%s/v2", net.JoinHostPort(conf.HTTP.Address, conf.HTTP.Port)),
				nil)
			if err != nil {
				logger.Error().Err(err).Msg("failed to create a new http request")

				return err
			}

			response, err := http.DefaultClient.Do(req)
			if err == nil {
				response.Body.Close()
				logger.Warn().Err(zerr.ErrServerIsRunning).
					Msg("server is running, in order to perform the scrub command the server should be shut down")

				return zerr.ErrServerIsRunning
			} else {
				// server is down
				ctlr := api.NewController(conf)
				ctlr.Metrics = monitoring.NewMetricsServer(false, ctlr.Log)

				if err := ctlr.InitImageStore(); err != nil {
					return err
				}

				result, err := ctlr.StoreController.CheckAllBlobsIntegrity(cmd.Context())
				if err != nil {
					return err
				}

				result.PrintScrubResults(cmd.OutOrStdout())
			}

			return nil
		},
	}

	return scrubCmd
}

func newVerifyCmd(conf *config.Config) *cobra.Command {
	// verify
	verifyCmd := &cobra.Command{
		Use:     "verify <config>",
		Aliases: []string{"verify"},
		Short:   "`verify` validates a zot config file",
		Long:    "`verify` validates a zot config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")
			
			if len(args) > 0 {
				cmd.SilenceUsage = true

				if err := LoadConfiguration(conf, args[0]); err != nil {
					logger.Error().Str("config", args[0]).Msg("invalid config file")

					return err
				}

				logger.Info().Str("config", args[0]).Msg("config file is valid")
			}

			return nil
		},
	}

	return verifyCmd
}

// "zot" - registry server.
func NewServerRootCmd() *cobra.Command {
	showVersion := false
	conf := config.New()

	rootCmd := &cobra.Command{
		Use:   "zot",
		Short: "`zot`",
		Long:  "`zot`",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := zlog.NewLogger("info", "")
			
			if showVersion {
				logger.Info().Str("distribution-spec", distspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Str("go version", config.GoVersion).Msg("version")
			} else {
				_ = cmd.Usage()
				cmd.SilenceErrors = false
			}

			return nil
		},
	}

	// "serve"
	rootCmd.AddCommand(newServeCmd(conf))
	// "verify"
	rootCmd.AddCommand(newVerifyCmd(conf))
	// "scrub"
	rootCmd.AddCommand(newScrubCmd(conf))
	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}

func validateStorageConfig(cfg *config.Config, log zlog.Logger) error {
	expConfigMap := make(map[string]config.StorageConfig, 0)

	defaultRootDir := cfg.Storage.RootDirectory

	for _, storageConfig := range cfg.Storage.SubPaths {
		if strings.EqualFold(defaultRootDir, storageConfig.RootDirectory) {
			msg := "invalid storage config, storage subpaths cannot use default storage root directory"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		expConfig, ok := expConfigMap[storageConfig.RootDirectory]
		if ok {
			equal := expConfig.ParamsEqual(storageConfig)
			if !equal {
				msg := "invalid storage config, storage config with same root directory should have same parameters"
				logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}
		} else {
			expConfigMap[storageConfig.RootDirectory] = storageConfig
		}
	}

	return nil
}

func validateCacheConfig(cfg *config.Config, log zlog.Logger) error {
	// global
	// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
	//nolint: lll
	if cfg.Storage.Dedupe && cfg.Storage.StorageDriver != nil && cfg.Storage.RemoteCache && cfg.Storage.CacheDriver == nil {
		msg := "invalid database config, dedupe set to true with remote storage and database, but no remote database configured"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if cfg.Storage.CacheDriver != nil && cfg.Storage.RemoteCache {
		// local storage with remote database
		// redis is supported with both local and S3 storage, while dynamodb is only supported with S3
		// redis is only supported with local storage in a non-clustering scenario with a single zot instance,
		if cfg.Storage.StorageDriver == nil && cfg.Storage.CacheDriver["name"] != storageConstants.RedisDriverName {
			msg := "invalid database config, cannot have local storage driver with remote database!"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		// unsupported database driver
		if cfg.Storage.CacheDriver["name"] != storageConstants.DynamoDBDriverName &&
			cfg.Storage.CacheDriver["name"] != storageConstants.RedisDriverName {
			msg := "invalid database config, unsupported database driver"
			logger.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", cfg.Storage.CacheDriver["name"]).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	if !cfg.Storage.RemoteCache && cfg.Storage.CacheDriver != nil {
		logger.Warn().Err(zerr.ErrBadConfig).Str("directory", cfg.Storage.RootDirectory).
			Msg("invalid database config, remoteCache set to false but cacheDriver config (remote database)" +
				" provided for directory will ignore and use local database")
	}

	// subpaths
	for _, subPath := range cfg.Storage.SubPaths {
		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		//nolint: lll
		if subPath.Dedupe && subPath.StorageDriver != nil && subPath.RemoteCache && subPath.CacheDriver == nil {
			msg := "invalid database config, dedupe set to true with remote storage and database, but no remote database configured!"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		if subPath.CacheDriver != nil && subPath.RemoteCache {
			// local storage with remote caching
			if subPath.StorageDriver == nil {
				msg := "invalid database config, cannot have local storage driver with remote database!"
				logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}

			// unsupported cache driver
			if subPath.CacheDriver["name"] != storageConstants.DynamoDBDriverName {
				msg := "invalid database config, unsupported database driver"
				logger.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", cfg.Storage.CacheDriver["name"]).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}
		}

		if !subPath.RemoteCache && subPath.CacheDriver != nil {
			logger.Warn().Err(zerr.ErrBadConfig).Str("directory", cfg.Storage.RootDirectory).
				Msg("invalid database config, remoteCache set to false but cacheDriver config (remote database)" +
					"provided for directory, will ignore and use local database")
		}
	}

	return nil
}

func validateExtensionsConfig(cfg *config.Config, log zlog.Logger) error {
	if cfg.Extensions != nil && cfg.Extensions.Mgmt != nil {
		logger.Warn().Msg("mgmt extensions configuration option has been made redundant and will be ignored.")
	}

	if cfg.Extensions != nil && cfg.Extensions.APIKey != nil {
		logger.Warn().Msg("apikey extension configuration will be ignored as API keys " +
			"are now configurable in the HTTP settings.")
	}

	if cfg.Extensions != nil && cfg.Extensions.UI != nil && cfg.Extensions.UI.Enable != nil && *cfg.Extensions.UI.Enable {
		// it would make sense to also check for mgmt and user prefs to be enabled,
		// but those are both enabled by having the search and ui extensions enabled
		if cfg.Extensions.Search == nil || !*cfg.Extensions.Search.Enable {
			msg := "failed to enable ui, search extension must be enabled"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	//nolint:lll
	if cfg.Storage.StorageDriver != nil && cfg.Extensions != nil && cfg.Extensions.Search != nil &&
		cfg.Extensions.Search.Enable != nil && *cfg.Extensions.Search.Enable && cfg.Extensions.Search.CVE != nil {
		msg := "failed to enable cve scanning due to incompatibility with remote storage, please disable cve"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	for _, subPath := range cfg.Storage.SubPaths {
		//nolint:lll
		if subPath.StorageDriver != nil && cfg.Extensions != nil && cfg.Extensions.Search != nil &&
			cfg.Extensions.Search.Enable != nil && *cfg.Extensions.Search.Enable && cfg.Extensions.Search.CVE != nil {
			msg := "failed to enable cve scanning due to incompatibility with remote storage, please disable cve"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}

func validateConfiguration(config *config.Config, log zlog.Logger) error {
	if err := validateHTTP(config, log); err != nil {
		return err
	}

	if err := validateGC(config, log); err != nil {
		return err
	}

	if err := validateLDAP(config, log); err != nil {
		return err
	}

	if err := validateOpenIDConfig(config, log); err != nil {
		return err
	}

	if err := validateSync(config, log); err != nil {
		return err
	}

	if err := validateStorageConfig(config, log); err != nil {
		return err
	}

	if err := validateCacheConfig(config, log); err != nil {
		return err
	}

	if err := validateExtensionsConfig(config, log); err != nil {
		return err
	}

	// check authorization config, it should have basic auth enabled or ldap, api keys or OpenID
	if config.HTTP.AccessControl != nil {
		// checking for anonymous policy only authorization config: no users, no policies but anonymous policy
		if err := validateAuthzPolicies(config, log); err != nil {
			return err
		}
	}

	if len(config.Storage.StorageDriver) != 0 {
		// enforce s3 driver in case of using storage driver
		if config.Storage.StorageDriver["name"] != storageConstants.S3StorageDriverName {
			msg := "unsupported storage driver"
			logger.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", config.Storage.StorageDriver["name"]).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		// enforce tmpDir in case sync + s3
		if config.Extensions != nil && config.Extensions.Sync != nil && config.Extensions.Sync.DownloadDir == "" {
			msg := "using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	// enforce s3 driver on subpaths in case of using storage driver
	if config.Storage.SubPaths != nil {
		if len(config.Storage.SubPaths) > 0 {
			subPaths := config.Storage.SubPaths

			for route, storageConfig := range subPaths {
				if len(storageConfig.StorageDriver) != 0 {
					if storageConfig.StorageDriver["name"] != storageConstants.S3StorageDriverName {
						msg := "unsupported storage driver"
						logger.Error().Err(zerr.ErrBadConfig).Str("subpath", route).Interface("storageDriver",
							storageConfig.StorageDriver["name"]).Msg(msg)

						return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
					}

					// enforce tmpDir in case sync + s3
					if config.Extensions != nil && config.Extensions.Sync != nil && config.Extensions.Sync.DownloadDir == "" {
						msg := "using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified"
						logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

						return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
					}
				}
			}
		}
	}

	// check glob patterns in authz config are compilable
	if config.HTTP.AccessControl != nil {
		for pattern := range config.HTTP.AccessControl.Repositories {
			ok := glob.ValidatePattern(pattern)
			if !ok {
				msg := "failed to compile authorization pattern"
				logger.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).Msg(msg)

				return fmt.Errorf("%w: %s", glob.ErrBadPattern, msg)
			}
		}
	}

	// check validity of scale out cluster config
	if err := validateClusterConfig(config, log); err != nil {
		return err
	}

	return nil
}

func validateOpenIDConfig(cfg *config.Config, log zlog.Logger) error {
	if cfg.HTTP.Auth != nil && cfg.HTTP.Auth.OpenID != nil {
		for provider, providerConfig := range cfg.HTTP.Auth.OpenID.Providers {
			//nolint: gocritic
			if config.IsOpenIDSupported(provider) {
				if providerConfig.ClientID == "" || providerConfig.Issuer == "" ||
					len(providerConfig.Scopes) == 0 {
					msg := "OpenID provider config requires clientid, issuer and scopes parameters"
					logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

					return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
				}
			} else if config.IsOauth2Supported(provider) {
				if providerConfig.ClientID == "" || len(providerConfig.Scopes) == 0 {
					msg := "OAuth2 provider config requires clientid and scopes parameters"
					logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

					return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
				}
			} else {
				msg := "unsupported openid/oauth2 provider"
				logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}
		}
	}

	return nil
}

func validateAuthzPolicies(config *config.Config, log zlog.Logger) error {
	if (config.HTTP.Auth == nil || (config.HTTP.Auth.HTPasswd.Path == "" && config.HTTP.Auth.LDAP == nil &&
		config.HTTP.Auth.OpenID == nil)) && !authzContainsOnlyAnonymousPolicy(config) {
		msg := "access control config requires one of httpasswd, ldap or openid authentication " +
			"or using only 'anonymousPolicy' policies"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	return nil
}

//nolint:gocyclo,cyclop,nestif
func applyDefaultValues(config *config.Config, viperInstance *viper.Viper, log zlog.Logger) {
	defaultVal := true

	if config.Extensions == nil && viperInstance.Get("extensions") != nil {
		config.Extensions = &extconf.ExtensionConfig{}

		extMap := viperInstance.GetStringMap("extensions")
		_, ok := extMap["metrics"]

		if ok {
			// we found a config like `"extensions": {"metrics": {}}`
			// Note: In case metrics is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Metrics = &extconf.MetricsConfig{}
		}

		_, ok = extMap["search"]
		if ok {
			// we found a config like `"extensions": {"search": {}}`
			// Note: In case search is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Search = &extconf.SearchConfig{}
		}

		_, ok = extMap["scrub"]
		if ok {
			// we found a config like `"extensions": {"scrub:": {}}`
			// Note: In case scrub is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Scrub = &extconf.ScrubConfig{}
		}

		_, ok = extMap["trust"]
		if ok {
			// we found a config like `"extensions": {"trust:": {}}`
			// Note: In case trust is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.Trust = &extconf.ImageTrustConfig{}
		}

		_, ok = extMap["ui"]
		if ok {
			// we found a config like `"extensions": {"ui:": {}}`
			// Note: In case UI is not empty the config.Extensions will not be nil and we will not reach here
			config.Extensions.UI = &extconf.UIConfig{}
		}
	}

	if config.Extensions != nil {
		if config.Extensions.Sync != nil {
			if config.Extensions.Sync.Enable == nil {
				config.Extensions.Sync.Enable = &defaultVal
			}

			for id, regCfg := range config.Extensions.Sync.Registries {
				if regCfg.TLSVerify == nil {
					config.Extensions.Sync.Registries[id].TLSVerify = &defaultVal
				}
			}
		}

		if config.Extensions.Search != nil {
			if config.Extensions.Search.Enable == nil {
				config.Extensions.Search.Enable = &defaultVal
			}

			if *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
				defaultUpdateInterval, _ := time.ParseDuration("2h")

				if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
					config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

					logger.Warn().Msg("cve update interval set to too-short interval < 2h, " +
						"changing update duration to 2 hours and continuing.")
				}

				if config.Extensions.Search.CVE.Trivy == nil {
					config.Extensions.Search.CVE.Trivy = &extconf.TrivyConfig{}
				}

				if config.Extensions.Search.CVE.Trivy.DBRepository == "" {
					defaultDBDownloadURL := "ghcr.io/aquasecurity/trivy-db"
					logger.Info().Str("url", defaultDBDownloadURL).Str("component", "config").
						Msg("using default trivy-db download URL.")

					config.Extensions.Search.CVE.Trivy.DBRepository = defaultDBDownloadURL
				}

				if config.Extensions.Search.CVE.Trivy.JavaDBRepository == "" {
					defaultJavaDBDownloadURL := "ghcr.io/aquasecurity/trivy-java-db"
					logger.Info().Str("url", defaultJavaDBDownloadURL).Str("component", "config").
						Msg("using default trivy-java-db download URL.")

					config.Extensions.Search.CVE.Trivy.JavaDBRepository = defaultJavaDBDownloadURL
				}
			}
		}

		if config.Extensions.Metrics != nil {
			if config.Extensions.Metrics.Enable == nil {
				config.Extensions.Metrics.Enable = &defaultVal
			}

			if config.Extensions.Metrics.Prometheus == nil {
				config.Extensions.Metrics.Prometheus = &extconf.PrometheusConfig{Path: constants.DefaultMetricsExtensionRoute}
			}
		}

		if config.Extensions.Scrub != nil {
			if config.Extensions.Scrub.Enable == nil {
				config.Extensions.Scrub.Enable = &defaultVal
			}

			if config.Extensions.Scrub.Interval == 0 {
				config.Extensions.Scrub.Interval = 24 * time.Hour //nolint:mnd
			}
		}

		if config.Extensions.UI != nil {
			if config.Extensions.UI.Enable == nil {
				config.Extensions.UI.Enable = &defaultVal
			}
		}

		if config.Extensions.Trust != nil {
			if config.Extensions.Trust.Enable == nil {
				config.Extensions.Trust.Enable = &defaultVal
			}
		}
	}

	// set default values in case GC is disabled
	if !config.Storage.GC {
		if viperInstance.Get("storage::gcdelay") == nil {
			config.Storage.GCDelay = 0
		}

		if viperInstance.Get("storage::retention::delay") == nil {
			config.Storage.Retention.Delay = 0
		}

		if viperInstance.Get("storage::gcinterval") == nil {
			config.Storage.GCInterval = 0
		}
	}

	// apply deleteUntagged default
	for idx := range config.Storage.Retention.Policies {
		if !viperInstance.IsSet("storage::retention::policies::" + strconv.Itoa(idx) + "::deleteUntagged") {
			config.Storage.Retention.Policies[idx].DeleteUntagged = &defaultVal
		}
	}

	// cache settings

	// global storage

	// if dedupe is true but remoteCache bool not set in config file
	// for cloud based storage, remoteCache defaults to true
	if config.Storage.Dedupe && !viperInstance.IsSet("storage::remotecache") && config.Storage.StorageDriver != nil {
		config.Storage.RemoteCache = true
	}

	if config.Storage.StorageDriver != nil {
		// s3 dedup=false, check for previous dedupe usage and set to true if cachedb found
		if !config.Storage.Dedupe {
			cacheDir, _ := config.Storage.StorageDriver["rootdirectory"].(string)
			cachePath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

			if _, err := os.Stat(cachePath); err == nil {
				logger.Info().Str("component", "config").Msg("dedupe set to false for s3 driver but used to be true.")
				logger.Info().Str("cache path", cachePath).Msg("found cache database")

				config.Storage.RemoteCache = false
			}
		}

		// backward compatibility for s3 storage driver
		// if regionendpoint is provided, forcepathstyle should be set to true
		// ref: https://github.com/distribution/distribution/pull/4291
		if config.Storage.StorageDriver["name"] == storageConstants.S3StorageDriverName {
			_, hasRegionEndpoint := config.Storage.StorageDriver["regionendpoint"]
			_, hasForcePathStyle := config.Storage.StorageDriver["forcepathstyle"]

			if hasRegionEndpoint && !hasForcePathStyle {
				logger.Warn().
					Msg("deprecated: automatically setting forcepathstyle to true for s3 storage driver.")
				config.Storage.StorageDriver["forcepathstyle"] = true
			}
		}
	}

	// subpaths
	for name, storageConfig := range config.Storage.SubPaths {
		// if dedupe is true but remoteCache bool not set in config file
		// for cloud based storage, remoteCache defaults to true
		if storageConfig.Dedupe && !viperInstance.IsSet("storage::subpaths::"+name+"::remotecache") && storageConfig.StorageDriver != nil { //nolint:lll
			storageConfig.RemoteCache = true
		}

		// s3 dedup=false, check for previous dedupe usage and set to true if cachedb found
		if !storageConfig.Dedupe && storageConfig.StorageDriver != nil {
			subpathCacheDir, _ := storageConfig.StorageDriver["rootdirectory"].(string)
			subpathCachePath := path.Join(subpathCacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

			if _, err := os.Stat(subpathCachePath); err == nil {
				logger.Info().Str("component", "config").Msg("dedupe set to false for s3 driver but used to be true. ")
				logger.Info().Str("cache path", subpathCachePath).Msg("found cache database")

				storageConfig.RemoteCache = false
			}
		}

		// if gc is enabled
		if storageConfig.GC {
			// and gcDelay is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcdelay") {
				storageConfig.GCDelay = storageConstants.DefaultGCDelay
			}

			// and retentionDelay is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::retention::delay") {
				storageConfig.Retention.Delay = storageConstants.DefaultRetentionDelay
			}

			// and gcInterval is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcinterval") {
				storageConfig.GCInterval = storageConstants.DefaultGCInterval
			}
		}

		// apply deleteUntagged default
		for idx := range storageConfig.Retention.Policies {
			deleteUntaggedKey := fmt.Sprintf("storage::subpaths::%s::retention::policies::%d::deleteUntagged",
				name, idx,
			)
			if !viperInstance.IsSet(deleteUntaggedKey) {
				storageConfig.Retention.Policies[idx].DeleteUntagged = &defaultVal
			}
		}

		config.Storage.SubPaths[name] = storageConfig
	}

	// if OpenID authentication is enabled,
	// API Keys are also enabled in order to provide data path authentication
	if config.HTTP.Auth != nil && config.HTTP.Auth.OpenID != nil {
		config.HTTP.Auth.APIKey = true
	}
}

func updateDistSpecVersion(config *config.Config, log zlog.Logger) {
	if config.DistSpecVersion == distspec.Version {
		return
	}

	logger.Warn().Str("config version", config.DistSpecVersion).Str("supported version", distspec.Version).
		Msg("config dist-spec version differs from version actually used")

	config.DistSpecVersion = distspec.Version
}

func LoadConfiguration(config *config.Config, configPath string) error {
	// Default is dot (.) but because we allow glob patterns in authz
	// we need another key delimiter.
	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))

	ext := filepath.Ext(configPath)
	ext = strings.Replace(ext, ".", "", 1)

	/* if file extension is not supported, try everything
	it's also possible that the filename is starting with a dot eg: ".config". */
	if !common.Contains(viper.SupportedExts, ext) {
		ext = ""
	}

	switch ext {
	case "":
		logger.Info().Str("path", configPath).Msg("config file with no extension, trying all supported config types")

		var err error

		for _, configType := range viper.SupportedExts {
			viperInstance.SetConfigType(configType)
			viperInstance.SetConfigFile(configPath)

			err = viperInstance.ReadInConfig()
			if err == nil {
				break
			}
		}

		if err != nil {
			logger.Error().Err(err).Str("path", configPath).Msg("failed to read configuration, tried all supported config types")

			return err
		}
	default:
		viperInstance.SetConfigFile(configPath)

		if err := viperInstance.ReadInConfig(); err != nil {
			logger.Error().Err(err).Str("path", configPath).Msg("failed to read configuration")

			return err
		}
	}

	metaData := &mapstructure.Metadata{}

	decoderOpts := []viper.DecoderConfigOption{
		metadataConfig(metaData),
		viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				eventsconf.SinkConfigDecoderHook(),
			),
		),
	}

	if err := viperInstance.UnmarshalExact(&config, decoderOpts...); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal new config")

		return err
	}

	log := zlog.NewLogger(config.Log.Level, config.Log.Output)

	if len(metaData.Keys) == 0 {
		msg := "failed to load config due to the absence of any key:value pair"
		logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if len(metaData.Unused) > 0 {
		msg := "failed to load config due to unknown keys"
		logger.Error().Err(zerr.ErrBadConfig).Strs("keys", metaData.Unused).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if err := updateLDAPConfig(config); err != nil {
		logger.Error().Err(err).Msg("failed to read ldap config file")

		return err
	}

	if err := updateOpenIDConfig(config); err != nil {
		logger.Error().Err(err).Msg("failed to read openid provider config file(s)")

		return err
	}

	if err := loadSessionKeys(config); err != nil {
		logger.Error().Err(err).Msg("failed to read sessionKeysFile")

		return err
	}

	// defaults
	applyDefaultValues(config, viperInstance, log)

	// various config checks
	if err := validateConfiguration(config, log); err != nil {
		return err
	}

	// update distSpecVersion
	updateDistSpecVersion(config, log)

	return nil
}

func loadSessionKeys(conf *config.Config) error {
	if conf.HTTP.Auth != nil && conf.HTTP.Auth.SessionKeysFile != "" {
		var sessionKeys config.SessionKeys

		if err := readSecretFile(conf.HTTP.Auth.SessionKeysFile, &sessionKeys, false); err != nil {
			return err
		}

		if sessionKeys.HashKey != "" {
			conf.HTTP.Auth.SessionHashKey = []byte(sessionKeys.HashKey)
		}

		if sessionKeys.EncryptKey != "" {
			conf.HTTP.Auth.SessionEncryptKey = []byte(sessionKeys.EncryptKey)
		}
	}

	return nil
}

func updateLDAPConfig(conf *config.Config) error {
	if conf.HTTP.Auth == nil || conf.HTTP.Auth.LDAP == nil {
		return nil
	}

	if conf.HTTP.Auth.LDAP.CredentialsFile == "" {
		conf.HTTP.Auth.LDAP.SetBindDN("anonym-user")

		return nil
	}

	var newLDAPCredentials config.LDAPCredentials

	if err := readSecretFile(conf.HTTP.Auth.LDAP.CredentialsFile, &newLDAPCredentials, true); err != nil {
		return err
	}

	conf.HTTP.Auth.LDAP.SetBindDN(newLDAPCredentials.BindDN)
	conf.HTTP.Auth.LDAP.SetBindPassword(newLDAPCredentials.BindPassword)

	return nil
}

func updateOpenIDConfig(conf *config.Config) error {
	if conf.HTTP.Auth == nil || conf.HTTP.Auth.OpenID == nil {
		return nil
	}

	for name, provider := range conf.HTTP.Auth.OpenID.Providers {
		if provider.CredentialsFile != "" {
			var newOpenIDCredentials config.OpenIDCredentials

			if err := readSecretFile(provider.CredentialsFile, &newOpenIDCredentials, true); err != nil {
				return err
			}

			provider.ClientID = newOpenIDCredentials.ClientID
			provider.ClientSecret = newOpenIDCredentials.ClientSecret

			conf.HTTP.Auth.OpenID.Providers[name] = provider
		} else {
			logger.Warn().Str("provider", name).
				Msg("deprecated: use the new OpenID provider credentialsfile instead of clientid and clientsecret.")
		}
	}

	return nil
}

func readSecretFile(path string, v any, checkUnsetFields bool) error { //nolint: varnamelen
	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))

	viperInstance.SetConfigFile(path)

	if err := viperInstance.ReadInConfig(); err != nil {
		logger.Error().Err(err).Str("path", path).Msg("failed to read secret file configuration")

		return errors.Join(zerr.ErrBadConfig, err)
	}

	metaData := &mapstructure.Metadata{}
	if err := viperInstance.Unmarshal(v, metadataConfig(metaData)); err != nil {
		logger.Error().Err(err).Str("path", path).Msg("failed to unmarshal secret file config")

		return errors.Join(zerr.ErrBadConfig, err)
	}

	if len(metaData.Keys) == 0 {
		msg := "failed to load secret file due to the absence of any key:value pair"
		logger.Error().Err(zerr.ErrBadConfig).Str("path", path).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if len(metaData.Unused) > 0 {
		msg := "failed to load secret file due to unknown keys"
		logger.Error().Err(zerr.ErrBadConfig).Str("path", path).Strs("keys", metaData.Unused).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	if checkUnsetFields && len(metaData.Unset) > 0 {
		msg := "failed to load secret file due to unset keys"
		logger.Error().Err(zerr.ErrBadConfig).Strs("keys", metaData.Unset).Msg(msg)

		return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
	}

	return nil
}

func authzContainsOnlyAnonymousPolicy(cfg *config.Config) bool {
	adminPolicy := cfg.HTTP.AccessControl.AdminPolicy
	anonymousPolicyPresent := false

	logger.Info().Msg("checking if anonymous authorization is the only type of authorization policy configured")

	if len(adminPolicy.Actions)+len(adminPolicy.Users) > 0 {
		logger.Info().Msg("admin policy detected, anonymous authorization is not the only authorization policy configured")

		return false
	}

	for _, repository := range cfg.HTTP.AccessControl.Repositories {
		if len(repository.DefaultPolicy) > 0 {
			logger.Info().Interface("repository", repository).
				Msg("default policy detected, anonymous authorization is not the only authorization policy configured")

			return false
		}

		if len(repository.AnonymousPolicy) > 0 {
			logger.Info().Msg("anonymous authorization detected")

			anonymousPolicyPresent = true
		}

		for _, policy := range repository.Policies {
			if len(policy.Actions)+len(policy.Users) > 0 {
				logger.Info().Interface("repository", repository).
					Msg("repository with non-empty policy detected, " +
						"anonymous authorization is not the only authorization policy configured")

				return false
			}
		}
	}

	return anonymousPolicyPresent
}

func validateLDAP(config *config.Config, log zlog.Logger) error {
	// LDAP mandatory configuration
	if config.HTTP.Auth != nil && config.HTTP.Auth.LDAP != nil {
		ldap := config.HTTP.Auth.LDAP
		if ldap.UserAttribute == "" {
			msg := "invalid LDAP configuration, missing mandatory key: userAttribute"
			logger.Error().Str("userAttribute", ldap.UserAttribute).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrLDAPConfig, msg)
		}

		if ldap.Address == "" {
			msg := "invalid LDAP configuration, missing mandatory key: address"
			logger.Error().Str("address", ldap.Address).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrLDAPConfig, msg)
		}

		if ldap.BaseDN == "" {
			msg := "invalid LDAP configuration, missing mandatory key: basedn"
			logger.Error().Str("basedn", ldap.BaseDN).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrLDAPConfig, msg)
		}
	}

	return nil
}

func validateHTTP(config *config.Config, log zlog.Logger) error {
	if config.HTTP.Port != "" {
		port, err := strconv.ParseInt(config.HTTP.Port, 10, 64)
		if err != nil || (port < 0 || port > 65535) {
			logger.Error().Str("port", config.HTTP.Port).Msg("invalid port")

			return fmt.Errorf("%w: invalid port %s", zerr.ErrBadConfig, config.HTTP.Port)
		}
	}

	return nil
}

func validateGC(config *config.Config, log zlog.Logger) error {
	// enforce GC params
	if config.Storage.GCDelay < 0 {
		logger.Error().Err(zerr.ErrBadConfig).Dur("delay", config.Storage.GCDelay).
			Msg("invalid garbage-collect delay specified")

		return fmt.Errorf("%w: invalid garbage-collect delay specified %s",
			zerr.ErrBadConfig, config.Storage.GCDelay)
	}

	if config.Storage.GCInterval < 0 {
		logger.Error().Err(zerr.ErrBadConfig).Dur("interval", config.Storage.GCInterval).
			Msg("invalid garbage-collect interval specified")

		return fmt.Errorf("%w: invalid garbage-collect interval specified %s",
			zerr.ErrBadConfig, config.Storage.GCInterval)
	}

	if !config.Storage.GC {
		if config.Storage.GCDelay != 0 {
			logger.Warn().Err(zerr.ErrBadConfig).
				Msg("garbage-collect delay specified without enabling garbage-collect, will be ignored")
		}

		if config.Storage.GCInterval != 0 {
			logger.Warn().Err(zerr.ErrBadConfig).
				Msg("periodic garbage-collect interval specified without enabling garbage-collect, will be ignored")
		}
	}

	if err := validateGCRules(config.Storage.Retention, log); err != nil {
		return err
	}

	// subpaths
	for name, subPath := range config.Storage.SubPaths {
		if subPath.GC && subPath.GCDelay <= 0 {
			logger.Error().Err(zerr.ErrBadConfig).
				Str("subPath", name).
				Interface("gcDelay", subPath.GCDelay).
				Msg("invalid GC delay configuration - cannot be negative or zero")

			return fmt.Errorf("%w: invalid GC delay configuration - cannot be negative or zero: %s",
				zerr.ErrBadConfig, subPath.GCDelay)
		}

		if err := validateGCRules(subPath.Retention, log); err != nil {
			return err
		}
	}

	return nil
}

func validateGCRules(retention config.ImageRetention, log zlog.Logger) error {
	for _, policy := range retention.Policies {
		for _, pattern := range policy.Repositories {
			if ok := glob.ValidatePattern(pattern); !ok {
				logger.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).
					Msg("retention repo glob pattern could not be compiled")

				return fmt.Errorf("%w: retention repo glob pattern could not be compiled: %s",
					zerr.ErrBadConfig, pattern)
			}
		}

		for _, tagRule := range policy.KeepTags {
			for _, regex := range tagRule.Patterns {
				_, err := regexp.Compile(regex)
				if err != nil {
					logger.Error().Err(glob.ErrBadPattern).Str("regex", regex).
						Msg("retention tag regex could not be compiled")

					return fmt.Errorf("%w: retention tag regex could not be compiled: %s",
						zerr.ErrBadConfig, regex)
				}
			}
		}
	}

	return nil
}

func validateSync(config *config.Config, log zlog.Logger) error {
	// check glob patterns in sync config are compilable
	if config.Extensions != nil && config.Extensions.Sync != nil {
		for regID, regCfg := range config.Extensions.Sync.Registries {
			// check retry options are configured for sync
			if regCfg.MaxRetries != nil && regCfg.RetryDelay == nil {
				msg := "retryDelay is required when using maxRetries"
				logger.Error().Err(zerr.ErrBadConfig).Int("id", regID).Interface("extensions.sync.registries[id]",
					config.Extensions.Sync.Registries[regID]).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}

			// check preserveDigest without compat
			if regCfg.PreserveDigest && !config.IsCompatEnabled() {
				msg := "can not use PreserveDigest option without enabling http.Compat"
				logger.Error().Err(zerr.ErrBadConfig).Int("id", regID).Interface("extensions.sync.registries[id]",
					config.Extensions.Sync.Registries[regID]).Msg(msg)

				return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
			}

			if regCfg.Content != nil {
				for _, content := range regCfg.Content {
					ok := glob.ValidatePattern(content.Prefix)
					if !ok {
						msg := "sync prefix could not be compiled"
						logger.Error().Err(glob.ErrBadPattern).Str("prefix", content.Prefix).Msg(msg)

						return fmt.Errorf("%w: %s: %s", zerr.ErrBadConfig, msg, content.Prefix)
					}

					if content.Tags != nil && content.Tags.Regex != nil {
						_, err := regexp.Compile(*content.Tags.Regex)
						if err != nil {
							msg := "sync content regex could not be compiled"
							logger.Error().Err(glob.ErrBadPattern).Str("regex", *content.Tags.Regex).Msg(msg)

							return fmt.Errorf("%w: %s: %s", zerr.ErrBadConfig, msg, *content.Tags.Regex)
						}
					}

					if content.Tags != nil && content.Tags.ExcludeRegex != nil {
						_, err := regexp.Compile(*content.Tags.ExcludeRegex)
						if err != nil {
							msg := "sync content excludeRegex could not be compiled"
							logger.Error().Err(glob.ErrBadPattern).Str("excludeRegex", *content.Tags.ExcludeRegex).Msg(msg)

							return fmt.Errorf("%w: %s: %s", zerr.ErrBadConfig, msg, *content.Tags.ExcludeRegex)
						}
					}

					if content.StripPrefix && !strings.Contains(content.Prefix, "/*") && content.Destination == "/" {
						msg := "can not use stripPrefix true and destination '/' without using glob patterns in prefix"
						logger.Error().Err(zerr.ErrBadConfig).
							Interface("sync content", content).Str("component", "sync").Msg(msg)

						return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
					}

					// check sync config doesn't overlap with retention config
					validateRetentionSyncOverlaps(config, content, regCfg.URLs, log)
				}
			}
		}
	}

	return nil
}

func validateClusterConfig(config *config.Config, log zlog.Logger) error {
	if config.Cluster != nil {
		if len(config.Cluster.Members) == 0 {
			msg := "cannot have 0 members in a scale out cluster"
			logger.Error().Err(zerr.ErrBadConfig).Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}

		// the allowed length is 16 as the siphash requires a 128 bit key.
		// that translates to 16 characters * 8 bits each.
		allowedHashKeyLength := 16
		if len(config.Cluster.HashKey) != allowedHashKeyLength {
			msg := fmt.Sprintf("hashKey for scale out cluster must have %d characters", allowedHashKeyLength)
			logger.Error().Err(zerr.ErrBadConfig).
				Str("hashkey", config.Cluster.HashKey).
				Msg(msg)

			return fmt.Errorf("%w: %s", zerr.ErrBadConfig, msg)
		}
	}

	return nil
}
