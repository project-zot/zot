package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/mitchellh/mapstructure"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
)

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
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					panic(err)
				}
			}

			ctlr := api.NewController(conf)

			// config reloader
			hotReloader, err := NewHotReloader(ctlr, args[0])
			if err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to create a new hot reloader")

				panic(err)
			}

			/* context used to cancel go routines so that
			we can change their config on the fly (restart routines with different config) */
			reloaderCtx := hotReloader.Start()

			if err := ctlr.Init(reloaderCtx); err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to init controller")

				panic(err)
			}

			if err := ctlr.Run(reloaderCtx); err != nil {
				ctlr.Log.Fatal().Err(err).Msg("unable to start controller, exiting")
			}
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
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					panic(err)
				}
			} else {
				if err := cmd.Usage(); err != nil {
					panic(err)
				}

				return
			}

			// checking if the server is  already running
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodGet,
				fmt.Sprintf("http://%s/v2", net.JoinHostPort(conf.HTTP.Address, conf.HTTP.Port)),
				nil)
			if err != nil {
				log.Error().Err(err).Msg("unable to create a new http request")
				panic(err)
			}

			response, err := http.DefaultClient.Do(req)
			if err == nil {
				response.Body.Close()
				log.Warn().Msg("The server is running, in order to perform the scrub command the server should be shut down")
				panic("Error: server is running")
			} else {
				// server is down
				ctlr := api.NewController(conf)
				ctlr.Metrics = monitoring.NewMetricsServer(false, ctlr.Log)

				if err := ctlr.InitImageStore(); err != nil {
					panic(err)
				}

				result, err := ctlr.StoreController.CheckAllBlobsIntegrity(cmd.Context())
				if err != nil {
					panic(err)
				}

				result.PrintScrubResults(cmd.OutOrStdout())
			}
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
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				if err := LoadConfiguration(conf, args[0]); err != nil {
					log.Error().Str("config", args[0]).Msg("Config file is invalid")
					panic(err)
				}

				log.Info().Str("config", args[0]).Msg("Config file is valid")
			}
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
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				log.Info().Str("distribution-spec", distspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Str("go version", config.GoVersion).Msg("version")
			} else {
				_ = cmd.Usage()
				cmd.SilenceErrors = false
			}
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
			log.Error().Err(zerr.ErrBadConfig).Msg("storage subpaths cannot use default storage root directory")

			return zerr.ErrBadConfig
		}

		expConfig, ok := expConfigMap[storageConfig.RootDirectory]
		if ok {
			equal := expConfig.ParamsEqual(storageConfig)
			if !equal {
				log.Error().Err(zerr.ErrBadConfig).Msg("storage config with same root directory should have same parameters")

				return zerr.ErrBadConfig
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
		log.Error().Err(zerr.ErrBadConfig).Msg(
			"dedupe set to true with remote storage and caching, but no remote cache configured!")

		return zerr.ErrBadConfig
	}

	if cfg.Storage.CacheDriver != nil && cfg.Storage.RemoteCache {
		// local storage with remote caching
		if cfg.Storage.StorageDriver == nil {
			log.Error().Err(zerr.ErrBadConfig).Msg("cannot have local storage driver with remote caching!")

			return zerr.ErrBadConfig
		}

		// unsupported cache driver
		if cfg.Storage.CacheDriver["name"] != storageConstants.DynamoDBDriverName {
			log.Error().Err(zerr.ErrBadConfig).
				Interface("cacheDriver", cfg.Storage.CacheDriver["name"]).Msg("unsupported cache driver")

			return zerr.ErrBadConfig
		}
	}

	if !cfg.Storage.RemoteCache && cfg.Storage.CacheDriver != nil {
		log.Warn().Err(zerr.ErrBadConfig).Str("directory", cfg.Storage.RootDirectory).
			Msg("remoteCache set to false but cacheDriver config (remote caching) provided for directory" +
				"will ignore and use local caching")
	}

	// subpaths
	for _, subPath := range cfg.Storage.SubPaths {
		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		//nolint: lll
		if subPath.Dedupe && subPath.StorageDriver != nil && subPath.RemoteCache && subPath.CacheDriver == nil {
			log.Error().Err(zerr.ErrBadConfig).Msg("dedupe set to true with remote storage and caching, but no remote cache configured!")

			return zerr.ErrBadConfig
		}

		if subPath.CacheDriver != nil && subPath.RemoteCache {
			// local storage with remote caching
			if subPath.StorageDriver == nil {
				log.Error().Err(zerr.ErrBadConfig).Msg("cannot have local storage driver with remote caching!")

				return zerr.ErrBadConfig
			}

			// unsupported cache driver
			if subPath.CacheDriver["name"] != storageConstants.DynamoDBDriverName {
				log.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", cfg.Storage.CacheDriver["name"]).
					Msg("unsupported cache driver")

				return zerr.ErrBadConfig
			}
		}

		if !subPath.RemoteCache && subPath.CacheDriver != nil {
			log.Warn().Err(zerr.ErrBadConfig).Str("directory", cfg.Storage.RootDirectory).
				Msg("remoteCache set to false but cacheDriver config (remote caching) provided for directory," +
					"will ignore and use local caching")
		}
	}

	return nil
}

func validateExtensionsConfig(cfg *config.Config, log zlog.Logger) error {
	if cfg.Extensions != nil && cfg.Extensions.Mgmt != nil {
		log.Warn().Msg("The mgmt extensions configuration option has been made redundant and will be ignored.")
	}

	if cfg.Extensions != nil && cfg.Extensions.APIKey != nil {
		log.Warn().Msg("The apikey extension configuration will be ignored as API keys " +
			"are now configurable in the HTTP settings.")
	}

	if cfg.Extensions != nil && cfg.Extensions.UI != nil && cfg.Extensions.UI.Enable != nil && *cfg.Extensions.UI.Enable {
		// it would make sense to also check for mgmt and user prefs to be enabled,
		// but those are both enabled by having the search and ui extensions enabled
		if cfg.Extensions.Search == nil || !*cfg.Extensions.Search.Enable {
			log.Error().Err(zerr.ErrBadConfig).Msg("UI functionality can't be used without search extension.")

			return zerr.ErrBadConfig
		}
	}

	//nolint:lll
	if cfg.Storage.StorageDriver != nil && cfg.Extensions != nil && cfg.Extensions.Search != nil &&
		cfg.Extensions.Search.Enable != nil && *cfg.Extensions.Search.Enable && cfg.Extensions.Search.CVE != nil {
		log.Error().Err(zerr.ErrBadConfig).Msg("CVE functionality can't be used with remote storage. Please disable CVE")

		return zerr.ErrBadConfig
	}

	for _, subPath := range cfg.Storage.SubPaths {
		//nolint:lll
		if subPath.StorageDriver != nil && cfg.Extensions != nil && cfg.Extensions.Search != nil &&
			cfg.Extensions.Search.Enable != nil && *cfg.Extensions.Search.Enable && cfg.Extensions.Search.CVE != nil {
			log.Error().Err(zerr.ErrBadConfig).Msg("CVE functionality can't be used with remote storage. Please disable CVE")

			return zerr.ErrBadConfig
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
			log.Error().Err(zerr.ErrBadConfig).Interface("cacheDriver", config.Storage.StorageDriver["name"]).
				Msg("unsupported storage driver")

			return zerr.ErrBadConfig
		}

		// enforce filesystem storage in case sync feature is enabled
		if config.Extensions != nil && config.Extensions.Sync != nil {
			log.Error().Err(zerr.ErrBadConfig).Msg("sync supports only filesystem storage")

			return zerr.ErrBadConfig
		}
	}

	// enforce s3 driver on subpaths in case of using storage driver
	if config.Storage.SubPaths != nil {
		if len(config.Storage.SubPaths) > 0 {
			subPaths := config.Storage.SubPaths

			for route, storageConfig := range subPaths {
				if len(storageConfig.StorageDriver) != 0 {
					if storageConfig.StorageDriver["name"] != storageConstants.S3StorageDriverName {
						log.Error().Err(zerr.ErrBadConfig).Str("subpath", route).Interface("storageDriver",
							storageConfig.StorageDriver["name"]).Msg("unsupported storage driver")

						return zerr.ErrBadConfig
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
				log.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).Msg("authorization pattern could not be compiled")

				return glob.ErrBadPattern
			}
		}
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
					log.Error().Err(zerr.ErrBadConfig).
						Msg("OpenID provider config requires clientid, issuer and scopes parameters")

					return zerr.ErrBadConfig
				}
			} else if config.IsOauth2Supported(provider) {
				if providerConfig.ClientID == "" || len(providerConfig.Scopes) == 0 {
					log.Error().Err(zerr.ErrBadConfig).
						Msg("OAuth2 provider config requires clientid and scopes parameters")

					return zerr.ErrBadConfig
				}
			} else {
				log.Error().Err(zerr.ErrBadConfig).
					Msg("unsupported openid/oauth2 provider")

				return zerr.ErrBadConfig
			}
		}
	}

	return nil
}

func validateAuthzPolicies(config *config.Config, log zlog.Logger) error {
	if (config.HTTP.Auth == nil || (config.HTTP.Auth.HTPasswd.Path == "" && config.HTTP.Auth.LDAP == nil &&
		config.HTTP.Auth.OpenID == nil)) && !authzContainsOnlyAnonymousPolicy(config) {
		log.Error().Err(zerr.ErrBadConfig).
			Msg("access control config requires one of httpasswd, ldap or openid authentication " +
				"or using only 'anonymousPolicy' policies")

		return zerr.ErrBadConfig
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

					log.Warn().Msg("CVE update interval set to too-short interval < 2h, " +
						"changing update duration to 2 hours and continuing.")
				}

				if config.Extensions.Search.CVE.Trivy == nil {
					config.Extensions.Search.CVE.Trivy = &extconf.TrivyConfig{}
				}

				if config.Extensions.Search.CVE.Trivy.DBRepository == "" {
					defaultDBDownloadURL := "ghcr.io/aquasecurity/trivy-db"
					log.Info().Str("trivyDownloadURL", defaultDBDownloadURL).
						Msg("Config: using default Trivy DB download URL.")
					config.Extensions.Search.CVE.Trivy.DBRepository = defaultDBDownloadURL
				}

				if config.Extensions.Search.CVE.Trivy.JavaDBRepository == "" {
					defaultJavaDBDownloadURL := "ghcr.io/aquasecurity/trivy-java-db"
					log.Info().Str("trivyJavaDownloadURL", defaultJavaDBDownloadURL).
						Msg("Config: using default Trivy Java DB download URL.")
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
				config.Extensions.Scrub.Interval = 24 * time.Hour //nolint: gomnd
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

	if !config.Storage.GC {
		if viperInstance.Get("storage::gcdelay") == nil {
			config.Storage.GCDelay = 0
		}

		if viperInstance.Get("storage::gcdelay") == nil {
			config.Storage.UntaggedImageRetentionDelay = 0
		}

		if viperInstance.Get("storage::gcinterval") == nil {
			config.Storage.GCInterval = 0
		}
	}

	// cache settings

	// global storage

	// if dedupe is true but remoteCache bool not set in config file
	// for cloud based storage, remoteCache defaults to true
	if config.Storage.Dedupe && !viperInstance.IsSet("storage::remotecache") && config.Storage.StorageDriver != nil {
		config.Storage.RemoteCache = true
	}

	// s3 dedup=false, check for previous dedup usage and set to true if cachedb found
	if !config.Storage.Dedupe && config.Storage.StorageDriver != nil {
		cacheDir, _ := config.Storage.StorageDriver["rootdirectory"].(string)
		cachePath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

		if _, err := os.Stat(cachePath); err == nil {
			log.Info().Msg("Config: dedupe set to false for s3 driver but used to be true.")
			log.Info().Str("cache path", cachePath).Msg("found cache database")

			config.Storage.RemoteCache = false
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
				log.Info().Msg("Config: dedupe set to false for s3 driver but used to be true. ")
				log.Info().Str("cache path", subpathCachePath).Msg("found cache database")

				storageConfig.RemoteCache = false
			}
		}

		// if gc is enabled
		if storageConfig.GC {
			// and gcReferrers is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcreferrers") {
				storageConfig.GCReferrers = true
			}

			// and gcDelay is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcdelay") {
				storageConfig.GCDelay = storageConstants.DefaultGCDelay
			}

			// and retentionDelay is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::retentiondelay") {
				storageConfig.UntaggedImageRetentionDelay = storageConstants.DefaultUntaggedImgeRetentionDelay
			}

			// and gcInterval is not set, it is set to default value
			if !viperInstance.IsSet("storage::subpaths::" + name + "::gcinterval") {
				storageConfig.GCInterval = storageConstants.DefaultGCInterval
			}

			config.Storage.SubPaths[name] = storageConfig
		}
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

	log.Warn().Str("config version", config.DistSpecVersion).Str("supported version", distspec.Version).
		Msg("config dist-spec version differs from version actually used")

	config.DistSpecVersion = distspec.Version
}

func LoadConfiguration(config *config.Config, configPath string) error {
	// Default is dot (.) but because we allow glob patterns in authz
	// we need another key delimiter.
	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))

	viperInstance.SetConfigFile(configPath)

	if err := viperInstance.ReadInConfig(); err != nil {
		log.Error().Err(err).Msg("error while reading configuration")

		return err
	}

	metaData := &mapstructure.Metadata{}
	if err := viperInstance.Unmarshal(&config, metadataConfig(metaData)); err != nil {
		log.Error().Err(err).Msg("error while unmarshaling new config")

		return err
	}

	log := zlog.NewLogger(config.Log.Level, config.Log.Output)

	if len(metaData.Keys) == 0 {
		log.Error().Err(zerr.ErrBadConfig).Msg("config doesn't contain any key:value pair")

		return zerr.ErrBadConfig
	}

	if len(metaData.Unused) > 0 {
		log.Error().Err(zerr.ErrBadConfig).Strs("keys", metaData.Unused).Msg("unknown keys")

		return zerr.ErrBadConfig
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

func authzContainsOnlyAnonymousPolicy(cfg *config.Config) bool {
	adminPolicy := cfg.HTTP.AccessControl.AdminPolicy
	anonymousPolicyPresent := false

	log.Info().Msg("checking if anonymous authorization is the only type of authorization policy configured")

	if len(adminPolicy.Actions)+len(adminPolicy.Users) > 0 {
		log.Info().Msg("admin policy detected, anonymous authorization is not the only authorization policy configured")

		return false
	}

	for _, repository := range cfg.HTTP.AccessControl.Repositories {
		if len(repository.DefaultPolicy) > 0 {
			log.Info().Interface("repository", repository).
				Msg("default policy detected, anonymous authorization is not the only authorization policy configured")

			return false
		}

		if len(repository.AnonymousPolicy) > 0 {
			log.Info().Msg("anonymous authorization detected")

			anonymousPolicyPresent = true
		}

		for _, policy := range repository.Policies {
			if len(policy.Actions)+len(policy.Users) > 0 {
				log.Info().Interface("repository", repository).
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
			log.Error().Str("userAttribute", ldap.UserAttribute).
				Msg("invalid LDAP configuration, missing mandatory key: userAttribute")

			return zerr.ErrLDAPConfig
		}

		if ldap.Address == "" {
			log.Error().Str("address", ldap.Address).
				Msg("invalid LDAP configuration, missing mandatory key: address")

			return zerr.ErrLDAPConfig
		}

		if ldap.BaseDN == "" {
			log.Error().Str("basedn", ldap.BaseDN).
				Msg("invalid LDAP configuration, missing mandatory key: basedn")

			return zerr.ErrLDAPConfig
		}
	}

	return nil
}

func validateHTTP(config *config.Config, log zlog.Logger) error {
	if config.HTTP.Port != "" {
		port, err := strconv.ParseInt(config.HTTP.Port, 10, 64)
		if err != nil || (port < 0 || port > 65535) {
			log.Error().Str("port", config.HTTP.Port).Msg("invalid port")

			return zerr.ErrBadConfig
		}
	}

	return nil
}

func validateGC(config *config.Config, log zlog.Logger) error {
	// enforce GC params
	if config.Storage.GCDelay < 0 {
		log.Error().Err(zerr.ErrBadConfig).Dur("delay", config.Storage.GCDelay).
			Msg("invalid garbage-collect delay specified")

		return zerr.ErrBadConfig
	}

	if config.Storage.GCInterval < 0 {
		log.Error().Err(zerr.ErrBadConfig).Dur("interval", config.Storage.GCInterval).
			Msg("invalid garbage-collect interval specified")

		return zerr.ErrBadConfig
	}

	if !config.Storage.GC {
		if config.Storage.GCDelay != 0 {
			log.Warn().Err(zerr.ErrBadConfig).
				Msg("garbage-collect delay specified without enabling garbage-collect, will be ignored")
		}

		if config.Storage.GCInterval != 0 {
			log.Warn().Err(zerr.ErrBadConfig).
				Msg("periodic garbage-collect interval specified without enabling garbage-collect, will be ignored")
		}
	}

	// subpaths
	for name, subPath := range config.Storage.SubPaths {
		if subPath.GC && subPath.GCDelay <= 0 {
			log.Error().Err(zerr.ErrBadConfig).
				Str("subPath", name).
				Interface("gcDelay", subPath.GCDelay).
				Msg("invalid GC delay configuration - cannot be negative or zero")

			return zerr.ErrBadConfig
		}
	}

	return nil
}

func validateSync(config *config.Config, log zlog.Logger) error {
	// check glob patterns in sync config are compilable
	if config.Extensions != nil && config.Extensions.Sync != nil {
		for id, regCfg := range config.Extensions.Sync.Registries {
			// check retry options are configured for sync
			if regCfg.MaxRetries != nil && regCfg.RetryDelay == nil {
				log.Error().Err(zerr.ErrBadConfig).Int("id", id).Interface("extensions.sync.registries[id]",
					config.Extensions.Sync.Registries[id]).Msg("retryDelay is required when using maxRetries")

				return zerr.ErrBadConfig
			}

			if regCfg.Content != nil {
				for _, content := range regCfg.Content {
					ok := glob.ValidatePattern(content.Prefix)
					if !ok {
						log.Error().Err(glob.ErrBadPattern).Str("prefix", content.Prefix).Msg("sync prefix could not be compiled")

						return glob.ErrBadPattern
					}

					if content.StripPrefix && !strings.Contains(content.Prefix, "/*") && content.Destination == "/" {
						log.Error().Err(zerr.ErrBadConfig).
							Interface("sync content", content).
							Msg("sync config: can not use stripPrefix true and destination '/' without using glob patterns in prefix")

						return zerr.ErrBadConfig
					}
				}
			}
		}
	}

	return nil
}
