package cli

import (
	"context"
	"fmt"
	"net/http"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/mitchellh/mapstructure"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/storage"
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
				panic(err)
			}

			/* context used to cancel go routines so that
			we can change their config on the fly (restart routines with different config) */
			reloaderCtx := hotReloader.Start()

			if err := ctlr.Run(reloaderCtx); err != nil {
				panic(err)
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
				fmt.Sprintf("http://%s:%s/v2", conf.HTTP.Address, conf.HTTP.Port),
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

				if err := ctlr.InitImageStore(context.Background()); err != nil {
					panic(err)
				}

				result, err := ctlr.StoreController.CheckAllBlobsIntegrity()
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
					panic(err)
				}

				log.Info().Msgf("Config file %s is valid", args[0])
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

// "zli" - client-side cli.
func NewCliRootCmd() *cobra.Command {
	showVersion := false

	rootCmd := &cobra.Command{
		Use:   "zli",
		Short: "`zli`",
		Long:  "`zli`",
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

	// additional cmds
	enableCli(rootCmd)
	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}

func validateConfiguration(config *config.Config) error {
	// enforce GC params
	if config.Storage.GCDelay < 0 {
		log.Error().Err(errors.ErrBadConfig).
			Msgf("invalid garbage-collect delay %v specified", config.Storage.GCDelay)

		return errors.ErrBadConfig
	}

	if !config.Storage.GC && config.Storage.GCDelay != 0 {
		log.Warn().Err(errors.ErrBadConfig).
			Msg("garbage-collect delay specified without enabling garbage-collect, will be ignored")
	}

	// check authorization config, it should have basic auth enabled or ldap
	if config.HTTP.RawAccessControl != nil {
		if config.HTTP.Auth == nil || (config.HTTP.Auth.HTPasswd.Path == "" && config.HTTP.Auth.LDAP == nil) {
			log.Error().Err(errors.ErrBadConfig).
				Msg("access control config requires httpasswd or ldap authentication to be enabled")

			return errors.ErrBadConfig
		}
	}

	if len(config.Storage.StorageDriver) != 0 {
		// enforce s3 driver in case of using storage driver
		if config.Storage.StorageDriver["name"] != storage.S3StorageDriverName {
			log.Error().Err(errors.ErrBadConfig).Msgf("unsupported storage driver: %s", config.Storage.StorageDriver["name"])

			return errors.ErrBadConfig
		}

		// enforce filesystem storage in case sync feature is enabled
		if config.Extensions != nil && config.Extensions.Sync != nil {
			log.Error().Err(errors.ErrBadConfig).Msg("sync supports only filesystem storage")

			return errors.ErrBadConfig
		}
	}

	// check glob patterns in sync config are compilable
	if config.Extensions != nil && config.Extensions.Sync != nil {
		for id, regCfg := range config.Extensions.Sync.Registries {
			// check retry options are configured for sync
			if regCfg.MaxRetries != nil && regCfg.RetryDelay == nil {
				log.Error().Err(errors.ErrBadConfig).Msgf("extensions.sync.registries[%d].retryDelay"+
					" is required when using extensions.sync.registries[%d].maxRetries", id, id)

				return errors.ErrBadConfig
			}

			if regCfg.Content != nil {
				for _, content := range regCfg.Content {
					ok := glob.ValidatePattern(content.Prefix)
					if !ok {
						log.Error().Err(glob.ErrBadPattern).Str("pattern", content.Prefix).Msg("sync pattern could not be compiled")

						return glob.ErrBadPattern
					}
				}
			}
		}
	}

	// enforce s3 driver on subpaths in case of using storage driver
	if config.Storage.SubPaths != nil {
		if len(config.Storage.SubPaths) > 0 {
			subPaths := config.Storage.SubPaths

			for route, storageConfig := range subPaths {
				if len(storageConfig.StorageDriver) != 0 {
					if storageConfig.StorageDriver["name"] != storage.S3StorageDriverName {
						log.Error().Err(errors.ErrBadConfig).Str("subpath",
							route).Msgf("unsupported storage driver: %s", storageConfig.StorageDriver["name"])

						return errors.ErrBadConfig
					}
				}
			}
		}
	}

	// check glob patterns in authz config are compilable
	if config.AccessControl != nil {
		for pattern := range config.AccessControl.Repositories {
			ok := glob.ValidatePattern(pattern)
			if !ok {
				log.Error().Err(glob.ErrBadPattern).Str("pattern", pattern).Msg("authorization pattern could not be compiled")

				return glob.ErrBadPattern
			}
		}
	}

	return nil
}

func applyDefaultValues(config *config.Config, viperInstance *viper.Viper) {
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

			if config.Extensions.Search.CVE == nil {
				config.Extensions.Search.CVE = &extconf.CVEConfig{UpdateInterval: 24 * time.Hour} // nolint: gomnd
			}
		}

		if config.Extensions.Metrics != nil {
			if config.Extensions.Metrics.Enable == nil {
				config.Extensions.Metrics.Enable = &defaultVal
			}

			if config.Extensions.Metrics.Prometheus == nil {
				config.Extensions.Metrics.Prometheus = &extconf.PrometheusConfig{Path: "/metrics"}
			}
		}
	}

	if !config.Storage.GC && viperInstance.Get("storage::gcdelay") == nil {
		config.Storage.GCDelay = 0
	}
}

func updateDistSpecVersion(config *config.Config) {
	if config.DistSpecVersion == distspec.Version {
		return
	}

	log.Warn().
		Msgf("config dist-spec version: %s differs from version actually used: %s",
			config.DistSpecVersion, distspec.Version)

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
		log.Error().Err(err).Msg("error while unmarshalling new config")

		return err
	}

	if len(metaData.Keys) == 0 || len(metaData.Unused) > 0 {
		log.Error().Err(errors.ErrBadConfig).Msg("bad configuration, retry writing it")

		return errors.ErrBadConfig
	}

	err := config.LoadAccessControlConfig(viperInstance)
	if err != nil {
		log.Error().Err(err).Msg("unable to unmarshal config's accessControl")

		return err
	}

	// defaults
	applyDefaultValues(config, viperInstance)

	// various config checks
	if err := validateConfiguration(config); err != nil {
		return err
	}

	// update distSpecVersion
	updateDistSpecVersion(config)

	return nil
}
