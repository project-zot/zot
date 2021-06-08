package cli

import (
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/api/config"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/fsnotify/fsnotify"
	"github.com/mitchellh/mapstructure"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// metadataConfig reports metadata after parsing, which we use to track
// errors.
func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}

func NewRootCmd() *cobra.Command {
	showVersion := false
	conf := config.New()

	// "serve"
	serveCmd := &cobra.Command{
		Use:     "serve <config>",
		Aliases: []string{"serve"},
		Short:   "`serve` stores and distributes OCI images",
		Long:    "`serve` stores and distributes OCI images",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				LoadConfiguration(conf, args[0])
			}
			c := api.NewController(conf)

			// creates a new file watcher
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				panic(err)
			}
			defer watcher.Close()

			done := make(chan bool)
			// run watcher
			go func() {
				go func() {
					for {
						select {
						// watch for events
						case event := <-watcher.Events:
							if event.Op == fsnotify.Write {
								log.Info().Msg("Config file changed, trying to reload accessControl config")
								newConfig := config.New()
								LoadConfiguration(newConfig, args[0])
								c.Config.AccessControl = newConfig.AccessControl
							}
						// watch for errors
						case err := <-watcher.Errors:
							log.Error().Err(err).Msgf("FsNotify error while watching config %s", args[0])
							panic(err)
						}
					}
				}()

				if err := watcher.Add(args[0]); err != nil {
					log.Error().Err(err).Msgf("Error adding config file %s to FsNotify watcher", args[0])
					panic(err)
				}
				<-done
			}()

			if err := c.Run(); err != nil {
				panic(err)
			}
		},
	}

	verifyCmd := &cobra.Command{
		Use:     "verify <config>",
		Aliases: []string{"verify"},
		Short:   "`verify` validates a zot config file",
		Long:    "`verify` validates a zot config file",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				config := config.New()
				LoadConfiguration(config, args[0])
				log.Info().Msgf("Config file %s is valid", args[0])
			}
		},
	}

	// "garbage-collect"
	gcDelUntagged := false
	gcDryRun := false

	gcCmd := &cobra.Command{
		Use:     "garbage-collect <config>",
		Aliases: []string{"gc"},
		Short:   "`garbage-collect` deletes layers not referenced by any manifests",
		Long:    "`garbage-collect` deletes layers not referenced by any manifests",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Interface("values", conf).Msg("configuration settings")
			if conf.Storage.RootDirectory != "" {
				if err := storage.Scrub(conf.Storage.RootDirectory, gcDryRun); err != nil {
					panic(err)
				}
			}
		},
	}

	gcCmd.Flags().StringVarP(&conf.Storage.RootDirectory, "storage-root-dir", "r", "",
		"Use specified directory for filestore backing image data")

	_ = gcCmd.MarkFlagRequired("storage-root-dir")
	gcCmd.Flags().BoolVarP(&gcDelUntagged, "delete-untagged", "m", false,
		"delete manifests that are not currently referenced via tag")
	gcCmd.Flags().BoolVarP(&gcDryRun, "dry-run", "d", false,
		"do everything except remove the blobs")

	rootCmd := &cobra.Command{
		Use:   "zot",
		Short: "`zot`",
		Long:  "`zot`",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				log.Info().Str("distribution-spec", distspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Msg("version")
			}
			_ = cmd.Usage()
			cmd.SilenceErrors = false
		},
	}

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(gcCmd)
	rootCmd.AddCommand(verifyCmd)

	enableCli(rootCmd)

	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}

func LoadConfiguration(config *config.Config, configPath string) {
	viper.SetConfigFile(configPath)

	if err := viper.ReadInConfig(); err != nil {
		log.Error().Err(err).Msg("Error while reading configuration")
		panic(err)
	}

	md := &mapstructure.Metadata{}
	if err := viper.Unmarshal(&config, metadataConfig(md)); err != nil {
		log.Error().Err(err).Msg("Error while unmarshalling new config")
		panic(err)
	}

	if len(md.Keys) == 0 || len(md.Unused) > 0 {
		log.Error().Err(errors.ErrBadConfig).Msg("Bad configuration, retry writing it")
		panic(errors.ErrBadConfig)
	}

	// check authorization config, it should have basic auth enabled or ldap
	if config.HTTP.RawAccessControl != nil {
		if config.HTTP.Auth == nil || (config.HTTP.Auth.HTPasswd.Path == "" && config.HTTP.Auth.LDAP == nil) {
			log.Error().Err(errors.ErrBadConfig).
				Msg("access control config requires httpasswd or ldap authentication to be enabled")
			panic(errors.ErrBadConfig)
		}
	}

	err := config.LoadAccessControlConfig()
	if err != nil {
		log.Error().Err(errors.ErrBadConfig).Msg("Unable to unmarshal http.accessControl.key.policies")
		panic(err)
	}

	// defaults
	defualtTLSVerify := true

	if config.Extensions != nil && config.Extensions.Sync != nil {
		for id, regCfg := range config.Extensions.Sync.Registries {
			if regCfg.TLSVerify == nil {
				config.Extensions.Sync.Registries[id].TLSVerify = &defualtTLSVerify
			}
		}
	}
}
