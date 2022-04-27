//go:build !metrics
// +build !metrics

package cli

import (
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/exporter/api"
)

// metadataConfig reports metadata after parsing, which we use to track
// errors.
func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}

func NewExporterCmd() *cobra.Command {
	config := api.DefaultConfig()

	// "config"
	configCmd := &cobra.Command{
		Use:     "config <config_file>",
		Aliases: []string{"config"},
		Short:   "`config` node exporter properties",
		Long:    "`config` node exporter properties",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				loadConfiguration(config, args[0])
			}

			c := api.NewController(config)
			c.Run()
		},
	}

	// "node_exporter"
	exporterCmd := &cobra.Command{
		Use:   "zxp",
		Short: "`zxp`",
		Long:  "`zxp`",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Usage()
			cmd.SilenceErrors = false
		},
	}

	exporterCmd.AddCommand(configCmd)

	return exporterCmd
}

func loadConfiguration(config *api.Config, configPath string) {
	viper.SetConfigFile(configPath)

	if err := viper.ReadInConfig(); err != nil {
		log.Error().Err(err).Msg("Error while reading configuration")
		panic(err)
	}

	metaData := &mapstructure.Metadata{}
	if err := viper.Unmarshal(&config, metadataConfig(metaData)); err != nil {
		log.Error().Err(err).Msg("Error while unmarshalling new config")
		panic(err)
	}

	if len(metaData.Keys) == 0 || len(metaData.Unused) > 0 {
		log.Error().Err(errors.ErrBadConfig).Msg("Bad configuration, retry writing it")
		panic(errors.ErrBadConfig)
	}
}
