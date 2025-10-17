//go:build !metrics
// +build !metrics

package cli

import (
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/exporter/api"
	"zotregistry.dev/zot/v2/pkg/log"
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

	logger := log.NewLogger("info", "")

	if err := viper.ReadInConfig(); err != nil {
		logger.Panic().Err(err).Str("config", configPath).Msg("failed to read configuration")
	}

	metaData := &mapstructure.Metadata{}
	if err := viper.Unmarshal(&config, metadataConfig(metaData)); err != nil {
		logger.Panic().Err(err).Str("config", configPath).Msg("failed to unmarshal config")
	}

	if len(metaData.Keys) == 0 {
		logger.Panic().Err(zerr.ErrBadConfig).Str("config", configPath).Msg("bad configuration")
	}

	if len(metaData.Unused) > 0 {
		logger.Panic().Err(zerr.ErrBadConfig).Interface("unknown fields", metaData.Unused).
			Str("config", configPath).Msg("bad configuration")
	}
}
