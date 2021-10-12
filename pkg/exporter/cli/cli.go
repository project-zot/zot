// +build minimal

package cli

import (
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/exporter/api"

	"github.com/mitchellh/mapstructure"
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

func NewZotExporterCmd() *cobra.Command {
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

	// "zot_exporter"
	zotExporterCmd := &cobra.Command{
		Use:   "zot_exporter",
		Short: "`zot_exporter`",
		Long:  "`zot_exporter`",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Usage()
			cmd.SilenceErrors = false
		},
	}

	zotExporterCmd.AddCommand(configCmd)

	return zotExporterCmd
}

func loadConfiguration(config *api.Config, configPath string) {
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
}
