package config

import (
	"io"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
)

func LoadFromBufferWithWriter(configPath string, in io.Reader, config *Config) (func() error, error) {
	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))
	viperInstance.SetConfigFile(configPath)

	if err := viperInstance.ReadConfig(in); err != nil {
		log.Error().Err(err).Msg("error while reading configuration")

		return nil, err
	}

	if err := unmarshal(viperInstance, config); err != nil {
		return nil, err
	}

	// defaults
	applyDefaultValues(config, viperInstance)

	if err := Validate(config); err != nil {
		log.Error().Err(err).Msg("config is not valid")

		return nil, err
	}

	writer := viperInstance.WriteConfig

	return writer, nil
}

func LoadFromFile(configPath string, config *Config) error {
	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))
	viperInstance.SetConfigFile(configPath)

	return loadFromFile(viperInstance, config)
}

func loadFromFile(viperInstance *viper.Viper, config *Config) error {
	if err := viperInstance.ReadInConfig(); err != nil {
		log.Error().Err(err).Msg("error while reading configuration")

		return err
	}

	if err := unmarshal(viperInstance, config); err != nil {
		return err
	}

	// defaults
	applyDefaultValues(config, viperInstance)

	if err := Validate(config); err != nil {
		log.Error().Err(err).Msg("config is not valid")

		return err
	}

	return nil
}

func unmarshal(viperInstance *viper.Viper, config *Config) error {
	metaData := &mapstructure.Metadata{}
	if err := viperInstance.Unmarshal(&config, metadataConfig(metaData)); err != nil {
		log.Error().Err(err).Msg("error while unmarshalling new config")

		return err
	}

	if len(metaData.Keys) == 0 {
		log.Error().Err(errors.ErrBadConfig).Interface("config", config).Msgf("config doesn't contain any key:value pair")

		return errors.ErrBadConfig
	}

	if len(metaData.Unused) > 0 {
		log.Error().Err(errors.ErrBadConfig).Msgf("unknown keys: %v", metaData.Unused)

		return errors.ErrBadConfig
	}

	return nil
}

func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}

func applyDefaultValues(config *Config, viperInstance *viper.Viper) {
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
				config.Extensions.Search.CVE = &extconf.CVEConfig{UpdateInterval: 24 * time.Hour} //nolint: gomnd
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
	}

	if !config.Storage.GC && viperInstance.Get("storage::gcdelay") == nil {
		config.Storage.GCDelay = 0
	}
}
