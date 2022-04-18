package plugins

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
)

// A plugin is defined by an interface and a gRPC communication protocol. 
// Each definition must come with an implementation that uses the gRPC client,
// a Builder that knows how to build a plugin implementation,
// a InterfaceManager that stores and dispenses implementations for the plugin.
type Plugin interface{}

// PluginManager is responsable for storing for each plugin
// it's implementation manager(called InterfaceManager)
var PluginManager pluginManager = pluginManager{
	InterfaceManagers: map[string]InterfaceManager{},
	builders:          map[string]PluginBuilder{},
}

type pluginManager struct {
	InterfaceManagers map[string]InterfaceManager
	builders          map[string]PluginBuilder
	log               log.Logger
}

func (pm *pluginManager) GetBuilder(interfaceName string) (PluginBuilder, error) {
	if pm.builders[interfaceName] == nil {
		return nil, fmt.Errorf("interface `%s` is not supported", interfaceName)
	}

	return pm.builders[interfaceName], nil
}

func (pm *pluginManager) LoadAll(pluginsDir string) error {
	pm.log.Info().Msgf("loading all plugins from %v", pluginsDir)

	pluginConfigs, err := os.ReadDir(pluginsDir)
	if err != nil {
		pm.log.Error().Err(err).Msg("can't read plugins dir")
		return err
	}

	for _, d := range pluginConfigs {
		if d.IsDir() {
			continue
		}
		config, err := loadConfig(filepath.Join(pluginsDir, d.Name()))
		if err != nil {
			pm.log.Error().Err(err).Msg("can't load plugin config")
			continue
		}
		for _, ip := range config.IntegrationPoints {
			builder, err := pm.GetBuilder(ip.Interface)
			if err != nil {
				pm.log.Warn().Err(err).Msgf("can't get builder for %v", ip.Interface)
				continue
			}

			pluginClient := builder.Build(
				ip.GrpcConnection.Addr,
				ip.GrpcConnection.Port,
				ip.Options,
			)

			err = pm.RegisterImplementation(ip.Interface, config.Name, pluginClient)
			if err != nil {
				pm.log.Warn().Err(err).Msgf("can't register implementation for %v", ip.Interface)
			}
		}
	}
	return nil
}

func (pm *pluginManager) RegisterInterface(name string, interfaceManager InterfaceManager, pluginBuilder PluginBuilder) {
	pm.InterfaceManagers[name] = interfaceManager
	pm.builders[name] = pluginBuilder
}

func (pm *pluginManager) RegisterImplementation(interfaceName string, implName string, plugin interface{}) error {
	if pm.InterfaceManagers[interfaceName] == nil {
		return zerr.ErrBadIntegrationPoint
	}

	err := pm.InterfaceManagers[interfaceName].RegisterImplementation(implName, plugin)

	if err != nil {
		return err
	}

	return nil
}

func loadConfig(configPath string) (*Config, error) {
	var config Config

	viperInstance := viper.NewWithOptions(viper.KeyDelimiter("::"))
	viperInstance.SetConfigFile(configPath)

	if err := viperInstance.ReadInConfig(); err != nil {
		fmt.Println("Can't read config: ", configPath)

		return nil, err
	}

	metaData := &mapstructure.Metadata{}
	if err := viperInstance.Unmarshal(&config, metadataConfig(metaData)); err != nil {
		return nil, err
	}

	if len(metaData.Keys) == 0 || len(metaData.Unused) > 0 {

		return nil, nil
	}

	return &config, nil
}

func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}
