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

// make it thread safe: https://refactoring.guru/design-patterns/singleton/go/example.

type PluginManager interface {
	GetImplManager(name string) ImplementationManager
	GetBuilder(interfaceName string) (PluginBuilder, error)
	LoadAll(pluginsDir string) error
	RegisterInterface(name string, implManager ImplementationManager, pluginBuilder PluginBuilder)
	RegisterImplementation(interfaceName string, implName string, plugin Plugin) error
}

type DefaultPluginManager struct {
	ImplManagers map[string]ImplementationManager
	builders     map[string]PluginBuilder
	log          log.Logger
}

func NewManager() DefaultPluginManager {
	return DefaultPluginManager{
		ImplManagers: map[string]ImplementationManager{},
		builders:     map[string]PluginBuilder{},
		log:          log.Logger{},
	}
}

// GetBuilder returns the PluginBuilder object for a registered integration point.
func (pm DefaultPluginManager) GetBuilder(interfaceName string) (PluginBuilder, error) {
	if pm.builders[interfaceName] == nil {
		return nil, zerr.ErrBadIntegrationPoint
	}

	return pm.builders[interfaceName], nil
}

// LoadAll given a directory path will search for plugin config files
// and try to initialize and hook plugins by creating a gRPC connection
// and registering the implementation.
func (pm DefaultPluginManager) LoadAll(pluginsDir string) error {
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

		for _, intPoint := range config.IntegrationPoints {
			builder, err := pm.GetBuilder(intPoint.Interface)
			if err != nil {
				pm.log.Warn().Err(err).Msgf("can't get builder for %v", intPoint.Interface)

				continue
			}

			pluginClient := builder.Build(
				config.Name,
				intPoint.GrpcConnection.Addr,
				intPoint.GrpcConnection.Port,
				intPoint.Options,
			)

			err = pm.RegisterImplementation(intPoint.Interface, config.Name, pluginClient)
			if err != nil {
				pm.log.Warn().Err(err).Msgf("can't register implementation for %v", intPoint.Interface)
			}
		}
	}

	return nil
}

// RegisterInterface makes the given interface name recognised as supported by Zot.
func (pm DefaultPluginManager) RegisterInterface(name string, interfaceManager ImplementationManager,
	pluginBuilder PluginBuilder,
) {
	pm.ImplManagers[name] = interfaceManager
	pm.builders[name] = pluginBuilder
}

// RegisterImplementation hooks the implementation to the InterfaceManager. This
// allows Zot to find and use the implementation.
func (pm DefaultPluginManager) RegisterImplementation(interfaceName string, implName string, plugin Plugin) error {
	if pm.ImplManagers[interfaceName] == nil {
		return zerr.ErrBadIntegrationPoint
	}

	err := pm.ImplManagers[interfaceName].RegisterImplementation(implName, plugin)
	if err != nil {
		return err
	}

	return nil
}

func (pm DefaultPluginManager) GetImplManager(name string) ImplementationManager {
	return pm.ImplManagers[name]
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
		return &Config{}, nil
	}

	return &config, nil
}

func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}
