package plugins

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	zerr "zotregistry.io/zot/errors"
	cliPlugin "zotregistry.io/zot/pkg/plugins/cli"
	"zotregistry.io/zot/pkg/plugins/common"
	scanPlugin "zotregistry.io/zot/pkg/plugins/scan"
)

// make it thread safe: https://refactoring.guru/design-patterns/singleton/go/example.

type PluginManager interface {
	GetImplManager(name string) common.ImplementationManager
	GetBuilder(interfaceName string) (common.PluginBuilder, error)
	LoadAll(pluginsDir string) error
	RegisterInterface(name string, implManager common.ImplementationManager, pluginBuilder common.PluginBuilder)
	RegisterImplementation(interfaceName string, implName string, plugin common.Plugin) error
}

type BasePluginManager struct {
	ImplManagers map[string]common.ImplementationManager
	builders     map[string]common.PluginBuilder
}

func NewManager() BasePluginManager {
	pluginManager := BasePluginManager{
		ImplManagers: map[string]common.ImplementationManager{},
		builders:     map[string]common.PluginBuilder{},
	}

	registerAllIntegrationPoints(&pluginManager)

	return pluginManager
}

func registerAllIntegrationPoints(pluginManager PluginManager) {
	pluginManager.RegisterInterface(
		"VulnScanner",
		scanPlugin.RPCScanManager{
			Impl: &struct {
				Name            string
				VulnScannerImpl common.Plugin
			}{},
		},
		scanPlugin.RPCScanBuilder{},
	)

	pluginManager.RegisterInterface(
		"CLICommand",
		cliPlugin.Manager{
			Implementations: map[string]common.Plugin{},
		},
		cliPlugin.Builder{},
	)
}

// GetBuilder returns the PluginBuilder object for a registered integration point.
func (pm BasePluginManager) GetBuilder(interfaceName string) (common.PluginBuilder, error) {
	if pm.builders[interfaceName] == nil {
		return nil, zerr.ErrBadIntegrationPoint
	}

	return pm.builders[interfaceName], nil
}

// LoadAll given a directory path will search for plugin config files
// and try to initialize and hook plugins by creating a gRPC connection
// and registering the implementation.
func (pm BasePluginManager) LoadAll(pluginsDir string) error {
	log.Info().Msgf("loading all plugins from %v", pluginsDir)

	pluginConfigs, err := os.ReadDir(pluginsDir)
	if err != nil {
		log.Error().Err(err).Msg("can't read plugins dir")

		return err
	}

	for _, d := range pluginConfigs {
		if d.IsDir() {
			continue
		}

		config, err := loadConfig(filepath.Join(pluginsDir, d.Name()))
		if err != nil {
			log.Error().Err(err).Msg("can't load plugin config")

			continue
		}

		for _, intPoint := range config.IntegrationPoints {
			builder, err := pm.GetBuilder(intPoint.Interface)
			if err != nil {
				log.Warn().Err(err).Msgf("can't get builder for %v", intPoint.Interface)

				continue
			}

			pluginClient, err := builder.Build(
				config.Name,
				intPoint.GrpcConnection.Addr,
				intPoint.GrpcConnection.Port,
				intPoint.Options,
			)
			if err != nil {
				log.Warn().Err(err).Msgf("can't build implementation for %v, name: %v",
					intPoint.Interface, config.Name)

				continue
			}

			err = pm.RegisterImplementation(intPoint.Interface, config.Name, pluginClient)
			if err != nil {
				log.Warn().Err(err).Msgf("can't register implementation for %v", intPoint.Interface)
			}
		}
	}

	return nil
}

// RegisterInterface makes the given interface name recognised as supported by Zot.
func (pm BasePluginManager) RegisterInterface(name string, implManager common.ImplementationManager,
	pluginBuilder common.PluginBuilder,
) {
	pm.ImplManagers[name] = implManager
	pm.builders[name] = pluginBuilder
}

// RegisterImplementation hooks the implementation to the InterfaceManager. This
// allows Zot to find and use the implementation.
func (pm BasePluginManager) RegisterImplementation(interfaceName string, implName string,
	plugin common.Plugin,
) error {
	if pm.ImplManagers[interfaceName] == nil {
		return zerr.ErrBadIntegrationPoint
	}

	err := pm.ImplManagers[interfaceName].RegisterImplementation(implName, plugin)
	if err != nil {
		return err
	}

	return nil
}

func (pm BasePluginManager) GetImplManager(name string) common.ImplementationManager {
	return pm.ImplManagers[name]
}

func loadConfig(configPath string) (*common.Config, error) {
	var config common.Config

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
		return &common.Config{}, nil
	}

	return &config, nil
}

func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}
