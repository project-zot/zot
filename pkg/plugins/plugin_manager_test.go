package plugins_test

import (
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/errors"
	. "zotregistry.io/zot/pkg/plugins"
	"zotregistry.io/zot/pkg/plugins/common"
)

type mockPlugin struct{}

type mockImplManager struct {
	Implementations map[string]common.Plugin

	// registerImplementationFn func(implName string, plugin interface{}) error
	// allPluginsFn             func() map[string]common.Plugin
	// getImplFn                func(name string) common.Plugin
}

func (mim mockImplManager) RegisterImplementation(implName string, plugin interface{}) error {
	if _, ok := mim.Implementations[implName]; ok {
		return errors.ErrImplNameCollision
	}

	mim.Implementations[implName] = plugin

	return nil
}

func (mim mockImplManager) AllPlugins() map[string]common.Plugin {
	return mim.Implementations
}

func (mim mockImplManager) GetImpl(name string) common.Plugin {
	return mim.Implementations[name]
}

// func (mt mockImplManager) RegisterImplementation(implName string, plugin interface{}) error {
// 	if mt.registerImplementationFn != nil {
// 		return mt.registerImplementationFn(implName, plugin)
// 	}

// 	return nil
// }

// func (mt mockImplManager) AllPlugins() map[string]common.Plugin {
// 	if mt.allPluginsFn != nil {
// 		return mt.allPluginsFn()
// 	}

// 	return nil
// }

// func (mt mockImplManager) GetImpl(name string) common.Plugin {
// 	if mt.getImplFn != nil {
// 		return mt.getImplFn(name)
// 	}

// 	return nil
// }

type mockPluginBuilder struct {
	buildFn func(name string, addr string, port string, options common.Options) (common.Plugin, error)
}

func (mt mockPluginBuilder) Build(name string, addr string, port string, options common.Options,
) (common.Plugin, error) {
	if mt.buildFn != nil {
		return mt.buildFn(name, addr, port, options)
	}

	return nil, nil
}

func TestPluginManager(t *testing.T) {
	Convey("GetBuilder method", t, func() {
		manager := NewManager()

		manager.RegisterInterface(
			"MockIntegrationPoint",
			mockImplManager{},
			mockPluginBuilder{},
		)

		Convey("Builder exists for the given interface", func() {
			builder, err := manager.GetBuilder("MockIntegrationPoint")
			So(builder, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})

		Convey("Builder does not exist for the given interface", func() {
			builder, err := manager.GetBuilder("NOT_REGISTERED_INTERFACE")
			So(builder, ShouldBeNil)
			So(err, ShouldEqual, errors.ErrBadIntegrationPoint)
		})
	})

	Convey("LoadAll method ", t, func() {
		pluginsDir, err := ioutil.TempDir("", "plugins_dir")
		So(err, ShouldBeNil)
		defer os.RemoveAll(pluginsDir)

		configFile1 := `{
			"name": "FirstTestPlugin",
			"integrationPoints": [
				{
					"interface": "MockIntegrationPoint",
					"grpcConnection": {
						"addr": "localhost",
						"port": 9001
					}
				}
			]
		}`
		configFile2 := `{
			"name": "SecondTestPlugin",
			"integrationPoints": [
				{
					"interface": "MockIntegrationPoint",
					"grpcConnection": {
						"addr": "localhost",
						"port": 9001
					}
				}
			]
		}`

		file1, err := ioutil.TempFile(pluginsDir, "mock_plugin1*.json")
		So(err, ShouldBeNil)
		_, err = file1.WriteString(configFile1)
		So(err, ShouldBeNil)

		file2, err := ioutil.TempFile(pluginsDir, "mock_plugin2*.json")
		So(err, ShouldBeNil)

		_, err = file2.WriteString(configFile2)
		So(err, ShouldBeNil)

		Convey("Load all is successful", func() {
			manager := NewManager()

			// register the MockIntegrationPoint so we can use it in tests, NewManager()
			// registers only the integration points used in zot.
			manager.RegisterInterface("MockIntegrationPoint",
				mockImplManager{
					Implementations: make(map[string]common.Plugin),
				},
				mockPluginBuilder{
					buildFn: func(name, addr, port string, options common.Options) (common.Plugin, error) {
						return mockPlugin{}, nil
					},
				},
			)

			err = manager.LoadAll(pluginsDir)
			So(err, ShouldBeNil)

			mockManager := manager.GetImplManager("MockIntegrationPoint")
			So(mockManager, ShouldNotBeNil)
			So(len(mockManager.AllPlugins()), ShouldEqual, 2)
			So(mockManager.GetImpl("FirstTestPlugin"), ShouldNotBeNil)
			So(mockManager.GetImpl("SecondTestPlugin"), ShouldNotBeNil)
			So(mockManager.GetImpl("OTHER_UNUSED_PLUGIN"), ShouldBeNil)
		})

		Convey("LoadAll doesn't have permission to read", func() {
			manager := NewManager()

			manager.RegisterInterface(
				"MockIntegrationPoint",
				mockImplManager{Implementations: make(map[string]common.Plugin)},
				mockPluginBuilder{},
			)

			err := os.Chmod(pluginsDir, 0o000)
			So(err, ShouldBeNil)
			err = manager.LoadAll(pluginsDir)
			So(err, ShouldNotBeNil)

			// this allows us to remove the file after finishing
			err = os.Chmod(pluginsDir, 0o755)
			So(err, ShouldBeNil)
		})

		Convey("MockBuilder was not initialized before calling LoadAll()", func() {
			manager := NewManager()

			manager.RegisterInterface(
				"MockIntegrationPoint",
				mockImplManager{Implementations: make(map[string]common.Plugin)},
				nil,
			)
		})
	})
}

// func initTestPluginsDir(pluginConfigs []common.Config) (pluginsDir string) {
// 	pluginsDir, err := ioutil.TempDir("", "plugins_dir")
// 	So(err, ShouldBeNil)

// 	for _, config := range pluginConfigs {
// 		file, err := ioutil.TempFile(pluginsDir, "mock_plugin1*.json")
// 		So(err, ShouldBeNil)

// 		configBytes, err := json.Marshal(config)
// 		So(err, ShouldBeNil)

// 		_, err = file.Write(configBytes)
// 		So(err, ShouldBeNil)
// 	}

// 	return pluginsDir
// }
