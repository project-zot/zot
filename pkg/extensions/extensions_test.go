//go:build sync || metrics || mgmt
// +build sync metrics mgmt

package extensions_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/extensions"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/test"
)

func TestEnableExtension(t *testing.T) {
	Convey("Verify log if sync disabled in config", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()
		conf := config.New()
		falseValue := false

		syncConfig := &sync.Config{
			Enable:     &falseValue,
			Registries: []sync.RegistryConfig{},
		}

		// conf.Extensions.Sync.Enable = &falseValue
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Sync = syncConfig
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Level = "info"
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		defer ctlrManager.StopServer()

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager.StartAndWait(port)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"Sync registries config not provided or disabled, skipping sync")
	})
}

func TestMetricsExtension(t *testing.T) {
	Convey("Verify Metrics enabled for storage subpaths", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Metrics = &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultValue},
			Prometheus: &extconf.PrometheusConfig{},
		}
		conf.Log.Level = "info"
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager.StartAndWait(port)

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring,
			"Prometheus instrumentation Path not set, changing to '/metrics'.")
	})
}

func TestMgmtExtension(t *testing.T) {
	Convey("Verify mgmt route enabled with basic auth", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		htpasswdPath := test.MakeHtpasswdFile()
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		go func() {
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(baseURL)

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtPrefix)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var response extensions.MgmtResponse
		err = json.Unmarshal(resp.Body(), &response)
		So(err, ShouldBeNil)
		So(response.Auth.Type, ShouldEqual, constants.BasicAuth)
		So(response.Auth.Enabled, ShouldBeTrue)

		// with credentials
		resp, err = resty.R().SetBasicAuth("test", "test").Get(baseURL + constants.FullMgmtPrefix)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &response)
		So(err, ShouldBeNil)
		So(response.Auth.Type, ShouldEqual, constants.BasicAuth)
		So(response.Auth.Enabled, ShouldBeTrue)
	})

	Convey("Verify mgmt route enabled without any auth", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		conf.Commit = "v1.0.0"

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		go func() {
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().Get(baseURL + constants.FullMgmtPrefix)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var response extensions.MgmtResponse
		err = json.Unmarshal(resp.Body(), &response)
		So(err, ShouldBeNil)
		So(response.Auth.Type, ShouldEqual, "")
		So(response.Auth.Enabled, ShouldBeFalse)
		So(response.Version, ShouldEqual, config.Commit)

		// use X-REAL-IP header
		resp, err = resty.R().SetHeader("X-REAL-IP", "127.0.0.1").Get(baseURL + constants.FullMgmtPrefix)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// use X-FORWARDED-FOR header
		headers := make(map[string]string)
		headers["X-FORWARDED-FOR"] = "192.168.0.100, 127.0.0.1"
		resp, err = resty.R().SetHeaders(headers).Get(baseURL + constants.FullMgmtPrefix)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		data, _ := os.ReadFile(logFile.Name())
		So(string(data), ShouldContainSubstring, "setting up mgmt routes")
	})
}
