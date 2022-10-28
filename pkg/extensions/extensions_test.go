//go:build sync || metrics || config
// +build sync metrics config

package extensions_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/cli"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/test"
)

const (
	username = "test"
	password = "test"
)

func TestEnableExtension(t *testing.T) {
	Convey("Verify log if sync disabled in config", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
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

		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()

		ctlr.Config.Storage.RootDirectory = globalDir

		go func() {
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(baseURL)

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
		baseURL := test.GetBaseURL(port)

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

		So(string(data), ShouldContainSubstring,
			"Prometheus instrumentation Path not set, changing to '/metrics'.")
	})
}

func TestConfigExtensionAPI(t *testing.T) {
	testCases := []struct {
		configContent string
		getStatus     int
		postStatus    int
		putStatus     int
	}{
		{
			configContent: `{
				"distSpecVersion": "0.1.0-dev",
				"storage": {
				  "rootDirectory": "%s"
				},
				"http": {
				  "address": "127.0.0.1",
				  "port": "%s",
				  "realm": "zot",
				  "auth": {
					"htpasswd": {
					  "path": "%s"
					},
					"failDelay": 1
				  },
				  "accessControl": {
					"adminPolicy": {
						"users": ["other"]
					}
				  }
				},
				"extensions":{
					"sysconfig": {
						"enable": true
					}
				},
				"log": {
				  "level": "debug"
				}
			  }`,
			getStatus:  http.StatusForbidden,
			postStatus: http.StatusForbidden,
			putStatus:  http.StatusMethodNotAllowed,
		},
		{
			configContent: `{
				"distSpecVersion": "0.1.0-dev",
				"storage": {
				  "rootDirectory": "%s"
				},
				"http": {
				  "address": "127.0.0.1",
				  "port": "%s",
				  "realm": "zot",
				  "auth": {
					"htpasswd": {
					  "path": "%s"
					},
					"failDelay": 1
				  },
				  "accessControl": {
					"adminPolicy": {
						"users": ["test"],
						"actions": ["read", "create", "update", "delete"]
					}
				  }
				},
				"extensions":{
					"sysconfig": {
						"enable": true
					}
				},
				"log": {
				  "level": "debug"
				}
			  }`,
			getStatus:  http.StatusOK,
			postStatus: http.StatusAccepted,
			putStatus:  http.StatusMethodNotAllowed,
		},
	}

	Convey("Verify config http handler", t, func() {
		for _, testCase := range testCases {
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			logFile, err := os.CreateTemp("", "zot-log*.txt")
			So(err, ShouldBeNil)

			hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
			if err != nil {
				panic(err)
			}

			usernameAndHash := fmt.Sprintf("%s:%s\n%s:%s", username, string(hash), "nonadmin", string(hash))

			htpasswdPath := test.MakeHtpasswdFileFromString(usernameAndHash)
			defer os.Remove(htpasswdPath)

			defer os.Remove(logFile.Name()) // clean up

			content := fmt.Sprintf(testCase.configContent, t.TempDir(), port, htpasswdPath)
			cfgfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)

			defer os.Remove(cfgfile.Name()) // clean up

			_, err = cfgfile.Write([]byte(content))
			So(err, ShouldBeNil)

			err = cfgfile.Close()
			So(err, ShouldBeNil)

			os.Args = []string{"cli_test", "serve", cfgfile.Name()}

			go func() {
				err = cli.NewServerRootCmd().Execute()
				So(err, ShouldBeNil)
			}()

			test.WaitTillServerReady(baseURL)

			// get config
			resp, err := resty.R().SetBasicAuth("nonadmin", password).
				Get(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// get config
			resp, err = resty.R().SetBasicAuth(username, password).
				Get(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, testCase.getStatus)

			// post config
			resp, err = resty.R().SetBasicAuth(username, password).
				SetHeader("Content-Type", "application/json").
				SetBody([]byte(content)).
				Post(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, testCase.postStatus)

			// put config should fail
			resp, err = resty.R().SetBasicAuth(username, password).
				Put(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, testCase.putStatus)
		}
	})
}

func TestConfigExtensionAPIErrors(t *testing.T) {
	Convey("Verify config http handler", t, func() {
		username := "test"
		password := "test"

		configContent := `{
			"distSpecVersion": "0.1.0-dev",
			"storage": {
				"rootDirectory": "%s"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s",
				"realm": "zot",
				"auth": {
				"htpasswd": {
					"path": "%s"
				},
				"failDelay": 1
				},
				"accessControl": {
				"adminPolicy": {
					"users": ["test"]
				}
				}
			},
			"extensions":{
				"sysconfig": {
					"enable": true
				}
			},
			"log": {
				"level": "debug"
			}
			}`
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
		if err != nil {
			panic(err)
		}

		usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

		htpasswdPath := test.MakeHtpasswdFileFromString(usernameAndHash)
		defer os.Remove(htpasswdPath)

		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(configContent, t.TempDir(), port, htpasswdPath)
		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)

		defer os.Remove(cfgfile.Name()) // clean up

		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		Convey("GET read config error", func() {
			// trigger permission denied on reading config file when GET
			err = os.Chmod(cfgfile.Name(), 0o000)
			So(err, ShouldBeNil)

			// get config
			resp, err := resty.R().SetBasicAuth(username, password).
				Get(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
		Convey("POST errors", func() {
			// trigger unmarshall error
			resp, err := resty.R().SetBasicAuth(username, password).
				SetHeader("Content-Type", "application/json").
				SetBody([]byte("{}")).
				Post(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			// trigger invalid config error
			badConfig := `
				{"log": {"level":"debug"}}
			`
			resp, err = resty.R().SetBasicAuth(username, password).
				SetHeader("Content-Type", "application/json").
				SetBody([]byte(badConfig)).
				Post(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			// trigger write config error
			err = os.Chmod(cfgfile.Name(), 0o000)
			So(err, ShouldBeNil)

			resp, err = resty.R().SetBasicAuth(username, password).
				SetHeader("Content-Type", "application/json").
				SetBody([]byte(content)).
				Post(baseURL + constants.ExtConfigPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
	})
}
