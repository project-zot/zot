//go:build sync && scrub && metrics && search && userprefs && mgmt && imagetrust
// +build sync,scrub,metrics,search,userprefs,mgmt,imagetrust

package server_test

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api/config"
	cli "zotregistry.dev/zot/pkg/cli/server"
	. "zotregistry.dev/zot/pkg/test/common"
)

const readLogFileTimeout = 5 * time.Second

func TestVerifyExtensionsConfig(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test verify CVE warn for remote storage", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up

		content := fmt.Sprintf(`{
			"storage":{
				"rootDirectory":"%s",
				"dedupe":true,
				"remoteCache":false,
				"storageDriver":{
					"name":"s3",
					"rootdirectory":"/zot",
					"region":"us-east-2",
					"bucket":"zot-storage",
					"secure":true,
					"skipverify":false
				}
			},
			"http":{
				"address":"127.0.0.1",
				"port":"8080"
			},
			"extensions":{
				"search": {
					"enable": true,
					"cve": {
						"updateInterval": "24h"
					}
				}
			}
		}`, t.TempDir())

		err = os.WriteFile(tmpfile.Name(), []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)

		content = fmt.Sprintf(`{
			"storage":{
				"rootDirectory":"%s",
				"dedupe":true,
				"remoteCache":false,
				"subPaths":{
					"/a": {
						"rootDirectory": "%s",
						"dedupe": false,
						"storageDriver":{
							"name":"s3",
							"rootdirectory":"/zot-a",
							"region":"us-east-2",
							"bucket":"zot-storage",
							"secure":true,
							"skipverify":false
						}
					}
				}
			},
			"http":{
				"address":"127.0.0.1",
				"port":"8080"
			},
			"extensions":{
				"search": {
					"enable": true,
					"cve": {
						"updateInterval": "24h"
					}
				}
			}
		}`, t.TempDir(), t.TempDir())
		err = os.WriteFile(tmpfile.Name(), []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})

	Convey("Test verify w/ sync and w/o filesystem storage", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s", "storageDriver": {"name": "s3"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s"}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})

	Convey("Test verify w/ sync and w/ filesystem storage", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s"}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldBeNil)
	})

	Convey("Test verify with bad sync prefixes", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"[repo^&["}]}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})

	Convey("Test verify with bad sync content config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"zot-repo","stripPrefix":true,"destination":"/"}]}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})

	Convey("Test verify with good sync content config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"zot-repo/*","stripPrefix":true,"destination":"/"}]}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify sync config default tls value", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"repo**"}]}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify sync without retry options", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{"storage":{"rootDirectory":"%s"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 10, "content": [{"prefix":"repo**"}]}]}}}`, t.TempDir())
		_, err = tmpfile.WriteString(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})
}

func TestValidateExtensionsConfig(t *testing.T) {
	Convey("Legacy extensions should not error", t, func(c C) {
		config := config.New()
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name())
		content := []byte(`{
			"storage": {
				"rootDirectory": "%/tmp/zot"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "8080"
			},
			"log": {
				"level": "debug"
			},
			"extensions": {
				"mgmt": {
					"enable": "true"
				},
				"apikey": {
					"enable": "true"
				}
			}
		}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldBeNil)
	})

	Convey("Test missing extensions for UI to work", t, func(c C) {
		config := config.New()
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name())
		content := []byte(`{
			"storage": {
				"rootDirectory": "%/tmp/zot"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "8080"
			},
			"log": {
				"level": "debug"
			},
			"extensions": {
				"ui": {
					"enable": "true"
				}
			}
		}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)
	})

	Convey("Test enabling UI extension with all prerequisites", t, func(c C) {
		config := config.New()
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name())

		content := []byte(`{
			"storage": {
				"rootDirectory": "%/tmp/zot"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "8080"
			},
			"log": {
				"level": "debug"
			},
			"extensions": {
				"ui": {
					"enable": "true"
				},
				"search": {
					"enable": "true"
				}
			}
		}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldBeNil)
	})

	Convey("Test extension are implicitly enabled", t, func(c C) {
		config := config.New()
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name())

		content := []byte(`{
			"storage": {
				"rootDirectory": "%/tmp/zot"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "8080"
			},
			"log": {
				"level": "debug"
			},
			"extensions": {
				"ui": {},
				"search": {},
				"metrics": {},
				"trust": {},
				"scrub": {}
			}
		}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldBeNil)
		So(config.Extensions.UI, ShouldNotBeNil)
		So(*config.Extensions.UI.Enable, ShouldBeTrue)
		So(config.Extensions.Search, ShouldNotBeNil)
		So(*config.Extensions.Search.Enable, ShouldBeTrue)
		So(config.Extensions.Trust, ShouldNotBeNil)
		So(*config.Extensions.Trust.Enable, ShouldBeTrue)
		So(*config.Extensions.Metrics, ShouldNotBeNil)
		So(*config.Extensions.Metrics.Enable, ShouldBeTrue)
		So(config.Extensions.Scrub, ShouldNotBeNil)
		So(*config.Extensions.Scrub.Enable, ShouldBeTrue)
	})
}

func TestServeExtensions(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("config file with no extensions", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up
		tmpFile := t.TempDir()

		content := fmt.Sprintf(`{
			"storage": {
				"rootDirectory": "%s"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			}
		}`, tmpFile, port, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(cfgfile.Name()) // clean up
		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)
		err = cfgfile.Close()
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			Convey("run", t, func() {
				err = cli.NewServerRootCmd().Execute()
				So(err, ShouldBeNil)
			})
		}()

		WaitTillServerReady(baseURL)
		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"Extensions\":null")
	})

	Convey("config file with empty extensions", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up
		tmpFile := t.TempDir()

		content := fmt.Sprintf(`{
			"storage": {
				"rootDirectory": "%s"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
			}
		}`, tmpFile, port, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(cfgfile.Name()) // clean up
		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)
		err = cfgfile.Close()
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}

		go func() {
			Convey("run", t, func() {
				err = cli.NewServerRootCmd().Execute()
				So(err, ShouldBeNil)
			})
		}()

		WaitTillServerReady(baseURL)
		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null,\"UI\":null,\"Mgmt\":null") //nolint:lll // gofumpt conflicts with lll
	})
}

func testWithMetricsEnabled(t *testing.T, rootDir string, cfgContentFormat string) {
	t.Helper()
	port := GetFreePort()
	baseURL := GetBaseURL(port)
	logFile, err := os.CreateTemp("", "zot-log*.txt")
	So(err, ShouldBeNil)

	defer os.Remove(logFile.Name()) // clean up

	content := fmt.Sprintf(cfgContentFormat, rootDir, port, logFile.Name())
	cfgfile, err := os.CreateTemp("", "zot-test*.json")
	So(err, ShouldBeNil)

	defer os.Remove(cfgfile.Name()) // clean up
	_, err = cfgfile.WriteString(content)
	So(err, ShouldBeNil)
	err = cfgfile.Close()
	So(err, ShouldBeNil)

	os.Args = []string{"cli_test", "serve", cfgfile.Name()}

	go func() {
		Convey("run", t, func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		})
	}()
	WaitTillServerReady(baseURL)

	resp, err := resty.R().Get(baseURL + "/metrics")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	respStr := string(resp.Body())
	So(respStr, ShouldContainSubstring, "zot_info")

	data, err := os.ReadFile(logFile.Name())
	So(err, ShouldBeNil)
	So(string(data), ShouldContainSubstring,
		"\"Metrics\":{\"Enable\":true,\"Prometheus\":{\"Path\":\"/metrics\"}}")
}

func TestServeMetricsExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("no explicit enable", t, func(c C) {
		tmpFile := t.TempDir()

		content := `{
			"storage": {
				"rootDirectory": "%s"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"metrics": {
				}
			}
		}`
		testWithMetricsEnabled(t, tmpFile, content)
	})

	Convey("no explicit enable but with prometheus parameter", t, func(c C) {
		tmpFile := t.TempDir()

		content := `{
			"storage": {
				"rootDirectory": "%s"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"metrics": {
					"prometheus": {
						"path": "/metrics"
					}
				}
			}
		}`
		testWithMetricsEnabled(t, tmpFile, content)
	})

	Convey("with explicit enable, but without prometheus parameter", t, func(c C) {
		tmpFile := t.TempDir()

		content := `{
			"storage": {
				"rootDirectory": "%s"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"metrics": {
					"enable": true
				}
			}
		}`
		testWithMetricsEnabled(t, tmpFile, content)
	})

	Convey("with explicit disable", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		tmpFile := t.TempDir()
		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(`{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"metrics": {
							"enable": false
						}
					}
				}`, tmpFile, port, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(cfgfile.Name()) // clean up
		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)
		err = cfgfile.Close()
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			Convey("run", t, func() {
				err = cli.NewServerRootCmd().Execute()
				So(err, ShouldBeNil)
			})
		}()
		WaitTillServerReady(baseURL)

		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"\"Metrics\":{\"Enable\":false,\"Prometheus\":{\"Path\":\"/metrics\"}}") //nolint:lll // gofumpt conflicts with lll
	})
}

func TestServeSyncExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("sync implicitly enabled", t, func(c C) {
		content := `{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"sync": {
						"registries": [{
							"urls": ["http://localhost:8080"],
							"tlsVerify": false,
							"onDemand": true,
							"maxRetries": 3,
							"retryDelay": "15m",
							"certDir": "",
							"content":[
								{
									"prefix": "zot-test",
									"tags": {
										"regex": ".*",
										"semver": true
									}
								}
							]
						}]
					}
				}
			}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":{\"Enable\":true")
	})

	Convey("sync explicitly enabled", t, func(c C) {
		content := `{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"sync": {
						"enable": true,
						"registries": [{
							"urls": ["http://localhost:8080"],
							"tlsVerify": false,
							"onDemand": true,
							"maxRetries": 3,
							"retryDelay": "15m",
							"certDir": "",
							"content":[
								{
									"prefix": "zot-test",
									"tags": {
										"regex": ".*",
										"semver": true
									}
								}
							]
						}]
					}
				}
			}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":{\"Enable\":true")
	})

	Convey("sync explicitly disabled", t, func(c C) {
		content := `{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"sync": {
						"enable": false,
						"registries": [{
							"urls": ["http://127.0.0.1:8080"],
							"tlsVerify": false,
							"certDir": "",
							"maxRetries": 3,
							"retryDelay": "15m"
						}]
					}
				}
			}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":{\"Enable\":false")
	})
}

func TestServeScrubExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("scrub implicitly enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"scrub": {
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		dataStr := string(data)
		So(dataStr, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":{\"Enable\":true,\"Interval\":86400000000000},\"Lint\":null") //nolint:lll // gofumpt conflicts with lll
		So(dataStr, ShouldNotContainSubstring,
			"scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
	})

	Convey("scrub implicitly enabled, but with scrub interval param set", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"scrub": {
							"interval": "1h"
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		// Even if in config we specified scrub interval=1h, the minimum interval is 2h
		dataStr := string(data)
		So(dataStr, ShouldContainSubstring, "\"Scrub\":{\"Enable\":true,\"Interval\":3600000000000}")
		So(dataStr, ShouldContainSubstring,
			"scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
	})

	Convey("scrub explicitly enabled, but without scrub interval param set", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"scrub": {
							"enable": true
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		dataStr := string(data)
		So(dataStr, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":{\"Enable\":true,\"Interval\":86400000000000},\"Lint\":null") //nolint:lll // gofumpt conflicts with lll
		So(dataStr, ShouldNotContainSubstring,
			"scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
	})

	Convey("scrub explicitly disabled", t, func(c C) {
		content := `{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"scrub": {
						"enable": false
					}
				}
			}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		dataStr := string(data)
		So(dataStr, ShouldContainSubstring, "\"Scrub\":{\"Enable\":false,\"Interval\":86400000000000}")
		So(dataStr, ShouldContainSubstring, "scrub config not provided, skipping scrub")
		So(dataStr, ShouldNotContainSubstring,
			"scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
	})
}

func TestServeLintExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("lint enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"lint": {
							"enable": "true",
							"mandatoryAnnotations": ["annot1"]
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":{\"Enable\":true,\"MandatoryAnnotations\":") //nolint:lll // gofumpt conflicts with lll
	})

	Convey("lint enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"lint": {
							"enable": "false"
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":{\"Enable\":false,\"MandatoryAnnotations\":null}") //nolint:lll // gofumpt conflicts with lll
	})
}

func TestServeSearchEnabled(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("search implicitly enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"search": {
						}
					}
				}`

		tempDir := t.TempDir()
		logPath, err := runCLIWithConfig(tempDir, content)
		So(err, ShouldBeNil)
		// to avoid data race when multiple go routines write to trivy DB instance.
		defer os.Remove(logPath) // clean up

		substring := `"Extensions":{"Search":{"Enable":true,"CVE":null}`

		found, err := ReadLogFileAndSearchString(logPath, substring, readLogFileTimeout)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestServeSearchEnabledCVE(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("search implicitly enabled with CVE param set", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"search": {
							"cve": {
								"updateInterval": "1h"
							}
						}
					}
				}`

		tempDir := t.TempDir()
		logPath, err := runCLIWithConfig(tempDir, content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		// to avoid data race when multiple go routines write to trivy DB instance.
		WaitTillTrivyDBDownloadStarted(tempDir)

		// The default config handling logic will convert the 1h interval to a 2h interval
		substring := "\"Search\":{\"Enable\":true,\"CVE\":{\"UpdateInterval\":7200000000000,\"Trivy\":" +
			"{\"DBRepository\":\"ghcr.io/aquasecurity/trivy-db\",\"JavaDBRepository\":\"ghcr.io/aquasecurity/trivy-java-db\"}}}"

		found, err := ReadLogFileAndSearchString(logPath, substring, readLogFileTimeout)

		defer func() {
			if !found {
				data, err := os.ReadFile(logPath)
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()

		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = ReadLogFileAndSearchString(logPath, "updating cve-db", readLogFileTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestServeSearchEnabledNoCVE(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("search explicitly enabled, but CVE parameter not set", t, func(c C) {
		content := `{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"search": {
						"enable": true
					}
				}
			}`

		tempDir := t.TempDir()
		logPath, err := runCLIWithConfig(tempDir, content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up

		substring := `"Extensions":{"Search":{"Enable":true,"CVE":null}` //nolint:lll // gofumpt conflicts with lll
		found, err := ReadLogFileAndSearchString(logPath, substring, readLogFileTimeout)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestServeSearchDisabled(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("search explicitly disabled", t, func(c C) {
		content := `{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"search": {
						"enable": false,
						"cve": {
							"updateInterval": "3h"
						}
					}
				}
			}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		dataStr := string(data)
		So(dataStr, ShouldContainSubstring,
			`"Search":{"Enable":false,"CVE":{"UpdateInterval":10800000000000,"Trivy":null}`)
		So(dataStr, ShouldContainSubstring, "cve config not provided, skipping cve-db update")
		So(dataStr, ShouldNotContainSubstring,
			"CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.")
	})
}

func TestServeMgmtExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Mgmt implicitly enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"search": {
							"enable": true
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		found, err := ReadLogFileAndSearchString(logPath, "setting up mgmt routes", 10*time.Second)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})

	Convey("Mgmt disabled - Search unconfigured", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		found, err := ReadLogFileAndSearchString(logPath,
			"skip enabling the mgmt route as the config prerequisites are not met", 10*time.Second)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})

	Convey("Mgmt disabled - extensions missing", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		found, err := ReadLogFileAndSearchString(logPath,
			"skip enabling the mgmt route as the config prerequisites are not met", 10*time.Second)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})
}

func TestServeImageTrustExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Trust explicitly disabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"trust": {
							"enable": false
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		found, err := ReadLogFileAndSearchString(logPath,
			"skip enabling the image trust routes as the config prerequisites are not met", 10*time.Second)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})

	Convey("Trust explicitly enabled - but cosign and notation disabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"trust": {
							"enable": true
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		found, err := ReadLogFileAndSearchString(logPath,
			"skip enabling the image trust routes as the config prerequisites are not met", 10*time.Second)

		if !found {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)
			t.Log(string(data))
		}

		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})

	Convey("Trust explicitly enabled -  cosign and notation enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s"
					},
					"log": {
						"level": "debug",
						"output": "%s"
					},
					"extensions": {
						"trust": {
							"enable": true,
							"cosign": true,
							"notation": true
						}
					}
				}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		found, err := ReadLogFileAndSearchString(logPath,
			"setting up image trust routes", 10*time.Second)

		defer func() {
			if !found {
				data, err := os.ReadFile(logPath)
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()

		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = ReadLogFileAndSearchString(logPath,
			"setting up notation route", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = ReadLogFileAndSearchString(logPath,
			"setting up cosign route", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})
}

func TestOverlappingSyncRetentionConfig(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test verify without overlapping sync and retention", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := `{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": "2h",
				"gcInterval": "1h",
				"retention": {
					"policies": [
						{
							"repositories": ["infra/*", "prod/*"],
							"deleteReferrers": false,
							"keepTags": [{
								"patterns": ["v4.*", ".*-prod"]
							},
							{
								"patterns": ["v3.*", ".*-prod"],
								"pulledWithin": "168h"
							}]
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"enable": true,
					"registries": [
						{
							"urls": [
								"https://registry1:5000"
							],
							"content": [
								{
									"prefix": "infra/*",
									"tags": {
										"regex": "v4.*",
										"semver": true
									}
								}
							]
						}
					]
				}
			}
		}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldNotContainSubstring, "overlapping sync content")
	})

	Convey("Test verify with overlapping sync and retention - retention would remove v4 tags", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := `{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": "2h",
				"gcInterval": "1h",
				"retention": {
					"policies": [
						{
							"repositories": ["infra/*", "prod/*"],
							"keepTags": [{
								"patterns": ["v2.*", ".*-prod"]
							},
							{
								"patterns": ["v3.*", ".*-prod"]
							}]
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"enable": true,
					"registries": [
						{
							"urls": [
								"https://registry1:5000"
							],
							"content": [
								{
									"prefix": "infra/*",
									"tags": {
										"regex": "4.*",
										"semver": true
									}
								}
							]
						}
					]
				}
			}
		}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring, "overlapping sync content\":{\"Prefix\":\"infra/*")
	})

	Convey("Test verify with overlapping sync and retention - retention would remove tags from repo", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := `{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": "2h",
				"gcInterval": "1h",
				"retention": {
					"dryRun": false,
					"delay": "24h",
					"policies": [
						{
							"repositories": ["tmp/**"],
							"keepTags": [{
								"patterns": ["v1.*"]
							}]
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"enable": true,
					"registries": [
						{
							"urls": [
								"https://registry1:5000"
							],
							"content": [
								{
									"prefix": "**",
									"destination": "/tmp",
									"stripPrefix": true
								}
							]
						}
					]
				}
			}
		}
		`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring, "overlapping sync content\":{\"Prefix\":\"**")
	})

	Convey("Test verify with overlapping sync and retention - retention would remove tags from subpath", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := `{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"gcDelay": "2h",
				"gcInterval": "1h",
				"subPaths": {
					"/synced": {
						"rootDirectory": "/tmp/zot2",
						"dedupe": true,
						"retention": {
							"policies": [
								{
									"repositories": ["infra/*", "prod/*"],
									"deleteReferrers": false,
									"keepTags": [{
									}]
								}
							]
						}
					}
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"enable": true,
					"registries": [
						{
							"urls": [
								"https://registry1:5000"
							],
							"content": [
								{
									"prefix": "prod/*",
									"destination": "/synced"
								}
							]
						}
					]
				}
			}
		}
		`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring, "overlapping sync content\":{\"Prefix\":\"prod/*")
	})
}

func TestSyncWithRemoteStorageConfig(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test verify sync with remote storage works if sync.tmpdir is provided", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up

		content := `{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"dedupe": false,
				"remoteCache": false,
				"storageDriver": {
					"name": "s3",
					"rootdirectory": "/zot",
					"region": "us-east-2",
					"regionendpoint": "localhost:4566",
					"bucket": "zot-storage",
					"secure": false,
					"skipverify": false
				}
			},
			"http": {
				"address": "0.0.0.0",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"downloadDir": "/tmp/sync",
					"registries": [
						{
							"urls": [
								"http://localhost:9000"
							],
							"onDemand": true,
							"tlsVerify": false,
							"content": [
								{
									"prefix": "**"
								}
							]
						}
					]
				}
			}
		}`

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldNotContainSubstring,
			"using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified")
	})

	Convey("Test verify sync with remote storage panics if sync.tmpdir is not provided", t, func(c C) {
		port := GetFreePort()
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up

		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"dedupe": false,
				"remoteCache": false,
				"storageDriver": {
					"name": "s3",
					"rootdirectory": "/zot",
					"region": "us-east-2",
					"regionendpoint": "localhost:4566",
					"bucket": "zot-storage",
					"secure": false,
					"skipverify": false
				}
			},
			"http": {
				"address": "0.0.0.0",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"registries": [
						{
							"urls": [
								"http://localhost:9000"
							],
							"onDemand": true,
							"tlsVerify": false,
							"content": [
								{
									"prefix": "**"
								}
							]
						}
					]
				}
			}
		}`, t.TempDir(), port, logFile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up
		So(string(data), ShouldContainSubstring,
			"using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified")
	})

	Convey("Test verify sync with remote storage on subpath panics if sync.tmpdir is not provided", t, func(c C) {
		port := GetFreePort()
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up

		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.0",
			"storage": {
				"rootDirectory": "%s",
				"subPaths":{
					"/a": {
						"rootDirectory": "%s",
						"dedupe": false,
						"remoteCache": false,
						"storageDriver":{
							"name":"s3",
							"rootdirectory":"/zot-a",
							"region":"us-east-2",
							"bucket":"zot-storage",
							"secure":true,
							"skipverify":true
						}
					}
				}
			},
			"http": {
				"address": "0.0.0.0",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			},
			"extensions": {
				"sync": {
					"registries": [
						{
							"urls": [
								"http://localhost:9000"
							],
							"onDemand": true,
							"tlsVerify": false,
							"content": [
								{
									"prefix": "**"
								}
							]
						}
					]
				}
			}
		}`, t.TempDir(), t.TempDir(), port, logFile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up
		So(string(data), ShouldContainSubstring,
			"using both sync and remote storage features needs config.Extensions.Sync.DownloadDir to be specified")
	})
}
