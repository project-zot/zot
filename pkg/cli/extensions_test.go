//go:build sync && scrub && metrics && search && ui_base
// +build sync,scrub,metrics,search,ui_base

package cli_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/cli"
	. "zotregistry.io/zot/pkg/test"
)

func TestServeExtensions(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("config file with no extensions", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(`{
			"storage": {
				"rootDirectory": "/tmp/zot"
			},
			"http": {
				"address": "127.0.0.1",
				"port": "%s"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			}
		}`, port, logFile.Name())

		cfgfile, err := ioutil.TempFile("", "zot-test*.json")
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

		WaitTillServerReady(baseURL)
		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"Extensions\":null")
	})

	Convey("config file with empty extensions", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(`{
			"storage": {
				"rootDirectory": "/tmp/zot"
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
		}`, port, logFile.Name())

		cfgfile, err := ioutil.TempFile("", "zot-test*.json")
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

		WaitTillServerReady(baseURL)
		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null") //nolint:lll // gofumpt conflicts with lll
	})
}

func testWithMetricsEnabled(cfgContentFormat string) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)
	logFile, err := ioutil.TempFile("", "zot-log*.txt")
	So(err, ShouldBeNil)

	defer os.Remove(logFile.Name()) // clean up

	content := fmt.Sprintf(cfgContentFormat, port, logFile.Name())
	cfgfile, err := ioutil.TempFile("", "zot-test*.json")
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
		"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":{\"Enable\":true,\"Prometheus\":{\"Path\":\"/metrics\"}},\"Scrub\":null,\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
}

func TestServeMetricsExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("no explicit enable", t, func(c C) {
		content := `{
			"storage": {
				"rootDirectory": "/tmp/zot"
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
		testWithMetricsEnabled(content)
	})

	Convey("no explicit enable but with prometheus parameter", t, func(c C) {
		content := `{
			"storage": {
				"rootDirectory": "/tmp/zot"
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
		testWithMetricsEnabled(content)
	})

	Convey("with explicit enable, but without prometheus parameter", t, func(c C) {
		content := `{
			"storage": {
				"rootDirectory": "/tmp/zot"
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
		testWithMetricsEnabled(content)
	})

	Convey("with explicit disable", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(`{
					"storage": {
						"rootDirectory": "/tmp/zot"
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
				}`, port, logFile.Name())

		cfgfile, err := ioutil.TempFile("", "zot-test*.json")
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
		WaitTillServerReady(baseURL)

		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":{\"Enable\":false,\"Prometheus\":{\"Path\":\"/metrics\"}},\"Scrub\":null,\"Lint\":null}}") //nolint:lll // gofumpt conflicts with lll
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

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
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

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
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

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":{\"Enable\":false")
	})
}

func TestServeScrubExtension(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("scrub enabled by scrub interval param set", t, func(c C) {
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

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		// Even if in config we specified scrub interval=1h, the minimum interval is 2h
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":{\"Interval\":3600000000000},\"Lint\":null") //nolint:lll // gofumpt conflicts with lll
		So(data, ShouldContainSubstring,
			"Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
		So(data, ShouldContainSubstring, "Starting periodic background tasks for")
		So(data, ShouldContainSubstring, "Finishing periodic background tasks for")
	})

	Convey("scrub not enabled - scrub interval param not set", t, func(c C) {
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

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}")
		So(data, ShouldContainSubstring, "Scrub config not provided, skipping scrub")
		So(data, ShouldNotContainSubstring,
			"Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
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
							"enabled": "true",
							"mandatoryAnnotations": ["annot1"]
						}
					}
				}`

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":{\"Enabled\":true,\"MandatoryAnnotations\":") //nolint:lll // gofumpt conflicts with lll
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
							"enabled": "false"
						}
					}
				}`

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":{\"Enabled\":false,\"MandatoryAnnotations\":null}") //nolint:lll // gofumpt conflicts with lll
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
		data, err := runCLIWithConfig(tempDir, content)
		// to avoid data race when multiple go routines write to trivy DB instance.
		WaitTillTrivyDBDownloadStarted(tempDir)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":86400000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
		So(data, ShouldContainSubstring, "updating the CVE database")
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
		data, err := runCLIWithConfig(tempDir, content)
		// to avoid data race when multiple go routines write to trivy DB instance.
		WaitTillTrivyDBDownloadStarted(tempDir)
		So(err, ShouldBeNil)
		// Even if in config we specified updateInterval=1h, the minimum interval is 2h
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":3600000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
		So(data, ShouldContainSubstring, "updating the CVE database")
		So(data, ShouldContainSubstring,
			"CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.")
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
		data, err := runCLIWithConfig(tempDir, content)
		// to avoid data race when multiple go routines write to trivy DB instance.
		WaitTillTrivyDBDownloadStarted(tempDir)
		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":86400000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
		So(data, ShouldContainSubstring, "updating the CVE database")
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

		data, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)

		So(err, ShouldBeNil)
		So(data, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":10800000000000},\"Enable\":false},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
		So(data, ShouldContainSubstring, "CVE config not provided, skipping CVE update")
		So(data, ShouldNotContainSubstring,
			"CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.")
	})
}

// run cli and return output.
func runCLIWithConfig(tempDir string, config string) (string, error) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)

	logFile, err := ioutil.TempFile(tempDir, "zot-log*.txt")
	if err != nil {
		return "", err
	}

	defer os.Remove(logFile.Name()) // clean up

	cfgfile, err := ioutil.TempFile(tempDir, "zot-test*.json")
	if err != nil {
		return "", err
	}

	config = fmt.Sprintf(config, tempDir, port, logFile.Name())

	_, err = cfgfile.Write([]byte(config))
	if err != nil {
		return "", err
	}

	err = cfgfile.Close()
	if err != nil {
		return "", err
	}

	os.Args = []string{"cli_test", "serve", cfgfile.Name()}

	go func() {
		err = cli.NewServerRootCmd().Execute()
		if err != nil {
			panic(err)
		}
	}()

	WaitTillServerReady(baseURL)

	data, err := os.ReadFile(logFile.Name())
	So(err, ShouldBeNil)

	return string(data), nil
}
