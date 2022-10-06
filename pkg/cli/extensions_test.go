//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package cli_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/cli"
	. "zotregistry.io/zot/pkg/test"
)

const readLogFileTimeout = 5 * time.Second

func TestServeExtensions(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("config file with no extensions", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		logFile, err := os.CreateTemp("", "zot-log*.txt")
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

		WaitTillServerReady(baseURL)
		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null") //nolint:lll // gofumpt conflicts with lll
	})
}

func testWithMetricsEnabled(cfgContentFormat string) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)
	logFile, err := os.CreateTemp("", "zot-log*.txt")
	So(err, ShouldBeNil)

	defer os.Remove(logFile.Name()) // clean up

	content := fmt.Sprintf(cfgContentFormat, port, logFile.Name())
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
		logFile, err := os.CreateTemp("", "zot-log*.txt")
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
			"Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
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
		So(dataStr, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":{\"Enable\":true,\"Interval\":3600000000000},\"Lint\":null") //nolint:lll // gofumpt conflicts with lll
		So(dataStr, ShouldContainSubstring,
			"Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
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
			"Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.")
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
		So(dataStr, ShouldContainSubstring,
			"\"Extensions\":{\"Search\":null,\"Sync\":null,\"Metrics\":null,\"Scrub\":{\"Enable\":false,\"Interval\":86400000000000},\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
		So(dataStr, ShouldContainSubstring, "Scrub config not provided, skipping scrub")
		So(dataStr, ShouldNotContainSubstring,
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

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
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

		logPath, err := runCLIWithConfig(t.TempDir(), content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		defer os.Remove(logPath) // clean up
		So(string(data), ShouldContainSubstring,
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
		logPath, err := runCLIWithConfig(tempDir, content)
		So(err, ShouldBeNil)
		// to avoid data race when multiple go routines write to trivy DB instance.
		WaitTillTrivyDBDownloadStarted(tempDir)
		defer os.Remove(logPath) // clean up

		substring := "\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":86400000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}" //nolint:lll // gofumpt conflicts with lll
		found, err := readLogFileAndSearchString(logPath, substring, readLogFileTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readLogFileAndSearchString(logPath, "updating the CVE database", readLogFileTimeout)
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

		substring := "\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":3600000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}" //nolint:lll // gofumpt conflicts with lll
		found, err := readLogFileAndSearchString(logPath, substring, readLogFileTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readLogFileAndSearchString(logPath, "updating the CVE database", readLogFileTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		substring = "CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing." //nolint:lll // gofumpt conflicts with lll
		found, err = readLogFileAndSearchString(logPath, substring, readLogFileTimeout)
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
		// to avoid data race when multiple go routines write to trivy DB instance.
		WaitTillTrivyDBDownloadStarted(tempDir)

		substring := "\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":86400000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}" //nolint:lll // gofumpt conflicts with lll
		found, err := readLogFileAndSearchString(logPath, substring, readLogFileTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readLogFileAndSearchString(logPath, "updating the CVE database", readLogFileTimeout)
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
			"\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":10800000000000},\"Enable\":false},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}") //nolint:lll // gofumpt conflicts with lll
		So(dataStr, ShouldContainSubstring, "CVE config not provided, skipping CVE update")
		So(dataStr, ShouldNotContainSubstring,
			"CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.")
	})
}

func readLogFileAndSearchString(logPath string, stringToMatch string, timeout time.Duration) (bool, error) { //nolint:unparam,lll
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Contains(string(content), stringToMatch) {
				return true, nil
			}
		}
	}
}

// run cli and return output.
func runCLIWithConfig(tempDir string, config string) (string, error) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)

	logFile, err := os.CreateTemp(tempDir, "zot-log*.txt")
	if err != nil {
		return "", err
	}

	cfgfile, err := os.CreateTemp(tempDir, "zot-test*.json")
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

	return logFile.Name(), nil
}
