//go:build search

package server_test

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestConfigReloader(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("reload access control config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		username := "alice"
		password := "alice"

		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		content := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
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
				"repositories": {
					"**": {
				  	"policies": [
						{
					  	"users": ["charlie"],
					  	"actions": ["read"]
						}
				  	],
				  	"defaultPolicy": ["read", "create"]
					}
				},
				"adminPolicy": {
					"users": ["admin"],
					"actions": ["read", "create", "update", "delete"]
				}
			  }
			},
			"log": {
			  "level": "debug",
			  "output": "%s"
			}
		  }`, t.TempDir(), port, htpasswdPath, logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()
		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}

		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		// verify initial startup authentication logs
		initialData, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(initialData), ShouldContainSubstring, "configuration settings")
		// verify authentication methods status messages are present in initial startup
		verifyAuthenticationLogs(initialData, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": true,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})

		content = fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
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
				"repositories": {
					"**": {
				  	"policies": [
						{
					  	"users": ["alice"],
					  	"actions": ["read", "create", "update", "delete"]
						}
				  	],
				  	"defaultPolicy": ["read"]
					}
				},
				"adminPolicy": {
					"users": ["admin"],
					"actions": ["read", "create", "update", "delete"]
				}
			  }
			},
			"log": {
			  "level": "debug",
			  "output": "%s"
			}
		}`, t.TempDir(), port, htpasswdPath, logPath)

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(2 * time.Second)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		t.Logf("log file: %s", data)
		So(string(data), ShouldContainSubstring, "reloaded params")
		So(string(data), ShouldContainSubstring, "loaded new configuration settings")
		So(string(data), ShouldContainSubstring, "\"Users\":[\"alice\"]")
		So(string(data), ShouldContainSubstring, "\"Actions\":[\"read\",\"create\",\"update\",\"delete\"]")
		// verify authentication methods status messages are present
		verifyAuthenticationLogs(data, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": true,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})
	})

	Convey("reload gc config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logFile := test.MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "%s",
					"gc": false,
					"dedupe": false,
					"subPaths": {
						"/a": {
							"rootDirectory": "%s",
							"gc": false,
							"dedupe": false
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
				}
			}`, t.TempDir(), t.TempDir(), port, logFile.Name())

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}

		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		// verify initial startup authentication logs (no auth configured)
		initialData, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(initialData), ShouldContainSubstring, "configuration settings")
		// verify authentication methods status messages are present in initial startup
		verifyAuthenticationLogs(initialData, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})

		content = fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "%s",
				"gc": true,
				"dedupe": true,
				"subPaths": {
					"/a": {
						"rootDirectory": "%s",
						"gc": true,
						"dedupe": true
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
			}
		}`, t.TempDir(), t.TempDir(), port, logFile.Name())

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		// truncate log before changing config, for the ShouldNotContainString
		So(logFile.Truncate(0), ShouldBeNil)
		err = logFile.Close()
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(2 * time.Second)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		t.Logf("log file: %s", data)

		So(string(data), ShouldContainSubstring, "reloaded params")
		So(string(data), ShouldContainSubstring, "loaded new configuration settings")
		So(string(data), ShouldContainSubstring, "\"GC\":true")
		So(string(data), ShouldContainSubstring, "\"Dedupe\":true")
		So(string(data), ShouldNotContainSubstring, "\"GC\":false")
		So(string(data), ShouldNotContainSubstring, "\"Dedupe\":false")
		// verify authentication methods status messages are present
		verifyAuthenticationLogs(data, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})
	})

	Convey("reload sync config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
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
			}`, t.TempDir(), port, logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}

		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		// verify initial startup authentication logs (no auth configured)
		initialData, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(initialData), ShouldContainSubstring, "configuration settings")
		// verify authentication methods status messages are present in initial startup
		verifyAuthenticationLogs(initialData, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})

		content = fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
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
						"urls": ["http://localhost:9999"],
						"tlsVerify": true,
						"onDemand": false,
						"maxRetries": 10,
						"retryDelay": "5m",
						"certDir": "certs",
						"content":[
							{
								"prefix": "zot-cve-test",
								"tags": {
									"regex": "tag",
									"semver": false
								}
							}
						]
					}]
				}
			}
		}`, t.TempDir(), port, logPath)

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(2 * time.Second)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		t.Logf("log file: %s", data)

		So(string(data), ShouldContainSubstring, "reloaded params")
		So(string(data), ShouldContainSubstring, "loaded new configuration settings")
		So(string(data), ShouldContainSubstring, "\"URLs\":[\"http://localhost:9999\"]")
		So(string(data), ShouldContainSubstring, "\"TLSVerify\":true")
		So(string(data), ShouldContainSubstring, "\"OnDemand\":false")
		So(string(data), ShouldContainSubstring, "\"MaxRetries\":10")
		So(string(data), ShouldContainSubstring, "\"RetryDelay\":300000000000")
		So(string(data), ShouldContainSubstring, "\"CertDir\":\"certs\"")
		So(string(data), ShouldContainSubstring, "\"Prefix\":\"zot-cve-test\"")
		So(string(data), ShouldContainSubstring, "\"Regex\":\"tag\"")
		So(string(data), ShouldContainSubstring, "\"Semver\":false")
		// verify authentication methods status messages are present
		verifyAuthenticationLogs(data, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})
	})

	Convey("reload scrub and CVE config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
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
							"updateInterval": "24h",
							"trivy": {
								"DBRepository": "unreachable/trivy/url1"
							}
						}
					},
					"scrub": {
						"enable": true,
						"interval": "24h"
					}
				}
			}`, t.TempDir(), port, logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}

		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		// verify initial startup authentication logs (no auth configured)
		initialData, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(initialData), ShouldContainSubstring, "configuration settings")
		// verify authentication methods status messages are present in initial startup
		verifyAuthenticationLogs(initialData, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})

		content = fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
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
						"updateInterval": "5h",
						"trivy": {
							"DBRepository": "another/unreachable/trivy/url2"
						}
					}
				}
			}
		}`, t.TempDir(), port, logPath)

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(5 * time.Second)

		// Wait for the async trivy download to fail and log the error
		found, err := test.ReadLogFileAndSearchString(logPath,
			"failed to download trivy-db to destination dir", 30*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// Now read the file once and check all the expected log content
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		t.Logf("log file: %s", data)

		So(string(data), ShouldContainSubstring, "reloaded params")
		So(string(data), ShouldContainSubstring, "loaded new configuration settings")
		So(string(data), ShouldContainSubstring, "\"UpdateInterval\":18000000000000")
		So(string(data), ShouldContainSubstring, "\"Scrub\":null")
		So(string(data), ShouldContainSubstring, "\"DBRepository\":\"another/unreachable/trivy/url2\"")
		// verify authentication methods status messages are present
		verifyAuthenticationLogs(data, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  false,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})

		// Just verify the new URL appears in the logs to confirm config reload worked and ignore
		// the order of json message formatting that can change independent of this functional
		// test.
		found, err = test.ReadLogFileAndSearchString(logPath,
			"index.docker.io/another/unreachable/trivy/url2", 1*time.Minute)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})

	Convey("reload bad config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
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
			}`, t.TempDir(), port, logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}

		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		content = "[]"

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(2 * time.Second)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		t.Logf("log file: %s", data)

		So(string(data), ShouldNotContainSubstring, "reloaded params")
		So(string(data), ShouldNotContainSubstring, "new configuration settings")
		So(string(data), ShouldContainSubstring, "\"URLs\":[\"http://localhost:8080\"]")
		So(string(data), ShouldContainSubstring, "\"TLSVerify\":false")
		So(string(data), ShouldContainSubstring, "\"OnDemand\":true")
		So(string(data), ShouldContainSubstring, "\"MaxRetries\":3")
		So(string(data), ShouldContainSubstring, "\"CertDir\":\"\"")
		So(string(data), ShouldContainSubstring, "\"Prefix\":\"zot-test\"")
		So(string(data), ShouldContainSubstring, "\"Regex\":\".*\"")
		So(string(data), ShouldContainSubstring, "\"Semver\":true")
	})
}
