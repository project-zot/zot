//go:build search

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestConfigReloader(t *testing.T) {
	Convey("reload access control config", t, func() {
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
			  "port": "0",
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
		  }`, t.TempDir(), htpasswdPath, logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()
		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

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
			  "port": "0",
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
		}`, t.TempDir(), htpasswdPath, logPath)

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

	Convey("reload gc config", t, func() {
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
					"port": "0"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				}
			}`, t.TempDir(), t.TempDir(), logFile.Name())

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

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
				"port": "0"
			},
			"log": {
				"level": "debug",
				"output": "%s"
			}
		}`, t.TempDir(), t.TempDir(), logFile.Name())

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

	Convey("reload sync config", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "0"
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
			}`, t.TempDir(), logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

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
				"port": "0"
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
		}`, t.TempDir(), logPath)

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

	Convey("reload scrub and CVE config", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "0"
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
			}`, t.TempDir(), logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

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
				"port": "0"
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
		}`, t.TempDir(), logPath)

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

	Convey("reload bad config", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "0"
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
			}`, t.TempDir(), logPath)

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()

		_, err := cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

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

func TestConfigReloaderKubernetesConfigMapUpdate(t *testing.T) {
	Convey("reload config on a Kubernetes-style atomic symlink swap", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		username := "alice"
		password := "alice"

		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))
		rootDir := t.TempDir()

		mkConfig := func(user string) string {
			return fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {
				  "rootDirectory": "%s"
				},
				"http": {
				  "address": "127.0.0.1",
				  "port": "0",
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
						  	"users": ["%s"],
						  	"actions": ["read"]
							}
					  	],
					  	"defaultPolicy": ["read"]
						}
					}
				  }
				},
				"log": {
				  "level": "debug",
				  "output": "%s"
				}
			  }`, rootDir, htpasswdPath, user, logPath)
		}

		// Lay the config out the way kubelet's AtomicWriter mounts a ConfigMap:
		// config.json -> ..data/config.json -> ..<timestamped dir>/config.json
		mountDir := t.TempDir()
		payloadV1 := filepath.Join(mountDir, "..2024_01_01")
		So(os.MkdirAll(payloadV1, 0o755), ShouldBeNil)
		So(os.WriteFile(filepath.Join(payloadV1, "config.json"), []byte(mkConfig("charlie")), 0o600), ShouldBeNil)
		So(os.Symlink("..2024_01_01", filepath.Join(mountDir, "..data")), ShouldBeNil)
		So(os.Symlink(filepath.Join("..data", "config.json"), filepath.Join(mountDir, "config.json")), ShouldBeNil)

		So(startServerFromConfigFile(t, filepath.Join(mountDir, "config.json")), ShouldBeNil)

		// Update the way kubelet does: write the new payload dir, atomically
		// retarget the ..data symlink via rename(2), remove the old payload.
		// No Write event is ever emitted for config.json itself.
		payloadV2 := filepath.Join(mountDir, "..2024_01_02")
		So(os.MkdirAll(payloadV2, 0o755), ShouldBeNil)
		So(os.WriteFile(filepath.Join(payloadV2, "config.json"), []byte(mkConfig("alice")), 0o600), ShouldBeNil)
		So(os.Symlink("..2024_01_02", filepath.Join(mountDir, "..data_tmp")), ShouldBeNil)
		So(os.Rename(filepath.Join(mountDir, "..data_tmp"), filepath.Join(mountDir, "..data")), ShouldBeNil)
		So(os.RemoveAll(payloadV1), ShouldBeNil)

		// wait for the reload: debounced event or, at the latest, a poll tick
		reloaded := false

		for range 100 {
			time.Sleep(100 * time.Millisecond)

			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)

			if strings.Contains(string(data), "\"Users\":[\"alice\"]") {
				reloaded = true

				break
			}
		}

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		t.Logf("log file: %s", data)
		So(reloaded, ShouldBeTrue)
		So(string(data), ShouldContainSubstring, "reloaded params")
		So(string(data), ShouldContainSubstring, "loaded new configuration settings")
	})
}

func TestConfigReloaderNonReloadableWarn(t *testing.T) {
	Convey("warn when a changed config field is outside the reloadable set", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		mkContent := func(rootDir string, gc bool) string {
			return fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "%s", "gc": %t},
				"http": {"address": "127.0.0.1", "port": "0"},
				"log": {"level": "debug", "output": "%s"}
			}`, rootDir, gc, logPath)
		}

		rootDirA := t.TempDir()
		rootDirB := t.TempDir()

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()
		_, err := cfgfile.WriteString(mkContent(rootDirA, false))
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

		// change one reloadable field (gc) and one non-reloadable field (rootDirectory)
		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)
		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)
		_, err = cfgfile.WriteString(mkContent(rootDirB, true))
		So(err, ShouldBeNil)
		So(cfgfile.Close(), ShouldBeNil)

		found := false

		for range 100 {
			time.Sleep(100 * time.Millisecond)

			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)

			if strings.Contains(string(data), "outside the reloadable set") {
				found = true

				break
			}
		}

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		t.Logf("log file: %s", data)
		So(found, ShouldBeTrue)
		So(string(data), ShouldContainSubstring, "Storage.RootDirectory")
		// the reloadable field was applied, so it is not in the warning
		So(string(data), ShouldContainSubstring, "reloaded params")
	})
}

func TestConfigReloaderLdapTransitions(t *testing.T) {
	Convey("adding and removing ldap auth on reload", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString("alice", "alice"))
		rootDir := t.TempDir()

		credsFile := test.MakeTempFile(t, "ldap-creds.json")
		_, err := credsFile.WriteString(`{"bindDN":"cn=ro,dc=example,dc=org","bindPassword":"ro-pass"}`)
		So(err, ShouldBeNil)
		So(credsFile.Close(), ShouldBeNil)

		mkConfig := func(withLdap bool) string {
			ldap := ""
			if withLdap {
				ldap = fmt.Sprintf(`"ldap": {
					"credentialsFile": "%s",
					"address": "127.0.0.1",
					"port": 10389,
					"baseDN": "ou=users,dc=example,dc=org",
					"userAttribute": "uid"
				},`, credsFile.Name())
			}

			return fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "%s"},
				"http": {
					"address": "127.0.0.1", "port": "0", "realm": "zot",
					"auth": {%s "htpasswd": {"path": "%s"}, "failDelay": 1}
				},
				"log": {"level": "debug", "output": "%s"}
			}`, rootDir, ldap, htpasswdPath, logPath)
		}

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()
		_, err = cfgfile.WriteString(mkConfig(false))
		So(err, ShouldBeNil)

		baseURL, err := startServerFromConfigFileURL(t, cfgfile.Name())
		So(err, ShouldBeNil)

		rewrite := func(content string) {
			So(cfgfile.Truncate(0), ShouldBeNil)
			_, err := cfgfile.Seek(0, io.SeekStart)
			So(err, ShouldBeNil)
			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)
			So(cfgfile.Sync(), ShouldBeNil)
		}

		// latest "basic authentication (LDAP)" log entry wins: startup and every
		// reload emit one
		waitForLdap := func(want bool) bool {
			for range 100 {
				time.Sleep(100 * time.Millisecond)

				data, err := os.ReadFile(logPath)
				So(err, ShouldBeNil)

				val, found := false, false

				for line := range strings.SplitSeq(string(data), "\n") {
					var entry map[string]any
					if json.Unmarshal([]byte(line), &entry) != nil {
						continue
					}

					if entry["message"] == "basic authentication (LDAP)" {
						if enabled, ok := entry["enabled"].(bool); ok {
							val, found = enabled, true
						}
					}
				}

				if found && val == want {
					return true
				}
			}

			return false
		}

		// enable ldap on reload: previously the credentials file was never
		// picked up for watching on this transition
		rewrite(mkConfig(true))
		So(waitForLdap(true), ShouldBeTrue)

		// a failed htpasswd login now falls through to the ldap path, which has
		// no client when ldap was enabled by reload: must 401, not panic
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			baseURL+"/v2/", nil)
		So(err, ShouldBeNil)
		request.SetBasicAuth("alice", "wrong-password")

		resp, err := http.DefaultClient.Do(request)
		So(err, ShouldBeNil)
		So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
		So(resp.Body.Close(), ShouldBeNil)

		// disable ldap on reload: previously a nil dereference in the reloader
		rewrite(mkConfig(false))
		So(waitForLdap(false), ShouldBeTrue)

		// the reloader survived both transitions: one more reload still lands
		rewrite(mkConfig(true))
		So(waitForLdap(true), ShouldBeTrue)
	})
}

func TestConfigReloaderInvalidConfig(t *testing.T) {
	Convey("an invalid rewrite is retried on the next change, not every poll tick", t, func() {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")
		rootDir := t.TempDir()

		mkConfig := func(level string) string {
			return fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
				"storage": {"rootDirectory": "%s"},
				"http": {"address": "127.0.0.1", "port": "0"},
				"log": {"level": "%s", "output": "%s"}
			}`, rootDir, level, logPath)
		}

		cfgfile := test.MakeTempFile(t, "zot-test.json")
		defer cfgfile.Close()
		_, err := cfgfile.WriteString(mkConfig("debug"))
		So(err, ShouldBeNil)

		So(startServerFromConfigFile(t, cfgfile.Name()), ShouldBeNil)

		rewrite := func(content string) {
			So(cfgfile.Truncate(0), ShouldBeNil)
			_, err := cfgfile.Seek(0, io.SeekStart)
			So(err, ShouldBeNil)
			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)
			So(cfgfile.Sync(), ShouldBeNil)
		}

		countFailures := func() int {
			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)

			return strings.Count(string(data), "failed to reload config")
		}

		rewrite(`{not json`)
		time.Sleep(4 * time.Second)

		failures := countFailures()
		So(failures, ShouldBeGreaterThanOrEqualTo, 1)
		// a 1s poll would have logged a failure per tick for 4s
		So(failures, ShouldBeLessThanOrEqualTo, 2)

		// a valid rewrite still lands
		rewrite(mkConfig("info"))

		reloaded := false

		for range 100 {
			time.Sleep(100 * time.Millisecond)

			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)

			if strings.Contains(string(data), "reloaded params") {
				reloaded = true

				break
			}
		}

		So(reloaded, ShouldBeTrue)
	})
}
