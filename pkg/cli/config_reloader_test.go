package cli_test

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"

	"zotregistry.io/zot/pkg/cli"
	"zotregistry.io/zot/pkg/test"
)

const (
	username = "test"
	password = "test"
)

func TestConfigReloader(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("reload access control config", t, func(c C) {
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

		content := fmt.Sprintf(`{
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
				"repositories": {
					"**": {
						"policies": [
						  {
							"users": ["other"],
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
		  }`, t.TempDir(), port, htpasswdPath, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)

		defer os.Remove(cfgfile.Name()) // clean up

		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)

		// err = cfgfile.Close()
		// So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		content = fmt.Sprintf(`{
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
				"repositories": {
					"**": {
					"policies": [
						{
						"users": ["test"],
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
		}`, t.TempDir(), port, htpasswdPath, logFile.Name())

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(3 * time.Second)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"Users\":[\"test\"]")
		So(string(data), ShouldContainSubstring, "\"Actions\":[\"read\",\"create\",\"update\",\"delete\"]")
	})

	Convey("reload sync config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(`{
				"distSpecVersion": "0.1.0-dev",
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
							"pollInterval": "1m",
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
			}`, t.TempDir(), port, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)

		defer os.Remove(cfgfile.Name()) // clean up

		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)

		// err = cfgfile.Close()
		// So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		content = fmt.Sprintf(`{
			"distSpecVersion": "0.1.0-dev",
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
						"urls": ["localhost:9999"],
						"tlsVerify": true,
						"onDemand": false,
						"pollInterval": "1m",
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
		}`, t.TempDir(), port, logFile.Name())

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(3 * time.Second)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"URLs\":[\"localhost:9999\"]")
		So(string(data), ShouldContainSubstring, "\"TLSVerify\":true")
		So(string(data), ShouldContainSubstring, "\"OnDemand\":false")
		So(string(data), ShouldContainSubstring, "\"Prefix\":\"zot-cve-test\"")
		So(string(data), ShouldContainSubstring, "\"Regex\":\"tag\"")
		So(string(data), ShouldContainSubstring, "\"Semver\":false")
	})

	Convey("reload bad config", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		content := fmt.Sprintf(`{
				"distSpecVersion": "0.1.0-dev",
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
			}`, t.TempDir(), port, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)

		defer os.Remove(cfgfile.Name()) // clean up

		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)

		// err = cfgfile.Close()
		// So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		Convey("reload with unparsable config", func(c C) {
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
			time.Sleep(3 * time.Second)

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "\"URLs\":[\"http://localhost:8080\"]")
			So(string(data), ShouldContainSubstring, "\"TLSVerify\":false")
			So(string(data), ShouldContainSubstring, "\"OnDemand\":true")
			So(string(data), ShouldContainSubstring, "\"MaxRetries\":3")
			So(string(data), ShouldContainSubstring, "\"CertDir\":\"\"")
			So(string(data), ShouldContainSubstring, "\"Prefix\":\"zot-test\"")
			So(string(data), ShouldContainSubstring, "\"Regex\":\".*\"")
			So(string(data), ShouldContainSubstring, "\"Semver\":true")
		})

		Convey("reload with invalid config", func(c C) {
			// config with sysconfig enabled but no auth and autz
			content := fmt.Sprintf(`
			{
				"distSpecVersion": "1.0.1-dev",
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
					"sysconfig": {
						"enable": true
					}
				}
			}`, t.TempDir(), port, logFile.Name())

			err = cfgfile.Truncate(0)
			So(err, ShouldBeNil)

			_, err = cfgfile.Seek(0, io.SeekStart)
			So(err, ShouldBeNil)

			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)

			err = cfgfile.Close()
			So(err, ShouldBeNil)

			// wait for config reload
			time.Sleep(3 * time.Second)

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "\"URLs\":[\"http://localhost:8080\"]")
			So(string(data), ShouldContainSubstring, "\"TLSVerify\":false")
			So(string(data), ShouldContainSubstring, "\"OnDemand\":true")
			So(string(data), ShouldContainSubstring, "\"MaxRetries\":3")
			So(string(data), ShouldContainSubstring, "\"CertDir\":\"\"")
			So(string(data), ShouldContainSubstring, "\"Prefix\":\"zot-test\"")
			So(string(data), ShouldContainSubstring, "\"Regex\":\".*\"")
			So(string(data), ShouldContainSubstring, "\"Semver\":true")
		})

		Convey("reload with valid config but wrong values", func(c C) {
			// config with sysconfig enabled but no auth and autz
			content := fmt.Sprintf(`
			{
				"distSpecVersion": "1.0.1-dev",
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s",
					"auth": {
						"htpasswd": {
						  "path": "/wrong/path/htpasswd"
						}
					}
				},
				"log": {
					"level": "debug",
					"output": "%s"
				}
			}`, t.TempDir(), port, logFile.Name())

			err = cfgfile.Truncate(0)
			So(err, ShouldBeNil)

			_, err = cfgfile.Seek(0, io.SeekStart)
			So(err, ShouldBeNil)

			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)

			err = cfgfile.Close()
			So(err, ShouldBeNil)

			// wait for config reload
			time.Sleep(3 * time.Second)

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "\"URLs\":[\"http://localhost:8080\"]")
			So(string(data), ShouldContainSubstring, "\"TLSVerify\":false")
			So(string(data), ShouldContainSubstring, "\"OnDemand\":true")
			So(string(data), ShouldContainSubstring, "\"MaxRetries\":3")
			So(string(data), ShouldContainSubstring, "\"CertDir\":\"\"")
			So(string(data), ShouldContainSubstring, "\"Prefix\":\"zot-test\"")
			So(string(data), ShouldContainSubstring, "\"Regex\":\".*\"")
			So(string(data), ShouldContainSubstring, "\"Semver\":true")
		})
	})
}

func TestConfigReloaderAllExtensions(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("reload access control config", t, func(c C) {
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

		content := fmt.Sprintf(`{
			"distSpecVersion": "0.1.0-dev",
			"storage": {
			  "rootDirectory": "%s",
			  "gc": true,
			  "gcDelay": "1h",
			  "gcInterval": "24h"
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
					"users": ["admin"],
					"actions": ["read", "create", "update", "delete"]
				}
			  }
			},
			"extensions": {
				"metrics": {},
				"search": {
					"cve": {
						"updateInterval": "2h"
					}
				},
				"scrub": {
					"interval": "24h"
				}
			},
			"log": {
			  "level": "debug",
			  "output": "%s"
			}
		  }`, t.TempDir(), port, htpasswdPath, logFile.Name())

		cfgfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)

		defer os.Remove(cfgfile.Name()) // clean up

		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)

		// err = cfgfile.Close()
		// So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "serve", cfgfile.Name()}
		go func() {
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		}()

		test.WaitTillServerReady(baseURL)

		// wait for cve db to be downloaded
		time.Sleep(30 * time.Second)

		content = fmt.Sprintf(`{
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
			  }
			},
			"log": {
			  "level": "debug",
			  "output": "%s"
			}
		}`, t.TempDir(), port, htpasswdPath, logFile.Name())

		err = cfgfile.Truncate(0)
		So(err, ShouldBeNil)

		_, err = cfgfile.Seek(0, io.SeekStart)
		So(err, ShouldBeNil)

		_, err = cfgfile.WriteString(content)
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		// wait for config reload
		time.Sleep(3 * time.Second)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "\"Extensions\":null")
	})
}
