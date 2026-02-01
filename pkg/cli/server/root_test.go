package server_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	. "zotregistry.dev/zot/v2/pkg/test/common"
)

// checkAuthLogEntry checks if a log entry with the given message has the expected enabled value.
func checkAuthLogEntry(logData []byte, message string, expectedEnabled bool) bool {
	//nolint:modernize // strings.Split is compatible with older Go versions
	for _, line := range strings.Split(string(logData), "\n") {
		if line == "" {
			continue
		}

		var logEntry map[string]any
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			continue
		}

		if msg, ok := logEntry["message"].(string); ok && msg == message {
			if enabled, ok := logEntry["enabled"].(bool); ok {
				return enabled == expectedEnabled
			}
		}
	}

	return false
}

// verifyAuthenticationLogs verifies that all authentication method log messages are present
// and that each method has the expected enabled status.
// expectedAuth maps authentication method names to their expected enabled status (true/false).
func verifyAuthenticationLogs(data []byte, expectedAuth map[string]bool) {
	authMethods := []string{
		"jwt bearer authentication",
		"oidc bearer authentication",
		"basic authentication (htpasswd)",
		"basic authentication (LDAP)",
		"basic authentication (API key)",
		"OpenID authentication",
		"mutual TLS authentication",
	}

	// Verify all authentication method messages are present
	for _, method := range authMethods {
		So(string(data), ShouldContainSubstring, method)
	}

	// Verify each authentication method has the expected enabled status
	for method, expectedEnabled := range expectedAuth {
		So(checkAuthLogEntry(data, method, expectedEnabled), ShouldBeTrue)
	}
}

func TestServerUsage(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test usage", t, func(c C) {
		os.Args = []string{"cli_test", "help"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test version", t, func(c C) {
		os.Args = []string{"cli_test", "--version"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestServe(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test serve help", t, func(c C) {
		os.Args = []string{"cli_test", "serve", "-h"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test serve config", t, func(c C) {
		Convey("no config arg", func(c C) {
			os.Args = []string{"cli_test", "serve"}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("two args", func(c C) {
			os.Args = []string{"cli_test", "serve", "config", "second arg"}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("unknown config", func(c C) {
			tempDir := t.TempDir()
			os.Args = []string{"cli_test", "serve", path.Join(tempDir, "/x")}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("non-existent config", func(c C) {
			tempDir := t.TempDir()
			os.Args = []string{"cli_test", "serve", path.Join(tempDir, "/x.yaml")}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad config", func(c C) {
			tmpFile := MakeTempFileWithContent(t, "zot-test.json", `{"log":{}}`)

			os.Args = []string{"cli_test", "serve", tmpFile}

			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("config with missing rootDir", func(c C) {
			// missing storage config should result in an error in Controller.Init()
			content := []byte(`{
				"distSpecVersion": "1.1.1",
				"http": {
					"address":"127.0.0.1",
					"port":"8080"
				}
			}`)

			contentStr := string(content)
			tmpFile := MakeTempFileWithContent(t, "zot-test.json", contentStr)

			os.Args = []string{"cli_test", "serve", tmpFile}

			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)

			// wait for the config reloader goroutine to start watching the config file
			// if we end the test too fast it will delete the config file
			// which will cause a panic and mark the test run as a failure
			time.Sleep(1 * time.Second)
		})
	})
}

func TestVerify(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test verify bad config", t, func(c C) {
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", `{"log":{}}`)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify config with no extension", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot"},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify config with dotted config name", t, func(c C) {
		content := `
distspecversion: 1.1.1
http:
  address: 127.0.0.1
  port: 8080
  realm: zot
log:
  level: debug
storage:
  rootdirectory: /tmp/zot
`
		tmpfile := MakeTempFileWithContent(t, ".zot-test", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify config with invalid log level", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot"},
							"log":{"level":"invalid"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "invalid log level")
		So(err.Error(), ShouldContainSubstring, "invalid")
	})

	Convey("Test verify config with valid trace log level", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot"},
							"log":{"level":"trace"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify CVE warn for remote storage", t, func(c C) {
		content := `{
			"storage":{
				"rootDirectory":"/tmp/zot",
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
		}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		contentBytes := []byte(`{
			"storage":{
				"rootDirectory":"/tmp/zot",
				"dedupe":true,
				"remoteCache":false,
				"subPaths":{
					"/a": {
						"rootDirectory": "/tmp/zot1",
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
		}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test cached db config", t, func(c C) {
		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		content := `{
			"storage":{
				"rootDirectory":"/tmp/zot",
				"dedupe":true,
				"remoteCache":true,
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
				"port":"8080",
				"realm":"zot",
				"auth":{
					"htpasswd":{
						"path":"test/data/htpasswd"
					},
					"failDelay":1
				}
			}
		}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// local storage with remote caching
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":true,
			   "remoteCache":true,
			   "cacheDriver":{
				  "name":"dynamodb",
				  "endpoint":"http://localhost:4566",
				  "region":"us-east-2",
				  "cacheTablename":"BlobTable"
			   }
			},
			"http":{
			   "address":"127.0.0.1",
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// unsupported cache driver
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":true,
			   "remoteCache":true,
			   "cacheDriver":{
				  "name":"unsupportedDriver"
			   },
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
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// remoteCache false but provided cacheDriver config, ignored
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":true,
			   "remoteCache":false,
			   "cacheDriver":{
				  "name":"dynamodb",
				  "endpoint":"http://localhost:4566",
				  "region":"us-east-2",
				  "cacheTablename":"BlobTable"
			   },
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
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`

		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// SubPaths
		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":false,
			   "subPaths":{
				  "/a":{
					 "rootDirectory":"/zot-a",
					 "dedupe":true,
					 "remoteCache":true,
					 "storageDriver":{
						"name":"s3",
						"rootdirectory":"/zot",
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
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// local storage with remote caching
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":false,
			   "subPaths":{
				  "/a":{
					 "rootDirectory":"/zot-a",
					 "dedupe":true,
					 "remoteCache":true,
					 "cacheDriver":{
						"name":"dynamodb",
						"endpoint":"http://localhost:4566",
						"region":"us-east-2",
						"cacheTablename":"BlobTable"
					 }
				  }
			   }
			},
			"http":{
			   "address":"127.0.0.1",
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// unsupported cache driver
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":false,
			   "subPaths":{
				  "/a":{
					 "rootDirectory":"/zot-a",
					 "dedupe":true,
					 "remoteCache":true,
					 "cacheDriver":{
						"name":"badDriverName"
					 },
					 "storageDriver":{
						"name":"s3",
						"rootdirectory":"/zot",
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
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// remoteCache false but provided cacheDriver config, ignored
		content = `{
			"storage":{
			   "rootDirectory":"/tmp/zot",
			   "dedupe":false,
			   "subPaths":{
				  "/a":{
					 "rootDirectory":"/zot-a",
					 "dedupe":true,
					 "remoteCache":false,
					 "cacheDriver":{
						"name":"dynamodb",
						"endpoint":"http://localhost:4566",
						"region":"us-east-2",
						"cacheTablename":"BlobTable"
					 }
				  }
			   }
			},
			"http":{
			   "address":"127.0.0.1",
			   "port":"8080",
			   "realm":"zot",
			   "auth":{
				  "htpasswd":{
					 "path":"test/data/htpasswd"
				  },
				  "failDelay":1
			   }
			}
		 }`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test session store config", t, func(c C) {
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", "")

		keysContent := `{
				"hashKey": "my-very-secret",
				"encryptKey": "another-secret"
			}`
		tmpSessionKeysFile := MakeTempFileWithContent(t, "keys.json", keysContent)

		testCases := []struct {
			name    string
			config  []byte
			isValid bool
			errMsg  string
		}{
			{
				"Should fail verify if session driver is enabled, but invalid driver provided",
				[]byte(`{
					"storage":{
						"rootDirectory":"/tmp/zot"
					},
					"http":{
						"address":"127.0.0.1",
						"port":"8080",
						"realm":"zot",
						"auth":{
							"htpasswd":{
								"path":"test/data/htpasswd"
							},
							"failDelay":1,
							"sessionDriver":{
								"name": "badDriver"
							}
						}
					},
					"extensions":{
						"search": {
							"cve": {
								"updateInterval": "2h"
							}
						},
						"ui": {
							"enable": true
						}
					}
				}`),
				false,
				zerr.ErrBadConfig.Error() +
					": session store driver badDriver is not allowed!",
			},
			{
				"Should fail verify if session driver is enabled, but driver name is not provided",
				[]byte(`{
					"storage":{
						"rootDirectory":"/tmp/zot"
					},
					"http":{
						"address":"127.0.0.1",
						"port":"8080",
						"realm":"zot",
						"auth":{
							"htpasswd":{
								"path":"test/data/htpasswd"
							},
							"failDelay":1,
							"sessionDriver":{
								"url": "redis://localhost"
							}
						}
					},
					"extensions":{
						"search": {
							"cve": {
								"updateInterval": "2h"
							}
						},
						"ui": {
							"enable": true
						}
					}
				}`),
				false,
				zerr.ErrBadConfig.Error() + ": must provide session driver name!",
			},
			{
				"Should fail verify if session driver is enabled and sessionKeysFile present",
				fmt.Appendf([]byte{}, `{
					"storage":{
						"rootDirectory":"/tmp/zot"
					},
					"http":{
						"address":"127.0.0.1",
						"port":"8080",
						"realm":"zot",
						"auth":{
							"htpasswd":{
								"path":"test/data/htpasswd"
							},
							"failDelay":1,
							"sessionKeysFile": "%s",
							"sessionDriver":{
								"name": "redis",
								"url": "redis://localhost"
							}
						}
					},
					"extensions":{
						"search": {
							"cve": {
								"updateInterval": "2h"
							}
						},
						"ui": {
							"enable": true
						}
					}
				}`, tmpSessionKeysFile),
				false,
				zerr.ErrBadConfig.Error() + ": session keys not supported when redis session driver is used!",
			},
			{
				"Should be successful if session driver config is valid for redis",
				[]byte(`{
					"storage":{
						"rootDirectory":"/tmp/zot"
					},
					"http":{
						"address":"127.0.0.1",
						"port":"8080",
						"realm":"zot",
						"auth":{
							"htpasswd":{
								"path":"test/data/htpasswd"
							},
							"failDelay":1,
							"sessionDriver":{
								"name": "redis",
								"url": "redis://localhost"
							}
						}
					},
					"extensions":{
						"search": {
							"cve": {
								"updateInterval": "2h"
							}
						},
						"ui": {
							"enable": true
						}
					}
				}`),
				true,
				"",
			},
			{
				"Should be successful if session driver config is valid for local",
				[]byte(`{
					"storage":{
						"rootDirectory":"/tmp/zot"
					},
					"http":{
						"address":"127.0.0.1",
						"port":"8080",
						"realm":"zot",
						"auth":{
							"htpasswd":{
								"path":"test/data/htpasswd"
							},
							"failDelay":1,
							"sessionDriver":{
								"name": "local"
							}
						}
					},
					"extensions":{
						"search": {
							"cve": {
								"updateInterval": "2h"
							}
						},
						"ui": {
							"enable": true
						}
					}
				}`),
				true,
				"",
			},
			{
				"Should be successful if session driver config is missing",
				[]byte(`{
					"storage":{
						"rootDirectory":"/tmp/zot"
					},
					"http":{
						"address":"127.0.0.1",
						"port":"8080",
						"realm":"zot",
						"auth":{
							"htpasswd":{
								"path":"test/data/htpasswd"
							},
							"failDelay":1
						}
					},
					"extensions":{
						"search": {
							"cve": {
								"updateInterval": "2h"
							}
						},
						"ui": {
							"enable": true
						}
					}
				}`),
				true,
				"",
			},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				err := os.WriteFile(tmpfile, testCase.config, 0o0600)
				So(err, ShouldBeNil)

				os.Args = []string{"cli_test", "verify", tmpfile}
				err = cli.NewServerRootCmd().Execute()

				if testCase.isValid {
					So(err, ShouldBeNil)
				} else {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldEqual, testCase.errMsg)
				}
			})
		}
	})

	Convey("Test verify with bad gc retention repo patterns", t, func(c C) {
		content := `{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "/tmp/zot",
				"gc": true,
				"retention": {
					"policies": [
						{
							"repositories": ["["],
							"deleteReferrers": false
						}
					]
				},
				"subPaths":{
					"/a":{
					   "rootDirectory":"/zot-a",
					   "retention": {
							"policies": [
								{
									"repositories": ["**"],
									"deleteReferrers": true
								}
							]
					   }
					}
				 }
			},
			"http": {
				"address": "127.0.0.1",
				"port": "8080"
			},
			"log": {
				"level": "debug"
			}
		}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}

		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})

	Convey("Test verify with bad gc image retention tag regex", t, func(c C) {
		content := `{
			"distSpecVersion": "1.1.1",
			"storage": {
				"rootDirectory": "/tmp/zot",
				"gc": true,
				"retention": {
					"dryRun": false,
					"policies": [
						{
							"repositories": ["infra/*"],
							"deleteReferrers": false,
							"deleteUntagged": true,
							"keepTags": [{
								"names": ["["]
							}]
						}
					]
				}
			},
			"http": {
				"address": "127.0.0.1",
				"port": "8080"
			},
			"log": {
				"level": "debug"
			}
		}`

		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}

		So(cli.NewServerRootCmd().Execute(), ShouldNotBeNil)
	})

	Convey("Test apply defaults cache db", t, func(c C) {
		// s3 dedup=false, check for previous dedup usage and set to true if cachedb found
		cacheDir := t.TempDir()
		existingDBPath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)
		_, err := os.Create(existingDBPath)
		So(err, ShouldBeNil)

		content := fmt.Sprintf(`{"storage":{"rootDirectory":"/tmp/zot", "dedupe": false,
							"storageDriver": {"rootDirectory": "%s"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`, cacheDir)
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// subpath s3 dedup=false, check for previous dedup usage and set to true if cachedb found
		cacheDir = t.TempDir()
		existingDBPath = path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)
		_, err = os.Create(existingDBPath)
		So(err, ShouldBeNil)

		content = fmt.Sprintf(`{"storage":{"rootDirectory":"/tmp/zot", "dedupe": true,
							"subpaths": {"/a": {"rootDirectory":"/tmp/zot1", "dedupe": false,
							"storageDriver": {"rootDirectory": "%s"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`, cacheDir)
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		// subpath s3 dedup=false, check for previous dedup usage and set to true if cachedb found
		cacheDir = t.TempDir()

		content = fmt.Sprintf(`{"storage":{"rootDirectory":"/tmp/zot", "dedupe": true,
							"subpaths": {"/a": {"rootDirectory":"/tmp/zot1", "dedupe": true,
							"storageDriver": {"rootDirectory": "%s"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`, cacheDir)
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify storage driver different than s3", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "gcs"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify subpath storage driver different than s3", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "s3"},
							"subPaths": {"/a": {"rootDirectory": "/zot-a","storageDriver": {"name": "gcs"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify subpath storage config", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a"},"/b": {"rootDirectory": "/zot-a"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		// Two substores of the same type cannot use the same root directory
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "cannot use the same root directory")
		So(err.Error(), ShouldContainSubstring, "substore (route: /a)")
		So(err.Error(), ShouldContainSubstring, "substore (route: /b)")

		// sub paths that point to same directory should have same storage config.
		contentBytes := []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"false"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// Two substores of the same type cannot use the same root directory
		So(err.Error(), ShouldContainSubstring, "cannot use the same root directory")
		So(err.Error(), ShouldContainSubstring, "substore (route: /a)")
		So(err.Error(), ShouldContainSubstring, "substore (route: /b)")

		// sub paths that point to default root directory should not be allowed.
		contentBytes = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot","dedupe":"true"},"/b": {"rootDirectory": "/zot-a"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		contentBytes = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"false"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		contentBytes = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		contentBytes = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)

		contentBytes = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile, contentBytes, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify storage config with different storage types", t, func(c C) {
		// Local and S3 stores with same rootDir should be allowed (different storage types)
		content := `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot",
							"storageDriver":{"name":"s3","rootdirectory":"/tmp/zot","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Two local stores with same rootDir should be rejected (same storage type)
		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// Two stores of the same type cannot use the same root directory
		So(err.Error(), ShouldContainSubstring, "cannot use the same root directory")
		So(err.Error(), ShouldContainSubstring, "default storage")
		So(err.Error(), ShouldContainSubstring, "substore (route: /a)")

		// Two S3 stores with same rootDir should be rejected (same storage type)
		content = `{"storage":{"rootDirectory":"/zot",
							"storageDriver":{"name":"s3","rootdirectory":"/zot","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false,
							"subPaths": {"/a": {"rootDirectory": "/zot",
							"storageDriver":{"name":"s3","rootdirectory":"/zot","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// Two stores of the same type cannot use the same root directory
		So(err.Error(), ShouldContainSubstring, "cannot use the same root directory")
		So(err.Error(), ShouldContainSubstring, "default storage")
		So(err.Error(), ShouldContainSubstring, "substore (route: /a)")

		// Local store with nested path inside default local store should be rejected
		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot/subdir"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring,
			"invalid storage config, substore (route: /a) root directory cannot be inside default storage root directory")

		// S3 store with nested path inside default S3 store should be rejected
		content = `{"storage":{"rootDirectory":"/zot",
							"storageDriver":{"name":"s3","rootdirectory":"/zot","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false,
							"subPaths": {"/a": {"rootDirectory": "/zot/subdir",
							"storageDriver":{"name":"s3","rootdirectory":"/zot/subdir","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring,
			"invalid storage config, substore (route: /a) root directory cannot be inside default storage root directory")

		// Local store with nested path inside S3 store should be allowed (different storage types)
		content = `{"storage":{"rootDirectory":"/zot",
							"storageDriver":{"name":"s3","rootdirectory":"/zot","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false,
							"subPaths": {"/a": {"rootDirectory": "/zot/subdir"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// S3 store with nested path inside local store should be allowed (different storage types)
		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot/subdir",
							"storageDriver":{"name":"s3","rootdirectory":"/tmp/zot/subdir","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Two local substores with nested paths should be rejected
		// /a is at /tmp/zot-a (not nested in default), /b is nested inside /a
		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot-a"},
							"/b": {"rootDirectory": "/tmp/zot-a/subdir"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// /b is nested inside /a, validation reports this conflict
		So(err.Error(), ShouldContainSubstring,
			"invalid storage config, substore (route: /b) root directory cannot be inside substore (route: /a) root directory")

		// Two S3 substores with nested paths should be rejected
		// /a is at /zot-a (not nested in default), /b is nested inside /a
		content = `{"storage":{"rootDirectory":"/zot",
							"storageDriver":{"name":"s3","rootdirectory":"/zot","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false,
							"subPaths": {"/a": {"rootDirectory": "/zot-a",
							"storageDriver":{"name":"s3","rootdirectory":"/zot-a","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false},
							"/b": {"rootDirectory": "/zot-a/subdir",
							"storageDriver":{"name":"s3","rootdirectory":"/zot-a/subdir","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// /b is nested inside /a, validation reports this conflict
		So(err.Error(), ShouldContainSubstring,
			"invalid storage config, substore (route: /b) root directory cannot be inside substore (route: /a) root directory")

		// Local and S3 substores with nested paths should be allowed (different storage types)
		// /a is local at /tmp/zot-a (not nested in default), /b is S3 nested inside /a
		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot-a"},
							"/b": {"rootDirectory": "/tmp/zot-a/subdir",
							"storageDriver":{"name":"s3","rootdirectory":"/tmp/zot-a/subdir","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// Default local store is inside substore (should be rejected)
		// default is at /tmp/zot-parent/subdir, /a is at /tmp/zot-parent
		content = `{"storage":{"rootDirectory":"/tmp/zot-parent/subdir",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot-parent"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// default storage is inside /a, validation reports this conflict
		So(err.Error(), ShouldContainSubstring,
			"invalid storage config, default storage root directory cannot be inside substore (route: /a) root directory")

		// Default S3 store is inside substore, with S3, (should be rejected)
		// default is at /zot-parent/subdir, /a is at /zot-parent
		content = `{"storage":{"rootDirectory":"/zot-parent/subdir",
							"storageDriver":{"name":"s3","rootdirectory":"/zot-parent/subdir","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false,
							"subPaths": {"/a": {"rootDirectory": "/zot-parent",
							"storageDriver":{"name":"s3","rootdirectory":"/zot-parent","region":"us-east-2",
							"bucket":"zot-storage","secure":true,"skipverify":false},
							"dedupe":false}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		// default storage is inside /a, validation reports this conflict
		So(err.Error(), ShouldContainSubstring,
			"invalid storage config, default storage root directory cannot be inside substore (route: /a) root directory")
	})

	Convey("Test verify w/ authorization and w/o authentication", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"repositories":{},"adminPolicy":{"users":["admin"],
							 "actions":["read","create","update","delete"]}}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify w/ authorization and w/ authentication", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1},
							"accessControl":{"repositories":{},"adminPolicy":{"users":["admin"],
							"actions":["read","create","update","delete"]}}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify anonymous authorization", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"repositories":{"**":{"anonymousPolicy": ["read", "create"]},
							 "/repo":{"anonymousPolicy": ["read", "create"]}}
							 }}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify admin policy authz is not allowed if no authn is configured", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
								"accessControl":{
									"repositories":{
										"**":{"defaultPolicy": ["read", "create"]},
										"/repo":{"anonymousPolicy": ["read", "create"]},
									},
									"adminPolicy":{
										"users":["admin"],
										"actions":["read","create","update","delete"]
									}
								}
							}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify default policy authz is not allowed if no authn is configured", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
								"accessControl":{
									"repositories": {
										"**":{"defaultPolicy": ["read", "create"]},
										"/repo":{"anonymousPolicy": ["read", "create"]}
									}
								}
							}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify authz per user policies fail if no authn is configured", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
								"accessControl":{
									"repositories": {
										"/repo":{"anonymousPolicy": ["read", "create"]},
										"/repo2":{
											"policies": [{
												"users": ["charlie"],
												"actions": ["read", "create", "update"]
											}]
										}
									}
								}
							}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify w/ sync and w/o filesystem storage", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "s3"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s"}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify w/ sync and w/ filesystem storage", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s"}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify with bad sync prefixes", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"[repo%^&"}]}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify with bad preserve digest and no compat", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"preserveDigest": true}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify with bad sync content config", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"zot-repo","stripPrefix":true,"destination":"/"}]}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify with good sync content config", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"zot-repo/*","stripPrefix":true,"destination":"/"}]}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify with bad authorization repo patterns", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1},
							"accessControl":{"repositories":{"[":{"policies":[],"anonymousPolicy":[]}}}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify sync config default tls value", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"repo**"}]}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify sync without retry options", t, func(c C) {
		content := `{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 10, "content": [{"prefix":"repo**"}]}]}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify config with unknown keys", t, func(c C) {
		content := `{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"url": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify openid config with missing parameter", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"openid":{"providers":{"oidc":{"issuer":"http://127.0.0.1:5556/dex"}}}}},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify oauth2 config with missing parameter scopes", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"openid":{"providers":{"github":{"clientid":"client_id"}}}}},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify oauth2 config with missing parameter clientid", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"openid":{"providers":{"github":{"scopes":["openid"]}}}}},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify openid config with unsupported provider", t, func(c C) {
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"openid":{"providers":{"unsupported":{"issuer":"http://127.0.0.1:5556/dex"}}}}},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify openid config without apikey extension enabled", t, func(c C) {
		//nolint:gosec // test credentials
		credsContent := `{
			"clientid":"client-id",
			"clientsecret":"client-secret"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
			"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
			"auth":{"openid":{"providers":{"oidc":{"issuer":"http://127.0.0.1:5556/dex",
			"credentialsFile":"%s","scopes":["openid"]}}}}},
			"log":{"level":"debug"}}`,
			tmpCredsFile,
		)
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify config with missing basedn key", t, func(c C) {
		content := `{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"auth": {"ldap": {"address": "ldap", "userattribute": "uid"}},
							"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify config with missing address key", t, func(c C) {
		content := `{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"auth": {"ldap": {"basedn": "ou=Users,dc=example,dc=org", "userattribute": "uid"}},
							"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify config with missing userattribute key", t, func(c C) {
		content := `{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"auth": {"ldap": {"basedn": "ou=Users,dc=example,dc=org", "address": "ldap"}},
							"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test verify good config", t, func(c C) {
		content := `{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		os.Args = []string{"cli_test", "verify", tmpfile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify good session keys config with both keys", t, func(c C) {
		//nolint:gosec // test credentials
		credsContent := `{
			"hashKey":"very-secret",
			"encryptKey":"another-secret"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth":{"htpasswd":{"path":"test/data/htpasswd"}, "sessionKeysFile": "%s", 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify good session keys config with one key", t, func(c C) {
		//nolint:gosec // test credentials
		credsContent := `{
			"hashKey":"very-secret"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth":{"htpasswd":{"path":"test/data/htpasswd"}, "sessionKeysFile": "%s", 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify good ldap config", t, func(c C) {
		//nolint:gosec // test credentials
		credsContent := `{
			"bindDN":"cn=ldap-searcher,ou=Users,dc=example,dc=org",
			"bindPassword":"ldap-searcher-password"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth": { "ldap": { "credentialsFile": "%v", "address": "ldap.example.org", "port": 389, 
			"startTLS": false, "baseDN": "ou=Users,dc=example,dc=org", 
			"userAttribute": "uid", "userGroupAttribute": "memberOf", "skipVerify": true, "subtreeSearch": true }, 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify bad ldap config: key is missing", t, func(c C) {
		// `bindDN` key is missing
		//nolint:gosec // test credentials
		credsContent := `{
			"bindPassword":"ldap-searcher-password"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth": { "ldap": { "credentialsFile": "%v", "address": "ldap.example.org", "port": 389, 
			"startTLS": false, "baseDN": "ou=Users,dc=example,dc=org", 
			"userAttribute": "uid", "userGroupAttribute": "memberOf", "skipVerify": true, "subtreeSearch": true }, 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "invalid server config")
	})

	Convey("Test verify bad ldap config: unused key", t, func(c C) {
		//nolint:gosec // test credentials
		credsContent := `{
			"bindDN":"cn=ldap-searcher,ou=Users,dc=example,dc=org",
			"bindPassword":"ldap-searcher-password",
			"extraKey": "extraValue"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth": { "ldap": { "credentialsFile": "%v", "address": "ldap.example.org", "port": 389, 
			"startTLS": false, "baseDN": "ou=Users,dc=example,dc=org", 
			"userAttribute": "uid", "userGroupAttribute": "memberOf", "skipVerify": true, "subtreeSearch": true }, 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "invalid server config")
	})

	Convey("Test verify bad ldap config: empty credentials file", t, func(c C) {
		// `bindDN` key is missing
		credsContent := ``
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth": { "ldap": { "credentialsFile": "%v", "address": "ldap.example.org", "port": 389, 
			"startTLS": false, "baseDN": "ou=Users,dc=example,dc=org", 
			"userAttribute": "uid", "userGroupAttribute": "memberOf", "skipVerify": true, "subtreeSearch": true }, 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "invalid server config")
	})

	Convey("Test verify bad ldap config: no keys set in credentials file", t, func(c C) {
		// empty json
		credsContent := `{}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{ "distSpecVersion": "1.1.1",
			"storage": { "rootDirectory": "/tmp/zot" }, "http": { "address": "127.0.0.1", "port": "8080", 
			"auth": { "ldap": { "credentialsFile": "%v", "address": "ldap.example.org", "port": 389, 
			"startTLS": false, "baseDN": "ou=Users,dc=example,dc=org", 
			"userAttribute": "uid", "userGroupAttribute": "memberOf", "skipVerify": true, "subtreeSearch": true }, 
			"failDelay": 5 } }, "log": { "level": "debug" } }`,
			tmpCredsFile,
		)
		tmpFile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		os.Args = []string{"cli_test", "verify", tmpFile}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "invalid server config")
	})

	Convey("Test verify mTLS config validation", t, func(c C) {
		Convey("Test valid mTLS config with CommonName", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName"]
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		})

		Convey("Test valid mTLS config with URI and pattern", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["URI", "CommonName"],
							"uriSanPattern": "spiffe://example.org/workload/(.*)"
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		})

		Convey("Test valid mTLS config with all valid identity attributes", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName", "CN", "Subject", "DN", "Email",
							"rfc822name", "URI", "URL", "DNSName", "DNS"]
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		})

		Convey("Test invalid identity attribute", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["InvalidAttribute"]
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "unsupported identity attribute")
			So(err.Error(), ShouldContainSubstring, "InvalidAttribute")
		})

		Convey("Test DNSANIndex without URI/URL identity attribute", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName"],
							"dnsSanIndex": 1
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "dnsSanIndex is only supported for URI/URL MTLS identity attribute")
		})

		Convey("Test EmailSANIndex without URI/URL identity attribute", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName"],
							"emailSanIndex": 1
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "emailSanIndex is only supported for URI/URL MTLS identity attribute")
		})

		Convey("Test URISANIndex without URI/URL identity attribute", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName"],
							"uriSanIndex": 1
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "uriSanIndex is only supported for URI/URL MTLS identity attribute")
		})

		Convey("Test URISANPattern without URI/URL identity attribute", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName"],
							"uriSanPattern": "spiffe://example.org/workload/(.*)"
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "uriSanPattern is only supported for URI/URL MTLS identity attribute")
		})

		Convey("Test invalid regex pattern for URISANPattern", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["URI"],
							"uriSanPattern": "[invalid(regex"
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "invalid URI SAN pattern")
		})

		Convey("Test valid mTLS config with URL identity attribute", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"tls": {
						"cert": "test/data/server.cert",
						"key": "test/data/server.key",
						"cacert": "test/data/ca.crt"
					},
					"auth": {
						"mtls": {
							"identityAttributes": ["URL"],
							"uriSanPattern": "spiffe://example.org/workload/(.*)",
							"uriSanIndex": 0
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldBeNil)
		})

		Convey("Test mTLS config without TLS (should fail - mTLS requires TLS)", func() {
			content := `{
				"distSpecVersion": "1.1.1",
				"storage": {
					"rootDirectory": "/tmp/zot"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080",
					"realm": "zot",
					"auth": {
						"mtls": {
							"identityAttributes": ["CommonName"]
						}
					}
				},
				"log": {
					"level": "debug"
				}
			}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "verify", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "mTLS configuration requires TLS to be enabled with CA certificate")
		})
	})
}

func TestApiKeyConfig(t *testing.T) {
	Convey("Test API Keys are enabled if OpenID is enabled", t, func(c C) {
		config := config.New()
		//nolint:gosec // test credentials
		credsContent := `{
			"clientid":"client-id",
			"clientsecret":"client-secret"
		}`
		tmpCredsFile := MakeTempFileWithContent(t, "zot-cred.json", credsContent)

		configContent := fmt.Sprintf(`{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
			"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
			"auth":{"openid":{"providers":{"oidc":{"issuer":"http://127.0.0.1:5556/dex",
			"credentialsFile":"%s","scopes":["openid"]}}}}},
			"log":{"level":"debug"}}`,
			tmpCredsFile,
		)
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", configContent)

		err := cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldBeNil)
		So(config.HTTP.Auth, ShouldNotBeNil)
		So(config.HTTP.Auth.APIKey, ShouldBeTrue)
	})

	Convey("Test API Keys are not enabled by default", t, func(c C) {
		config := config.New()
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot"},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		err := cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldBeNil)
		So(config.HTTP.Auth, ShouldNotBeNil)
		So(config.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Test API Keys are not enabled if OpenID is not enabled", t, func(c C) {
		config := config.New()
		content := `{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"}}},
							"log":{"level":"debug"}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

		err := cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldBeNil)
		So(config.HTTP.Auth, ShouldNotBeNil)
		So(config.HTTP.Auth.APIKey, ShouldBeFalse)
	})
}

func TestServeAPIKey(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("apikey implicitly enabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s",
						"auth": {
							"apikey": true
						}
					},
					"log": {
						"level": "debug",
						"output": "%s"
					}
				}`

		logPath, _, err := runCLIWithConfig(t, content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		So(string(data), ShouldContainSubstring, "\"APIKey\":true")
		// verify configuration settings message is present
		So(string(data), ShouldContainSubstring, "configuration settings")
		// verify authentication methods status messages are present
		verifyAuthenticationLogs(data, map[string]bool{
			"jwt bearer authentication":       false,
			"oidc bearer authentication":      false,
			"basic authentication (htpasswd)": false,
			"basic authentication (LDAP)":     false,
			"basic authentication (API key)":  true,
			"OpenID authentication":           false,
			"mutual TLS authentication":       false,
		})
	})

	Convey("apikey disabled", t, func(c C) {
		content := `{
					"storage": {
						"rootDirectory": "%s"
					},
					"http": {
						"address": "127.0.0.1",
						"port": "%s",
						"auth": {
							"apikey": false
						}
					},
					"log": {
						"level": "debug",
						"output": "%s"
					}
				}`

		logPath, _, err := runCLIWithConfig(t, content)
		So(err, ShouldBeNil)
		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		So(string(data), ShouldContainSubstring, "\"APIKey\":false")
		// verify configuration settings message is present
		So(string(data), ShouldContainSubstring, "configuration settings")
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
}

func TestLoadConfig(t *testing.T) {
	Convey("Test viper load config", t, func(c C) {
		config := config.New()
		err := cli.LoadConfiguration(config, "../../../examples/config-policy.json")
		So(err, ShouldBeNil)
	})
	Convey("Test subpath config combination", t, func(c C) {
		config := config.New()
		content := `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
		err := cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldNotBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldNotBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"false"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldNotBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"0s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldNotBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true"},
							"/b": {"rootDirectory": "/b","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		// Two substores of the same type cannot use the same root directory
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "cannot use the same root directory")
		So(err.Error(), ShouldContainSubstring, "substore (route: /a)")
		So(err.Error(), ShouldContainSubstring, "substore (route: /b)")
	})

	Convey("Test HTTP port", t, func() {
		config := config.New()
		content := `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-b","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
		err := cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-b","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"-1","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldNotBeNil)

		content = `{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"65536","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`
		err = os.WriteFile(tmpfile, []byte(content), 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile)
		So(err, ShouldNotBeNil)
	})
}

func TestGC(t *testing.T) {
	Convey("Test GC config", t, func(c C) {
		config := config.New()
		err := cli.LoadConfiguration(config, "../../../examples/config-multiple.json")
		So(err, ShouldBeNil)
		So(config.Storage.GCDelay, ShouldEqual, storageConstants.DefaultGCDelay)
		err = cli.LoadConfiguration(config, "../../../examples/config-gc.json")
		So(err, ShouldBeNil)
		So(config.Storage.GCDelay, ShouldNotEqual, storageConstants.DefaultGCDelay)
		err = cli.LoadConfiguration(config, "../../../examples/config-gc-periodic.json")
		So(err, ShouldBeNil)
	})

	Convey("Test GC config corner cases", t, func(c C) {
		contents, err := os.ReadFile("../../../examples/config-gc.json")
		So(err, ShouldBeNil)

		Convey("GC delay without GC", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GC = false

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "gc-config.json", string(contents))
			err = cli.LoadConfiguration(config, file)
			So(err, ShouldBeNil)
		})

		Convey("GC interval without GC", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GC = false
			config.Storage.GCDelay = 0
			config.Storage.GCInterval = 24 * time.Hour

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "gc-config.json", string(contents))
			err = cli.LoadConfiguration(config, file)
			So(err, ShouldBeNil)
		})

		Convey("Negative GC delay", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GCDelay = -1 * time.Second

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "gc-config.json", string(contents))
			err = cli.LoadConfiguration(config, file)
			So(err, ShouldNotBeNil)
		})

		Convey("GC delay when GC = false", func() {
			config := config.New()

			content := `{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot",
			"gc": false}, "http": {"address": "127.0.0.1", "port": "8080"},
			"log": {"level": "debug"}}`

			file := MakeTempFileWithContent(t, "gc-false-config.json", content)
			err = cli.LoadConfiguration(config, file)
			So(err, ShouldBeNil)
			So(config.Storage.GCDelay, ShouldEqual, 0)
		})

		Convey("Negative GC interval", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GCInterval = -1 * time.Second

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "gc-config.json", string(contents))
			err = cli.LoadConfiguration(config, file)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestScrub(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test scrub help", t, func(c C) {
		os.Args = []string{"cli_test", "scrub", "-h"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test scrub no args", t, func(c C) {
		os.Args = []string{"cli_test", "scrub"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test scrub config", t, func(c C) {
		Convey("non-existent config", func(c C) {
			tempDir := t.TempDir()
			os.Args = []string{"cli_test", "scrub", path.Join(tempDir, "/x.yaml")}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("unknown config", func(c C) {
			tempDir := t.TempDir()
			os.Args = []string{"cli_test", "scrub", path.Join(tempDir, "/x")}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad config", func(c C) {
			content := `{"log":{}}`
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "scrub", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("server is running", func(c C) {
			port := GetFreePort()
			config := config.New()
			config.HTTP.Port = port
			controller := api.NewController(config)

			dir := t.TempDir()

			controller.Config.Storage.RootDirectory = dir
			ctrlManager := NewControllerManager(controller)
			ctrlManager.StartAndWait(port)

			content := fmt.Sprintf(`{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"port": %s
				},
				"log": {
					"level": "debug"
				}
			}
			`, dir, port)
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "scrub", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)

			defer ctrlManager.StopServer()
		})

		Convey("no image store provided", func(c C) {
			port := GetFreePort()

			content := fmt.Sprintf(`{
				"storage": {
					"rootDirectory": ""
				},
				"http": {
					"port": %s
				},
				"log": {
					"level": "debug"
				}
			}
			`, port)
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "scrub", tmpfile}
			err := cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad index.json", func(c C) {
			port := GetFreePort()

			dir := t.TempDir()

			repoName := "badindex"

			repo := filepath.Join(dir, repoName)
			if err := os.MkdirAll(filepath.Join(repo, "blobs"), 0o755); err != nil {
				panic(err)
			}

			var err error
			if _, err = os.Stat(repo + "/oci-layout"); err != nil {
				content := []byte(`{"imageLayoutVersion": "1.0.0"}`)
				if err = os.WriteFile(repo+"/oci-layout", content, 0o600); err != nil {
					panic(err)
				}
			}

			if _, err = os.Stat(repo + "/index.json"); err != nil {
				content := []byte(`not a JSON content`)
				if err = os.WriteFile(repo+"/index.json", content, 0o600); err != nil {
					panic(err)
				}
			}

			content := fmt.Sprintf(`{
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"port": %s
				},
				"log": {
					"level": "debug"
				}
			}
			`, dir, port)
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)

			os.Args = []string{"cli_test", "scrub", tmpfile}
			err = cli.NewServerRootCmd().Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestUpdateLDAPConfig(t *testing.T) {
	Convey("updateLDAPConfig errors while unmarshaling ldap config", t, func() {
		ldapConfigContent := "bad-json"
		ldapConfigPath := MakeTempFileWithContent(t, "ldap.json", ldapConfigContent)

		configStr := fmt.Sprintf(`
		{
			"Storage": {
				"RootDirectory": "%s"
			},
			"HTTP": {
				"Address": "%s",
				"Port": "%s",
				"Auth": {
					"LDAP": {
						"CredentialsFile":    "%s",
						"BaseDN":             "%v",
						"UserAttribute":      "uid",
						"UserGroupAttribute": "memberOf",
						"Insecure":           true,
						"Address":            "%v",
						"Port":               %v
					}
				}
			}
		}`, t.TempDir(), "127.0.0.1", "8000", ldapConfigPath, "LDAPBaseDN", "LDAPAddress", 1000)

		configPath := MakeTempFileWithContent(t, "config.json", configStr)

		server := cli.NewServerRootCmd()
		server.SetArgs([]string{"serve", configPath})
		So(server.Execute(), ShouldNotBeNil)

		err := os.Chmod(ldapConfigPath, 0o600)
		So(err, ShouldBeNil)

		server = cli.NewServerRootCmd()
		server.SetArgs([]string{"serve", configPath})
		So(server.Execute(), ShouldNotBeNil)
	})

	Convey("unauthenticated LDAP config", t, func() {
		tempDir := t.TempDir()

		configStr := fmt.Sprintf(`
		{
			"Storage": {
				"RootDirectory": "%s"
			},
			"HTTP": {
				"Address": "%s",
				"Port": "%s",
				"Auth": {
					"LDAP": {
						"BaseDN":             "%v",
						"UserAttribute":      "uid",
						"UserGroupAttribute": "memberOf",
						"Insecure":           true,
						"Address":            "%v",
						"Port":               %v
					}
				}
			}
		}`, tempDir, "127.0.0.1", "8000", "LDAPBaseDN", "LDAPAddress", 1000)

		configPath := MakeTempFileWithContent(t, "config.json", configStr)

		err := cli.LoadConfiguration(config.New(), configPath)
		So(err, ShouldBeNil)
	})
}

func TestClusterConfig(t *testing.T) {
	baseExamplePath := "../../../examples/scale-out-cluster-cloud/"

	Convey("Should successfully load example configs for cloud", t, func() {
		for memberIdx := range 3 {
			cfgFileToLoad := fmt.Sprintf("%s/config-cluster-member%d.json", baseExamplePath, memberIdx)
			cfg := config.New()
			err := cli.LoadConfiguration(cfg, cfgFileToLoad)
			So(err, ShouldBeNil)
		}
	})

	Convey("Should successfully load example TLS configs for cloud", t, func() {
		for memberIdx := range 3 {
			cfgFileToLoad := fmt.Sprintf("%s/tls/config-cluster-member%d.json", baseExamplePath, memberIdx)
			cfg := config.New()
			err := cli.LoadConfiguration(cfg, cfgFileToLoad)
			So(err, ShouldBeNil)
		}
	})

	Convey("Should reject scale out cluster invalid cases", t, func() {
		cfgFileContents, err := os.ReadFile(baseExamplePath + "config-cluster-member0.json")
		So(err, ShouldBeNil)

		Convey("Should reject empty members list", func() {
			cfg := config.New()
			err := json.Unmarshal(cfgFileContents, cfg)
			So(err, ShouldBeNil)

			// set the members to an empty list
			cfg.Cluster.Members = []string{}

			cfgFileContents, err := json.MarshalIndent(cfg, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "cluster-config.json", string(cfgFileContents))
			err = cli.LoadConfiguration(cfg, file)
			So(err, ShouldNotBeNil)
		})

		Convey("Should reject missing members list", func() {
			cfg := config.New()

			configStr := `
			{
				"storage": {
					"RootDirectory": "/tmp/example"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "800"
				},
				"cluster" {
					"hashKey": "loremipsumdolors"
				}
			}`

			file := MakeTempFileWithContent(t, "cluster-config.json", configStr)
			err = cli.LoadConfiguration(cfg, file)
			So(err, ShouldNotBeNil)
		})

		Convey("Should reject missing hashkey", func() {
			cfg := config.New()

			configStr := `
			{
				"storage": {
					"RootDirectory": "/tmp/example"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "800"
				},
				"cluster" {
					"members": ["127.0.0.1:9000"]
				}
			}`

			file := MakeTempFileWithContent(t, "cluster-config.json", configStr)
			err = cli.LoadConfiguration(cfg, file)
			So(err, ShouldNotBeNil)
		})

		Convey("Should reject a hashkey that is too short", func() {
			cfg := config.New()
			err := json.Unmarshal(cfgFileContents, cfg)
			So(err, ShouldBeNil)

			// set the hashkey to a string shorter than 16 characters
			cfg.Cluster.HashKey = "fifteencharacte"

			cfgFileContents, err := json.MarshalIndent(cfg, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "cluster-config.json", string(cfgFileContents))
			err = cli.LoadConfiguration(cfg, file)
			So(err, ShouldNotBeNil)
		})

		Convey("Should reject a hashkey that is too long", func() {
			cfg := config.New()
			err := json.Unmarshal(cfgFileContents, cfg)
			So(err, ShouldBeNil)

			// set the hashkey to a string longer than 16 characters
			cfg.Cluster.HashKey = "seventeencharacte"

			cfgFileContents, err := json.MarshalIndent(cfg, "", " ")
			So(err, ShouldBeNil)

			file := MakeTempFileWithContent(t, "cluster-config.json", string(cfgFileContents))
			err = cli.LoadConfiguration(cfg, file)
			So(err, ShouldNotBeNil)
		})
	})
}

// run cli and return output (logPath, rootDir, error).
//
//nolint:unparam // rootDir used by callers waiting for Trivy DB, build tags may not be available.
func runCLIWithConfig(t *testing.T, config string) (string, string, error) {
	t.Helper()
	port := GetFreePort()
	baseURL := GetBaseURL(port)

	logPath := MakeTempFilePath(t, "zot-log.txt")

	rootDir := t.TempDir()
	config = fmt.Sprintf(config, rootDir, port, logPath)

	cfgfile := MakeTempFileWithContent(t, "zot-test.json", config)

	os.Args = []string{"cli_test", "serve", cfgfile}

	// Run CLI in a goroutine, but handle errors via a channel
	errCh := make(chan error, 1)

	go func() {
		errCh <- cli.NewServerRootCmd().Execute()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return "", "", err
		}
	case <-time.After(250 * time.Millisecond): // No startup error
	}

	WaitTillServerReady(baseURL)

	return logPath, rootDir, nil
}

func TestRetentionDelayDefaults(t *testing.T) {
	Convey("Test retention delay defaults to GC delay", t, func() {
		Convey("When retention delay is not specified, it should default to GC delay", func() {
			config := config.New()

			// Config with GC enabled but no retention delay specified
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"gc": true,
					"gcDelay": "2h"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify GC delay is set correctly
			So(config.Storage.GCDelay, ShouldEqual, 2*time.Hour)
			// Verify retention delay defaults to GC delay
			So(config.Storage.Retention.Delay, ShouldEqual, 2*time.Hour)
		})

		Convey("When retention delay is explicitly specified, it should use that value", func() {
			config := config.New()

			// Config with explicit retention delay
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"gc": true,
					"gcDelay": "2h",
					"retention": {
						"delay": "3h"
					}
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify GC delay is set correctly
			So(config.Storage.GCDelay, ShouldEqual, 2*time.Hour)
			// Verify retention delay uses explicit value
			So(config.Storage.Retention.Delay, ShouldEqual, 3*time.Hour)
		})

		Convey("When GC is disabled, retention delay should be 0", func() {
			config := config.New()

			// Config with GC disabled
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"gc": false
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify GC delay is 0 when GC is disabled
			So(config.Storage.GCDelay, ShouldEqual, 0)
			// Verify retention delay is 0 when GC is disabled
			So(config.Storage.Retention.Delay, ShouldEqual, 0)
		})

		Convey("When GC delay is not specified, retention delay should default to default GC delay", func() {
			config := config.New()

			// Config with GC enabled but no gcDelay specified
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"gc": true
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify GC delay defaults to default value
			So(config.Storage.GCDelay, ShouldEqual, storageConstants.DefaultGCDelay)
			// Verify retention delay defaults to default GC delay
			So(config.Storage.Retention.Delay, ShouldEqual, storageConstants.DefaultGCDelay)
		})
	})

	Convey("Test subpath retention delay defaults to subpath GC delay", t, func() {
		Convey("When subpath retention delay is not specified, it should default to subpath GC delay", func() {
			config := config.New()

			// Config with subpath GC enabled but no retention delay specified
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"subPaths": {
						"/a": {
							"rootDirectory": "/tmp/zot-a",
							"gc": true,
							"gcDelay": "30m"
						}
					}
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify subpath GC delay is set correctly
			So(config.Storage.SubPaths["/a"].GCDelay, ShouldEqual, 30*time.Minute)
			// Verify subpath retention delay defaults to subpath GC delay
			So(config.Storage.SubPaths["/a"].Retention.Delay, ShouldEqual, 30*time.Minute)
		})

		Convey("When subpath retention delay is explicitly specified, it should use that value", func() {
			config := config.New()

			// Config with explicit subpath retention delay
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"subPaths": {
						"/a": {
							"rootDirectory": "/tmp/zot-a",
							"gc": true,
							"gcDelay": "30m",
							"retention": {
								"delay": "45m"
							}
						}
					}
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify subpath GC delay is set correctly
			So(config.Storage.SubPaths["/a"].GCDelay, ShouldEqual, 30*time.Minute)
			// Verify subpath retention delay uses explicit value
			So(config.Storage.SubPaths["/a"].Retention.Delay, ShouldEqual, 45*time.Minute)
		})

		Convey("When subpath GC is not specified, retention delay should default to default GC delay", func() {
			config := config.New()

			// Config with subpath but no GC settings
			content := `{
				"storage": {
					"rootDirectory": "/tmp/zot",
					"subPaths": {
						"/a": {
							"rootDirectory": "/tmp/zot-a",
							"gc": true
						}
					}
				},
				"http": {
					"address": "127.0.0.1",
					"port": "8080"
				}
			}`
			configPath := MakeTempFileWithContent(t, "zot-test.json", content)

			err := cli.LoadConfiguration(config, configPath)
			So(err, ShouldBeNil)

			// Verify subpath GC delay defaults to default value
			So(config.Storage.SubPaths["/a"].GCDelay, ShouldEqual, storageConstants.DefaultGCDelay)
			// Verify subpath retention delay defaults to default GC delay
			So(config.Storage.SubPaths["/a"].Retention.Delay, ShouldEqual, storageConstants.DefaultGCDelay)
		})
	})
}

func TestBearerASMConfigValidation(t *testing.T) {
	Convey("Test bearer ASM config validation", t, func() {
		Convey("Reject both cert and awsSecretsManager", func() {
			content := `{
				"storage": {"rootDirectory": "/tmp/zot"},
				"http": {
					"address": "127.0.0.1", "port": "8080",
					"auth": {
						"bearer": {
							"realm": "test", "service": "test",
							"cert": "/some/cert.pem",
							"awsSecretsManager": {"region": "us-east-1", "secretName": "my-secret"}
						}
					}
				}
			}`
			cfg := config.New()
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
			err := cli.LoadConfiguration(cfg, tmpfile)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrBadConfig)
		})

		Convey("Reject empty region", func() {
			content := `{
				"storage": {"rootDirectory": "/tmp/zot"},
				"http": {
					"address": "127.0.0.1", "port": "8080",
					"auth": {
						"bearer": {
							"realm": "test", "service": "test",
							"awsSecretsManager": {"region": "", "secretName": "my-secret"}
						}
					}
				}
			}`
			cfg := config.New()
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
			err := cli.LoadConfiguration(cfg, tmpfile)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrBadConfig)
		})

		Convey("Reject empty secretName", func() {
			content := `{
				"storage": {"rootDirectory": "/tmp/zot"},
				"http": {
					"address": "127.0.0.1", "port": "8080",
					"auth": {
						"bearer": {
							"realm": "test", "service": "test",
							"awsSecretsManager": {"region": "us-east-1", "secretName": ""}
						}
					}
				}
			}`
			cfg := config.New()
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
			err := cli.LoadConfiguration(cfg, tmpfile)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrBadConfig)
		})

		Convey("Reject negative refreshInterval", func() {
			content := `{
				"storage": {"rootDirectory": "/tmp/zot"},
				"http": {
					"address": "127.0.0.1", "port": "8080",
					"auth": {
						"bearer": {
							"realm": "test", "service": "test",
							"awsSecretsManager": {"region": "us-east-1", "secretName": "my-secret", "refreshInterval": "-1s"}
						}
					}
				}
			}`
			cfg := config.New()
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
			err := cli.LoadConfiguration(cfg, tmpfile)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrBadConfig)
		})

		Convey("Valid ASM config is accepted", func() {
			content := `{
				"storage": {"rootDirectory": "/tmp/zot"},
				"http": {
					"address": "127.0.0.1", "port": "8080",
					"auth": {
						"bearer": {
							"realm": "test", "service": "test",
							"awsSecretsManager": {"region": "us-east-1", "secretName": "my-secret"}
						}
					}
				}
			}`
			cfg := config.New()
			tmpfile := MakeTempFileWithContent(t, "zot-test.json", content)
			err := cli.LoadConfiguration(cfg, tmpfile)
			So(err, ShouldBeNil)
		})
	})
}
