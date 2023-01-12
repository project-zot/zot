package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli"
	"zotregistry.io/zot/pkg/storage"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/s3"
	. "zotregistry.io/zot/pkg/test"
)

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

func TestCliUsage(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test usage", t, func(c C) {
		os.Args = []string{"cli_test", "help"}
		err := cli.NewCliRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test version", t, func(c C) {
		os.Args = []string{"cli_test", "--version"}
		err := cli.NewCliRootCmd().Execute()
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
		Convey("unknown config", func(c C) {
			os.Args = []string{"cli_test", "serve", path.Join(os.TempDir(), "/x")}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})

		Convey("non-existent config", func(c C) {
			os.Args = []string{"cli_test", "serve", path.Join(os.TempDir(), "/x.yaml")}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})

		Convey("bad config", func(c C) {
			rootDir := t.TempDir()

			tmpFile := path.Join(rootDir, "zot-test.json")
			err := os.WriteFile(tmpFile, []byte(`{"log":{}}`), 0o0600)
			So(err, ShouldBeNil)

			os.Args = []string{"cli_test", "serve", tmpFile}

			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})

		Convey("config with missing rootDir", func(c C) {
			rootDir := t.TempDir()

			// missing storag config should result in an error in Controller.Init()
			content := []byte(`{
				"distSpecVersion": "1.1.0-dev",
				"http": {
					"address":"127.0.0.1",
					"port":"8080"
				}
			}`)

			tmpFile := path.Join(rootDir, "zot-test.json")
			err := os.WriteFile(tmpFile, content, 0o0600)
			So(err, ShouldBeNil)

			os.Args = []string{"cli_test", "serve", tmpFile}

			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

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
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"log":{}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify CVE warn for remote storage", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up

		content := []byte(`{
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
		}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		content = []byte(`{
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
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test cached db config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up

		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		content := []byte(`{
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
		}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// local storage with remote caching
		content = []byte(`{
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
		 }`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// unsupported cache driver
		content = []byte(`{
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
		 }`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// remoteCache false but provided cacheDriver config, ignored
		content = []byte(`{
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
		 }`)

		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)

		// SubPaths
		// dedupe true, remote storage, remoteCache true, but no cacheDriver (remote)
		content = []byte(`{
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
		 }`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// local storage with remote caching
		content = []byte(`{
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
		 }`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// unsupported cache driver
		content = []byte(`{
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
		 }`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// remoteCache false but provided cacheDriver config, ignored
		content = []byte(`{
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
		 }`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test apply defaults cache db", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up

		// s3 dedup=false, check for previous dedup usage and set to true if cachedb found
		cacheDir := t.TempDir()
		existingDBPath := path.Join(cacheDir, s3.CacheDBName+storageConstants.DBExtensionName)
		_, err = os.Create(existingDBPath)
		So(err, ShouldBeNil)

		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot", "dedupe": false,
							"storageDriver": {"rootDirectory": "` + cacheDir + `"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// subpath s3 dedup=false, check for previous dedup usage and set to true if cachedb found
		cacheDir = t.TempDir()
		existingDBPath = path.Join(cacheDir, s3.CacheDBName+storageConstants.DBExtensionName)
		_, err = os.Create(existingDBPath)
		So(err, ShouldBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot", "dedupe": true,
							"subpaths": {"/a": {"rootDirectory":"/tmp/zot1", "dedupe": false,
							"storageDriver": {"rootDirectory": "` + cacheDir + `"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// subpath s3 dedup=false, check for previous dedup usage and set to true if cachedb found
		cacheDir = t.TempDir()

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot", "dedupe": true,
							"subpaths": {"/a": {"rootDirectory":"/tmp/zot1", "dedupe": true,
							"storageDriver": {"rootDirectory": "` + cacheDir + `"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)

		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify storage driver different than s3", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "gcs"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify subpath storage driver different than s3", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "s3"},
							"subPaths": {"/a": {"rootDirectory": "/zot-a","storageDriver": {"name": "gcs"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify subpath storage config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a"},"/b": {"rootDirectory": "/zot-a"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)

		// sub paths that point to same directory should have same storage config.
		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {{"rootDirectory": "/zot-a","dedupe":"false"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		// sub paths that point to default root directory should not be allowed.
		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot","dedupe":"true"},"/b": {{"rootDirectory": "/zot-a"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"false"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify w/ authorization and w/o authentication", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"repositories":{},"adminPolicy":{"users":["admin"],
							 "actions":["read","create","update","delete"]}}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify w/ authorization and w/ authentication", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1},
							"accessControl":{"repositories":{},"adminPolicy":{"users":["admin"],
							"actions":["read","create","update","delete"]}}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test verify anonymous authorization", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"repositories":{"**":{"anonymousPolicy": ["read", "create"]},
							 "/repo":{"anonymousPolicy": ["read", "create"]}}
							 }}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test verify admin policy authz is not allowed if no authn is configured", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
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
							}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify default policy authz is not allowed if no authn is configured", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
								"accessControl":{
									"repositories": {
										"**":{"defaultPolicy": ["read", "create"]},
										"/repo":{"anonymousPolicy": ["read", "create"]}
									}
								}
							}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify authz per user policies fail if no authn is configured", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
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
							}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify w/ sync and w/o filesystem storage", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "s3"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s"}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify w/ sync and w/ filesystem storage", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s"}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test verify with bad sync prefixes", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"[repo%^&"}]}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify with bad sync content config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"zot-repo","stripPrefix":true,"destination":"/"}]}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify with good sync content config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"zot-repo/*","stripPrefix":true,"destination":"/"}]}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test verify with bad authorization repo patterns", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1},
							"accessControl":{"[":{"policies":[],"anonymousPolicy":[]}}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify sync config default tls value", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 1, "retryDelay": "10s",
							"content": [{"prefix":"repo**"}]}]}}}`)
		_, err = tmpfile.Write(content)
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
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"urls":["localhost:9999"],
							"maxRetries": 10, "content": [{"prefix":"repo**"}]}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify config with unknown keys", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"url": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify config with missing basedn key", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"auth": {"ldap": {"address": "ldap", "userattribute": "uid"}},
							"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify config with missing address key", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"auth": {"ldap": {"basedn": "ou=Users,dc=example,dc=org", "userattribute": "uid"}},
							"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify config with missing userattribute key", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"auth": {"ldap": {"basedn": "ou=Users,dc=example,dc=org", "address": "ldap"}},
							"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify good config", t, func(c C) {
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"address": "127.0.0.1", "port": "8080"},
							"log": {"level": "debug"}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		err = cli.NewServerRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestLoadConfig(t *testing.T) {
	Convey("Test viper load config", t, func(c C) {
		config := config.New()
		err := cli.LoadConfiguration(config, "../../examples/config-policy.json")
		So(err, ShouldBeNil)
	})
	Convey("Test subpath config combination", t, func(c C) {
		config := config.New()
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name())
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/tmp/zot","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s","gcInterval":"1s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"1s"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"false"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true","gcDelay":"0s"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true","gc":"true"},
							"/b": {"rootDirectory": "/b","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldBeNil)
	})

	Convey("Test HTTP port", t, func() {
		config := config.New()
		tmpfile, err := os.CreateTemp("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name())

		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"-1","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)

		content = []byte(`{"storage":{"rootDirectory":"/tmp/zot",
							"subPaths": {"/a": {"rootDirectory": "/zot-a","dedupe":"true"},
							"/b": {"rootDirectory": "/zot-a","dedupe":"true"}}},
							"http":{"address":"127.0.0.1","port":"65536","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}}}`)
		err = os.WriteFile(tmpfile.Name(), content, 0o0600)
		So(err, ShouldBeNil)
		err = cli.LoadConfiguration(config, tmpfile.Name())
		So(err, ShouldNotBeNil)
	})
}

func TestGC(t *testing.T) {
	Convey("Test GC config", t, func(c C) {
		config := config.New()
		err := cli.LoadConfiguration(config, "../../examples/config-multiple.json")
		So(err, ShouldBeNil)
		So(config.Storage.GCDelay, ShouldEqual, storage.DefaultGCDelay)
		err = cli.LoadConfiguration(config, "../../examples/config-gc.json")
		So(err, ShouldBeNil)
		So(config.Storage.GCDelay, ShouldNotEqual, storage.DefaultGCDelay)
		err = cli.LoadConfiguration(config, "../../examples/config-gc-periodic.json")
		So(err, ShouldBeNil)
	})

	Convey("Test GC config corner cases", t, func(c C) {
		contents, err := os.ReadFile("../../examples/config-gc.json")
		So(err, ShouldBeNil)

		Convey("GC delay without GC", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GC = false

			file, err := os.CreateTemp("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = os.WriteFile(file.Name(), contents, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldBeNil)
		})

		Convey("GC interval without GC", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GC = false
			config.Storage.GCDelay = 0
			config.Storage.GCInterval = 24 * time.Hour

			file, err := os.CreateTemp("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = os.WriteFile(file.Name(), contents, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldBeNil)
		})

		Convey("Negative GC delay", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GCDelay = -1 * time.Second

			file, err := os.CreateTemp("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = os.WriteFile(file.Name(), contents, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldNotBeNil)
		})

		Convey("GC delay when GC = false", func() {
			config := config.New()

			file, err := os.CreateTemp("", "gc-false-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot",
			"gc": false}, "http": {"address": "127.0.0.1", "port": "8080"},
			"log": {"level": "debug"}}`)

			err = os.WriteFile(file.Name(), content, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldBeNil)
			So(config.Storage.GCDelay, ShouldEqual, 0)
		})

		Convey("Negative GC interval", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GCInterval = -1 * time.Second

			file, err := os.CreateTemp("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = os.WriteFile(file.Name(), contents, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
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
			os.Args = []string{"cli_test", "scrub", path.Join(os.TempDir(), "/x.yaml")}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})

		Convey("unknown config", func(c C) {
			os.Args = []string{"cli_test", "scrub", path.Join(os.TempDir(), "/x")}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})

		Convey("bad config", func(c C) {
			tmpfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)
			defer os.Remove(tmpfile.Name()) // clean up
			content := []byte(`{"log":{}}`)
			_, err = tmpfile.Write(content)
			So(err, ShouldBeNil)
			err = tmpfile.Close()
			So(err, ShouldBeNil)
			os.Args = []string{"cli_test", "scrub", tmpfile.Name()}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
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

			tmpfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)
			defer os.Remove(tmpfile.Name()) // clean up
			content := []byte(fmt.Sprintf(`{
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
			`, dir, port))
			_, err = tmpfile.Write(content)
			So(err, ShouldBeNil)
			err = tmpfile.Close()
			So(err, ShouldBeNil)

			os.Args = []string{"cli_test", "scrub", tmpfile.Name()}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)

			defer ctrlManager.StopServer()
		})

		Convey("no image store provided", func(c C) {
			port := GetFreePort()

			tmpfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)
			defer os.Remove(tmpfile.Name()) // clean up
			content := []byte(fmt.Sprintf(`{
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
			`, port))
			_, err = tmpfile.Write(content)
			So(err, ShouldBeNil)
			err = tmpfile.Close()
			So(err, ShouldBeNil)
			os.Args = []string{"cli_test", "scrub", tmpfile.Name()}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})

		Convey("bad index.json", func(c C) {
			port := GetFreePort()

			dir := t.TempDir()

			repoName := "badindex"

			repo, err := os.MkdirTemp(dir, repoName)
			if err != nil {
				panic(err)
			}

			if err := os.MkdirAll(fmt.Sprintf("%s/blobs", repo), 0o755); err != nil {
				panic(err)
			}

			if _, err = os.Stat(fmt.Sprintf("%s/oci-layout", repo)); err != nil {
				content := []byte(`{"imageLayoutVersion": "1.0.0"}`)
				if err = os.WriteFile(fmt.Sprintf("%s/oci-layout", repo), content, 0o600); err != nil {
					panic(err)
				}
			}

			if _, err = os.Stat(fmt.Sprintf("%s/index.json", repo)); err != nil {
				content := []byte(`not a JSON content`)
				if err = os.WriteFile(fmt.Sprintf("%s/index.json", repo), content, 0o600); err != nil {
					panic(err)
				}
			}

			tmpfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)
			defer os.Remove(tmpfile.Name()) // clean up
			content := []byte(fmt.Sprintf(`{
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
			`, dir, port))
			_, err = tmpfile.Write(content)
			So(err, ShouldBeNil)
			err = tmpfile.Close()
			So(err, ShouldBeNil)

			os.Args = []string{"cli_test", "scrub", tmpfile.Name()}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})
	})
}
