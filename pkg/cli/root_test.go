package cli_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli"
	"zotregistry.io/zot/pkg/storage"
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
			tmpfile, err := ioutil.TempFile("", "zot-test*.json")
			So(err, ShouldBeNil)
			defer os.Remove(tmpfile.Name()) // clean up
			content := []byte(`{"log":{}}`)
			_, err = tmpfile.Write(content)
			So(err, ShouldBeNil)
			err = tmpfile.Close()
			So(err, ShouldBeNil)
			os.Args = []string{"cli_test", "serve", tmpfile.Name()}
			So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
		})
	})
}

func TestVerify(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test verify bad config", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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

	Convey("Test verify storage driver different than s3", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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

	Convey("Test verify w/ authorization and w/o authentication", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"adminPolicy":{"users":["admin"],
							 "actions":["read","create","update","delete"]}}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify w/ authorization and w/ authentication", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1},
							"accessControl":{"adminPolicy":{"users":["admin"],
							"actions":["read","create","update","delete"]}}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test verify anonymous authorization", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"**":{"anonymousPolicy": ["read", "create"]},
							 "/repo":{"anonymousPolicy": ["read", "create"]}
							 }}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test verify default authorization fail", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
		 					"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							 "accessControl":{"**":{"defaultPolicy": ["read", "create"]},
							 "/repo":{"anonymousPolicy": ["read", "create"]},
							 "adminPolicy":{"users":["admin"],
							 "actions":["read","create","update","delete"]}
							 }}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify default authorization fail", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"accessControl":{"**":{"defaultPolicy": ["read", "create"]},
							"/repo":{"anonymousPolicy": ["read", "create"]},
							"/repo2":{"policies": [{
								 "users": ["charlie"],
								 "actions": ["read", "create", "update"]}]}
							}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewServerRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify w/ sync and w/o filesystem storage", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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

	Convey("Test verify with bad authorization repo patterns", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
		contents, err := ioutil.ReadFile("../../examples/config-gc.json")
		So(err, ShouldBeNil)

		Convey("GC delay without GC", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GC = false

			file, err := ioutil.TempFile("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = ioutil.WriteFile(file.Name(), contents, 0o600)
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

			file, err := ioutil.TempFile("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = ioutil.WriteFile(file.Name(), contents, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldBeNil)
		})

		Convey("Negative GC delay", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GCDelay = -1 * time.Second

			file, err := ioutil.TempFile("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = ioutil.WriteFile(file.Name(), contents, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldNotBeNil)
		})

		Convey("GC delay when GC = false", func() {
			config := config.New()

			file, err := ioutil.TempFile("", "gc-false-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			content := []byte(`{"distSpecVersion": "1.0.0", "storage": {"rootDirectory": "/tmp/zot",
			"gc": false}, "http": {"address": "127.0.0.1", "port": "8080"},
			"log": {"level": "debug"}}`)

			err = ioutil.WriteFile(file.Name(), content, 0o600)
			So(err, ShouldBeNil)
			err = cli.LoadConfiguration(config, file.Name())
			So(err, ShouldBeNil)
			So(config.Storage.GCDelay, ShouldEqual, 0)
		})

		Convey("Negative GC interval", func() {
			config := config.New()
			err = json.Unmarshal(contents, config)
			config.Storage.GCInterval = -1 * time.Second

			file, err := ioutil.TempFile("", "gc-config-*.json")
			So(err, ShouldBeNil)
			defer os.Remove(file.Name())

			contents, err = json.MarshalIndent(config, "", " ")
			So(err, ShouldBeNil)

			err = ioutil.WriteFile(file.Name(), contents, 0o600)
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
			tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
			go func(controller *api.Controller) {
				// this blocks
				if err := controller.Run(context.Background()); err != nil {
					return
				}
			}(controller)
			// wait till ready
			for {
				_, err := resty.R().Get(fmt.Sprintf("http://127.0.0.1:%s", port))
				if err == nil {
					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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

			defer func(controller *api.Controller) {
				ctx := context.Background()
				_ = controller.Server.Shutdown(ctx)
			}(controller)
		})

		Convey("no image store provided", func(c C) {
			port := GetFreePort()

			tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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

			repoName := "badIndex"

			repo, err := ioutil.TempDir(dir, repoName)
			if err != nil {
				panic(err)
			}

			if err := os.MkdirAll(fmt.Sprintf("%s/blobs", repo), 0o755); err != nil {
				panic(err)
			}

			if _, err = os.Stat(fmt.Sprintf("%s/oci-layout", repo)); err != nil {
				content := []byte(`{"imageLayoutVersion": "1.0.0"}`)
				if err = ioutil.WriteFile(fmt.Sprintf("%s/oci-layout", repo), content, 0o600); err != nil {
					panic(err)
				}
			}

			if _, err = os.Stat(fmt.Sprintf("%s/index.json", repo)); err != nil {
				content := []byte(`not a JSON content`)
				if err = ioutil.WriteFile(fmt.Sprintf("%s/index.json", repo), content, 0o600); err != nil {
					panic(err)
				}
			}

			tmpfile, err := ioutil.TempFile("", "zot-test*.json")
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
