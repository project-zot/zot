package cli_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"gopkg.in/resty.v1"

	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli"
	. "zotregistry.io/zot/test"
)

func TestUsage(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test usage", t, func(c C) {
		os.Args = []string{"cli_test", "help"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test version", t, func(c C) {
		os.Args = []string{"cli_test", "--version"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestServe(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test serve help", t, func(c C) {
		os.Args = []string{"cli_test", "serve", "-h"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test serve config", t, func(c C) {
		Convey("unknown config", func(c C) {
			os.Args = []string{"cli_test", "serve", path.Join(os.TempDir(), "/x")}
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
		})

		Convey("non-existent config", func(c C) {
			os.Args = []string{"cli_test", "serve", path.Join(os.TempDir(), "/x.yaml")}
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
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
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
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
		So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
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
		So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
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
		So(func() { _ = cli.NewRootCmd().Execute() }, ShouldNotPanic)
	})

	Convey("Test verify w/ sync and w/o filesystem storage", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot", "storageDriver": {"name": "s3"}},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"url":"localhost:9999"}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify with bad sync prefixes", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"storage":{"rootDirectory":"/tmp/zot"},
							"http":{"address":"127.0.0.1","port":"8080","realm":"zot",
							"auth":{"htpasswd":{"path":"test/data/htpasswd"},"failDelay":1}},
							"extensions":{"sync": {"registries": [{"url":"localhost:9999",
							"content": [{"prefix":"[repo%^&"}]}]}}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
	})

	Convey("Test verify good config", t, func(c C) {
		tmpfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)
		defer os.Remove(tmpfile.Name()) // clean up
		content := []byte(`{"version": "0.1.0-dev", "storage": {"rootDirectory": "/tmp/zot"},
							"http": {"address": "127.0.0.1", "port": "8080", "ReadOnly": false},
							"log": {"level": "debug"}}`)
		_, err = tmpfile.Write(content)
		So(err, ShouldBeNil)
		err = tmpfile.Close()
		So(err, ShouldBeNil)
		os.Args = []string{"cli_test", "verify", tmpfile.Name()}
		err = cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestLoadConfig(t *testing.T) {
	Convey("Test viper load config", t, func(c C) {
		config := config.New()
		So(func() { cli.LoadConfiguration(config, "../../examples/config-policy.json") }, ShouldNotPanic)
		adminPolicy := viper.GetStringMapStringSlice("http.accessControl.adminPolicy")
		So(config.AccessControl.AdminPolicy.Actions, ShouldResemble, adminPolicy["actions"])
		So(config.AccessControl.AdminPolicy.Users, ShouldResemble, adminPolicy["users"])
	})
}

func TestGC(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test gc", t, func(c C) {
		os.Args = []string{"cli_test", "garbage-collect", "-h"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestScrub(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test scrub help", t, func(c C) {
		os.Args = []string{"cli_test", "scrub", "-h"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test scrub config", t, func(c C) {
		Convey("non-existent config", func(c C) {
			os.Args = []string{"cli_test", "scrub", path.Join(os.TempDir(), "/x.yaml")}
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
		})

		Convey("unknown config", func(c C) {
			os.Args = []string{"cli_test", "scrub", path.Join(os.TempDir(), "/x")}
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
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
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
		})

		Convey("server is running", func(c C) {
			port := GetFreePort()
			config := config.New()
			config.HTTP.Port = port
			controller := api.NewController(config)

			dir, err := ioutil.TempDir("", "scrub-test")
			if err != nil {
				panic(err)
			}

			defer os.RemoveAll(dir)

			controller.Config.Storage.RootDirectory = dir
			go func(controller *api.Controller) {
				// this blocks
				if err := controller.Run(); err != nil {
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
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)

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
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
		})

		Convey("bad index.json", func(c C) {
			port := GetFreePort()

			dir, err := ioutil.TempDir("", "scrub-test")
			if err != nil {
				panic(err)
			}
			defer os.RemoveAll(dir)

			repoName := "badIndex"

			repo, err := ioutil.TempDir(dir, repoName)
			if err != nil {
				panic(err)
			}

			if err := os.MkdirAll(fmt.Sprintf("%s/blobs", repo), 0755); err != nil {
				panic(err)
			}

			if _, err = os.Stat(fmt.Sprintf("%s/oci-layout", repo)); err != nil {
				content := []byte(`{"imageLayoutVersion": "1.0.0"}`)
				if err = ioutil.WriteFile(fmt.Sprintf("%s/oci-layout", repo), content, 0600); err != nil {
					panic(err)
				}
			}

			if _, err = os.Stat(fmt.Sprintf("%s/index.json", repo)); err != nil {
				content := []byte(`not a JSON content`)
				if err = ioutil.WriteFile(fmt.Sprintf("%s/index.json", repo), content, 0600); err != nil {
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
			So(func() { _ = cli.NewRootCmd().Execute() }, ShouldPanic)
		})
	})
}
