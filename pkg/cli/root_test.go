package cli_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/anuvu/zot/pkg/api/config"
	"github.com/anuvu/zot/pkg/cli"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
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
