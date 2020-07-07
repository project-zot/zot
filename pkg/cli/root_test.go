package cli_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/anuvu/zot/pkg/cli"
	. "github.com/smartystreets/goconvey/convey"
)

func TestUsage(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test usage", t, func(c C) {
		os.Args = []string{"cli_test", "help"}
		err := cli.NewRootCmd(os.TempDir()).Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test version", t, func(c C) {
		os.Args = []string{"cli_test", "--version"}
		err := cli.NewRootCmd(os.TempDir()).Execute()
		So(err, ShouldBeNil)
	})
}

func TestServe(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test serve help", t, func(c C) {
		os.Args = []string{"cli_test", "serve", "-h"}
		err := cli.NewRootCmd(os.TempDir()).Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test serve config", t, func(c C) {
		Convey("unknown config", func(c C) {
			os.Args = []string{"cli_test", "serve", path.Join(os.TempDir(), "/x")}
			So(func() { _ = cli.NewRootCmd(os.TempDir()).Execute() }, ShouldPanic)
		})

		Convey("non-existent config", func(c C) {
			os.Args = []string{"cli_test", "serve", path.Join(os.TempDir(), "/x.yaml")}
			So(func() { _ = cli.NewRootCmd(os.TempDir()).Execute() }, ShouldPanic)
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
			So(func() { _ = cli.NewRootCmd(os.TempDir()).Execute() }, ShouldPanic)
		})
	})
}

func TestGC(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("Test gc", t, func(c C) {
		os.Args = []string{"cli_test", "garbage-collect", "-h"}
		err := cli.NewRootCmd(os.TempDir()).Execute()
		So(err, ShouldBeNil)
	})
}
