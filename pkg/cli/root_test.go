package cli_test

import (
	"os"
	"testing"

	"github.com/anuvu/zot/pkg/cli"
	. "github.com/smartystreets/goconvey/convey"
)

func TestUsage(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	Convey("Test Usage", t, func(c C) {
		os.Args = []string{"cli_test", "help"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestServe(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	Convey("Test Usage", t, func(c C) {
		os.Args = []string{"cli_test", "serve", "-h"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}

func TestGC(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	Convey("Test Usage", t, func(c C) {
		os.Args = []string{"cli_test", "garbage-collect", "-h"}
		err := cli.NewRootCmd().Execute()
		So(err, ShouldBeNil)
	})
}
