package main_test

import (
	"io/ioutil"
	"testing"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/cli"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIntegration(t *testing.T) {
	Convey("Make a new controller", t, func() {
		config := api.NewConfig()
		c := api.NewController(config)
		So(c, ShouldNotBeNil)

		tempFile, _ := ioutil.TempFile("", "tmp-")
		cl := cli.NewRootCmd(tempFile.Name())
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}
