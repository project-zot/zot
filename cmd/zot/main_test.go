package main_test

import (
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

		cl := cli.NewRootCmd()
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}
