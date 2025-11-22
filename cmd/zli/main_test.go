//go:build search

package main_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	cli "zotregistry.dev/zot/v2/pkg/cli/client"
)

func TestIntegration(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		c := api.NewController(conf)
		So(c, ShouldNotBeNil)

		cl := cli.NewCliRootCmd()
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}
