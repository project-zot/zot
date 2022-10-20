package main //nolint:testpackage // separate binary

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
)

func TestIntegration(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		c := api.NewController(conf)
		So(c, ShouldNotBeNil)

		cl := NewPerfRootCmd()
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}
