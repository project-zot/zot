package main //nolint:testpackage // separate binary

import (
	"reflect"
	"testing"

	distspec "github.com/opencontainers/distribution-spec/specs-go"
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
	Convey("Check DistSpecVersion const has same value in distribution-spec", t, func() {
		So(DistSpecVersion, ShouldEqual, distspec.Version)
	})
	Convey("Check ImageTags definition is the same as zotregistry.io/zot/pkg/api.ImageTags", t, func() {
		So(reflect.VisibleFields(reflect.TypeOf(ImageTags{})), ShouldResemble,
			reflect.VisibleFields(reflect.TypeOf(api.ImageTags{})))
	})
}
