//go:build search
// +build search

package client

import (
	"io"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	test "zotregistry.io/zot/pkg/test/common"
)

func TestGQLQueries(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	dir := t.TempDir()
	conf.Storage.RootDirectory = dir
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		},
	}

	ctlr := api.NewController(conf)

	cm := test.NewControllerManager(ctlr)
	cm.StartAndWait(conf.HTTP.Port)

	defer cm.StopServer()

	searchConfig := searchConfig{
		servURL:      baseURL,
		user:         "",
		verifyTLS:    false,
		debug:        false,
		resultWriter: io.Discard,
	}

	Convey("Make sure the current CLI used the right queries in case they change", t, func() {
		Convey("ImageList", func() {
			err := CheckExtEndPointQuery(searchConfig, ImageListQuery())
			So(err, ShouldBeNil)
		})

		Convey("ImageListForDigest", func() {
			err := CheckExtEndPointQuery(searchConfig, ImageListForDigestQuery())
			So(err, ShouldBeNil)
		})

		Convey("BaseImageList", func() {
			err := CheckExtEndPointQuery(searchConfig, BaseImageListQuery())
			So(err, ShouldBeNil)
		})

		Convey("DerivedImageList", func() {
			err := CheckExtEndPointQuery(searchConfig, DerivedImageListQuery())
			So(err, ShouldBeNil)
		})

		Convey("CVEListForImage", func() {
			err := CheckExtEndPointQuery(searchConfig, CVEListForImageQuery())
			So(err, ShouldBeNil)
		})

		Convey("ImageListForCVE", func() {
			err := CheckExtEndPointQuery(searchConfig, ImageListForCVEQuery())
			So(err, ShouldBeNil)
		})

		Convey("ImageListWithCVEFixed", func() {
			err := CheckExtEndPointQuery(searchConfig, ImageListWithCVEFixedQuery())
			So(err, ShouldBeNil)
		})

		Convey("Referrers", func() {
			err := CheckExtEndPointQuery(searchConfig, ReferrersQuery())
			So(err, ShouldBeNil)
		})

		Convey("GlobalSearch", func() {
			err := CheckExtEndPointQuery(searchConfig, GlobalSearchQuery())
			So(err, ShouldBeNil)
		})
	})
}
