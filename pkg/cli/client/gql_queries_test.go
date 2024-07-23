//go:build search
// +build search

package client_test

import (
	"io"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/cli/client"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	test "zotregistry.dev/zot/pkg/test/common"
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

	searchConfig := client.SearchConfig{
		ServURL:      baseURL,
		User:         "",
		VerifyTLS:    false,
		Debug:        false,
		ResultWriter: io.Discard,
	}

	Convey("Make sure the current CLI used the right queries in case they change", t, func() {
		Convey("ImageList", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.ImageListQuery())
			So(err, ShouldBeNil)
		})

		Convey("ImageListForDigest", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.ImageListForDigestQuery())
			So(err, ShouldBeNil)
		})

		Convey("BaseImageList", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.BaseImageListQuery())
			So(err, ShouldBeNil)
		})

		Convey("DerivedImageList", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.DerivedImageListQuery())
			So(err, ShouldBeNil)
		})

		Convey("CVEListForImage", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.CVEListForImageQuery())
			So(err, ShouldBeNil)
		})

		Convey("ImageListForCVE", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.ImageListForCVEQuery())
			So(err, ShouldBeNil)
		})

		Convey("ImageListWithCVEFixed", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.ImageListWithCVEFixedQuery())
			So(err, ShouldBeNil)
		})

		Convey("Referrers", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.ReferrersQuery())
			So(err, ShouldBeNil)
		})

		Convey("GlobalSearch", func() {
			err := client.CheckExtEndPointQuery(searchConfig, client.GlobalSearchQuery())
			So(err, ShouldBeNil)
		})
	})
}
