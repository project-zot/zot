//go:build !sync
// +build !sync

package sync_test

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestSyncExtension(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		port := test.GetFreePort()

		baseURL := test.GetBaseURL(port)
		globalDir := t.TempDir()
		defaultValue := true

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name())

		conf.HTTP.Port = port
		conf.Storage.RootDirectory = globalDir
		conf.Storage.Commit = true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Sync = &syncconf.Config{
			Enable: &defaultValue,
		}
		conf.Log.Level = "warn"
		conf.Log.Output = logFile.Name()

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		Convey("verify sync is skipped when binary doesn't include it", func() {
			// image
			resp, err := resty.R().
				Head(baseURL + "/v2/" + "invalid" + "/manifests/invalid:0.0.2")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			// reference
			resp, err = resty.R().
				Head(baseURL + "/v2/" + "invalid" + "/manifests/sha256_digest.sig")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)

			So(string(data), ShouldContainSubstring,
				"skipping enabling sync extension because given zot binary doesn't include "+
					"this feature,please build a binary that does so")
		})
	})
}
