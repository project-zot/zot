//go:build !sync

package sync_test

import (
	"context"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestOnDemandStub(t *testing.T) {
	Convey("stubbed on demand always allows upstream manifest checks", t, func() {
		onDemand := &sync.BaseOnDemand{}

		So(onDemand.SyncImage(context.Background(), "repo", "latest"), ShouldBeNil)
		So(onDemand.SyncReferrers(context.Background(), "repo", "sha256:digest", nil), ShouldBeNil)
		So(onDemand.ShouldCheckUpstreamManifest("repo", "latest"), ShouldBeTrue)
	})
}

func TestSyncExtension(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()

		globalDir := t.TempDir()
		defaultValue := true

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf.HTTP.Port = "0"
		conf.Storage.RootDirectory = globalDir
		conf.Storage.Commit = true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Sync = &syncconf.Config{
			Enable: &defaultValue,
		}
		conf.Log.Level = "warn"
		conf.Log.Output = logPath

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		baseURL := ctlrManager.StartAndWait()
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

			data, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)

			So(string(data), ShouldContainSubstring,
				"skipping enabling sync extension because given zot binary doesn't include "+
					"this feature,please build a binary that does so")
		})
	})
}
