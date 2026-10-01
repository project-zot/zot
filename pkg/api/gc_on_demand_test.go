package api_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestGCOnDemand(t *testing.T) {
	Convey("On-demand GC is available for each store with GC enabled", t, func() {
		conf := config.New()
		conf.HTTP.Port = test.GetFreePort()
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = true
		conf.Storage.GCInterval = time.Hour
		conf.Storage.SubPaths = map[string]config.StorageConfig{
			"/gc":   {RootDirectory: t.TempDir(), GC: true, GCInterval: time.Hour},
			"/nogc": {RootDirectory: t.TempDir(), GC: false},
		}

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait()

		defer ctlrManager.StopServer()

		defaultStore, exists := ctlr.GCOnDemand("/")
		So(exists, ShouldBeTrue)
		So(defaultStore, ShouldNotBeNil)

		subStore, exists := ctlr.GCOnDemand("/gc")
		So(exists, ShouldBeTrue)
		So(subStore, ShouldNotBeNil)
		So(subStore != defaultStore, ShouldBeTrue)

		noGCStore, exists := ctlr.GCOnDemand("/nogc")
		So(exists, ShouldBeTrue)
		So(noGCStore, ShouldBeNil)

		unknownStore, exists := ctlr.GCOnDemand("/unknown")
		So(exists, ShouldBeFalse)
		So(unknownStore, ShouldBeNil)

		Convey("and is replaced when background tasks restart on config reload", func() {
			ctlr.StopBackgroundTasks()
			ctlr.StartBackgroundTasks()

			reloaded, exists := ctlr.GCOnDemand("/")
			So(exists, ShouldBeTrue)
			So(reloaded, ShouldNotBeNil)
			So(reloaded != defaultStore, ShouldBeTrue)

			// bound to the new scheduler
			So(reloaded.SweepNow(), ShouldBeNil)
		})
	})
}
