//go:build !events

package extensions_test

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestEventsExtension(t *testing.T) {
	Convey("event generation is skipped when extension is disabled", t, func() {
		conf := config.New()
		port := test.GetFreePort()

		globalDir := t.TempDir()
		defaultValue := true

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf.HTTP.Port = port
		conf.Storage.RootDirectory = globalDir
		conf.Storage.Commit = true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Events = &eventsconf.Config{
			Enable: &defaultValue,
		}
		conf.Log.Level = "warn"
		conf.Log.Output = logPath

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		So(string(data), ShouldContainSubstring,
			"skipping setting up events because given zot binary doesn't include this feature, "+
				"please build a binary that does so")
	})
}
