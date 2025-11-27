//go:build !imagetrust

package extensions_test

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestImageTrustExtension(t *testing.T) {
	Convey("periodic signature verification is skipped when binary doesn't include imagetrust", t, func() {
		conf := config.New()
		port := test.GetFreePort()

		globalDir := t.TempDir()
		defaultValue := true

		logFile := test.MakeTempFile(t, "zot-log.txt")

		conf.HTTP.Port = port
		conf.Storage.RootDirectory = globalDir
		conf.Storage.Commit = true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Cosign = defaultValue
		conf.Extensions.Trust.Notation = defaultValue
		conf.Log.Level = "warn"
		conf.Log.Output = logFile.Name()

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)

		So(string(data), ShouldContainSubstring,
			"skipping adding to the scheduler a generator for updating signatures validity because "+
				"given binary doesn't include this feature, please build a binary that does so")
	})
}
