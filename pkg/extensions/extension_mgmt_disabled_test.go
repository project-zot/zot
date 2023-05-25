//go:build !mgmt

package extensions_test

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

func TestMgmtExtension(t *testing.T) {
	Convey("periodic signature verification is skipped when binary doesn't include mgmt", t, func() {
		conf := config.New()
		port := test.GetFreePort()

		globalDir := t.TempDir()
		defaultValue := true

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name())

		conf.HTTP.Port = port
		conf.Storage.RootDirectory = globalDir
		conf.Storage.Commit = true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}
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
