//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli/cmdflags"
	"zotregistry.io/zot/pkg/test"
)

func TestReposCommand(t *testing.T) {
	Convey("repos", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"repostest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		args := []string{"list"}
		cmd := NewRepoCommand(mockService{})
		cmd.PersistentFlags().String(cmdflags.ConfigFlag, "repostest", "")
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo1")
		So(actual, ShouldContainSubstring, "repo2")
	})
}
