//go:build search
// +build search

package client_test

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/cli/client"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
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

		err := UploadImage(CreateRandomImage(), baseURL, "repo1", "tag1")
		So(err, ShouldBeNil)
		err = UploadImage(CreateRandomImage(), baseURL, "repo2", "tag2")
		So(err, ShouldBeNil)

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"repostest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		args := []string{"list", "--config", "repostest"}
		cmd := client.NewRepoCommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo1")
		So(actual, ShouldContainSubstring, "repo2")

		args = []string{"list", "--sort-by", "alpha-dsc", "--config", "repostest"}
		cmd = client.NewRepoCommand(client.NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space = regexp.MustCompile(`\s+`)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo1")
		So(actual, ShouldContainSubstring, "repo2")
		So(strings.Index(actual, "repo2"), ShouldBeLessThan, strings.Index(actual, "repo1"))

		args = []string{"list", "--sort-by", "alpha-asc", "--config", "repostest"}
		cmd = client.NewRepoCommand(client.NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space = regexp.MustCompile(`\s+`)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo1")
		So(actual, ShouldContainSubstring, "repo2")
		So(strings.Index(actual, "repo1"), ShouldBeLessThan, strings.Index(actual, "repo2"))
	})
}

func TestSuggestions(t *testing.T) {
	Convey("Suggestions", t, func() {
		space := regexp.MustCompile(`\s+`)
		suggestion := client.ShowSuggestionsIfUnknownCommand(
			client.NewRepoCommand(client.NewSearchService()), []string{"bad-command"})
		str := space.ReplaceAllString(suggestion.Error(), " ")
		So(str, ShouldContainSubstring, "unknown cli subcommand")

		suggestion = client.ShowSuggestionsIfUnknownCommand(
			client.NewRepoCommand(client.NewSearchService()), []string{"listt"})
		str = space.ReplaceAllString(suggestion.Error(), " ")
		So(str, ShouldContainSubstring, "Did you mean this? list")
	})
}
