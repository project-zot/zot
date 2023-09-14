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

		err := test.UploadImage(test.CreateRandomImage(), baseURL, "repo1", "tag1")
		So(err, ShouldBeNil)
		err = test.UploadImage(test.CreateRandomImage(), baseURL, "repo2", "tag2")
		So(err, ShouldBeNil)

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"repostest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		args := []string{"list", "--config", "repostest"}
		cmd := NewRepoCommand(mockService{})
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
		cmd = NewRepoCommand(new(searchService))
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
		cmd = NewRepoCommand(new(searchService))
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
		suggestion := ShowSuggestionsIfUnknownCommand(NewRepoCommand(mockService{}), []string{"bad-command"})
		str := space.ReplaceAllString(suggestion.Error(), " ")
		So(str, ShouldContainSubstring, "unknown subcommand")

		suggestion = ShowSuggestionsIfUnknownCommand(NewRepoCommand(mockService{}), []string{"listt"})
		str = space.ReplaceAllString(suggestion.Error(), " ")
		So(str, ShouldContainSubstring, "Did you mean this? list")
	})
}
