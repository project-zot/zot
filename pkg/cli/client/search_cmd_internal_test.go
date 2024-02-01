//go:build search
// +build search

package client

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
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
)

func TestSearchCommandGQL(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		},
	}

	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	Convey("commands without gql", t, func() {
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		Convey("query", func() {
			args := []string{"query", "repo/al", "--config", "searchtest"}
			cmd := NewSearchCommand(mockService{})

			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "repo 8c25cb36 false 100B")
			So(actual, ShouldContainSubstring, "repo 100B 2010-01-01 01:01:01 +0000 UTC 0 0")
		})

		Convey("query command errors", func() {
			// no url
			args := []string{"repo/al", "--config", "searchtest"}
			cmd := NewSearchQueryCommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("subject", func() {
			err := UploadImage(CreateRandomImage(), baseURL, "repo", "tag")
			So(err, ShouldBeNil)

			args := []string{"subject", "repo:tag", "--config", "searchtest"}
			cmd := NewSearchCommand(mockService{})

			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "ArtifactType 100 B Digest")
		})

		Convey("subject command errors", func() {
			// no url
			args := []string{"repo:tag", "--config", "searchtest"}
			cmd := NewSearchSubjectCommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestSearchCommandREST(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	Convey("commands without gql", t, func() {
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		Convey("query", func() {
			args := []string{"query", "repo/al", "--config", "searchtest"}
			cmd := NewSearchCommand(mockService{})

			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("subject", func() {
			err := UploadImage(CreateRandomImage(), baseURL, "repo", "tag")
			So(err, ShouldBeNil)

			args := []string{"subject", "repo:tag", "--config", "searchtest"}
			cmd := NewSearchCommand(mockService{})

			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring,
				"art.type 100 B sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
		})
	})
}
