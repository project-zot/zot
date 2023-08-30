//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli/cmdflags"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

func TestGlobalSearchers(t *testing.T) {
	globalSearcher := globalSearcherGQL{}

	Convey("GQL Searcher", t, func() {
		Convey("Bad parameters", func() {
			ok, err := globalSearcher.search(searchConfig{params: map[string]*string{
				"badParam": ref("badParam"),
			}})

			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("global searcher service fail", func() {
			conf := searchConfig{
				params: map[string]*string{
					"query": ref("repo"),
				},
				searchService: NewSearchService(),
				user:          ref("test:pass"),
				servURL:       ref("127.0.0.1:8080"),
				verifyTLS:     ref(false),
				debug:         ref(false),
				verbose:       ref(false),
				fixedFlag:     ref(false),
			}
			ok, err := globalSearcher.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("print images fail", func() {
			conf := searchConfig{
				params: map[string]*string{
					"query": ref("repo"),
				},
				user:          ref("user:pass"),
				outputFormat:  ref("bad-format"),
				searchService: mockService{},
				resultWriter:  io.Discard,
				verbose:       ref(false),
			}
			ok, err := globalSearcher.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})
	})
}

func TestSearchCLI(t *testing.T) {
	Convey("Test GQL", t, func() {
		rootDir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = rootDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		const (
			repo1  = "repo"
			r1tag1 = "repo1tag1"
			r1tag2 = "repo1tag2"

			repo2  = "repo/alpine"
			r2tag1 = "repo2tag1"
			r2tag2 = "repo2tag2"

			repo3  = "repo/test/alpine"
			r3tag1 = "repo3tag1"
			r3tag2 = "repo3tag2"
		)

		image1 := test.CreateImageWith().
			RandomLayers(1, 10).
			ImageConfig(ispec.Image{
				Created:  test.DefaultTimeRef(),
				Platform: ispec.Platform{OS: "Os", Architecture: "Arch"},
			}).
			Build()
		formatterDigest1 := image1.Digest().Encoded()[:8]

		image2 := test.CreateImageWith().
			RandomLayers(1, 10).
			DefaultConfig().
			Build()
		formatterDigest2 := image2.Digest().Encoded()[:8]

		err := test.UploadImage(image1, baseURL, repo1, r1tag1)
		So(err, ShouldBeNil)
		err = test.UploadImage(image2, baseURL, repo1, r1tag2)
		So(err, ShouldBeNil)

		err = test.UploadImage(image1, baseURL, repo2, r2tag1)
		So(err, ShouldBeNil)
		err = test.UploadImage(image2, baseURL, repo2, r2tag2)
		So(err, ShouldBeNil)

		err = test.UploadImage(image1, baseURL, repo3, r3tag1)
		So(err, ShouldBeNil)
		err = test.UploadImage(image2, baseURL, repo3, r3tag2)
		So(err, ShouldBeNil)

		// search by repos

		args := []string{"searchtest", "--query", "test/alpin", "--verbose"}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd := NewSearchCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "NAME SIZE LAST UPDATED DOWNLOADS STARS PLATFORMS")
		So(str, ShouldContainSubstring, "repo/test/alpine 1.1kB 2010-01-01 01:01:01 +0000 UTC 0 0")
		So(str, ShouldContainSubstring, "Os/Arch")
		So(str, ShouldContainSubstring, "linux/amd64")

		fmt.Println("\n", buff.String())

		os.Remove(configPath)

		cmd = NewSearchCommand(new(searchService))

		args = []string{"searchtest", "--query", "repo/alpine:"}

		configPath = makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))

		defer os.Remove(configPath)

		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(str, ShouldContainSubstring, "repo/alpine repo2tag1 Os/Arch "+formatterDigest1+" false 525B")
		So(str, ShouldContainSubstring, "repo/alpine repo2tag2 linux/amd64 "+formatterDigest2+" false 552B")

		fmt.Println("\n", buff.String())
	})
}

func TestFormatsSearchCLI(t *testing.T) {
	Convey("", t, func() {
		rootDir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = rootDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		const (
			repo1  = "repo"
			r1tag1 = "repo1tag1"
			r1tag2 = "repo1tag2"

			repo2  = "repo/alpine"
			r2tag1 = "repo2tag1"
			r2tag2 = "repo2tag2"

			repo3  = "repo/test/alpine"
			r3tag1 = "repo3tag1"
			r3tag2 = "repo3tag2"
		)

		image1 := test.CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()
		image2 := test.CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

		err := test.UploadImage(image1, baseURL, repo1, r1tag1)
		So(err, ShouldBeNil)
		err = test.UploadImage(image2, baseURL, repo1, r1tag2)
		So(err, ShouldBeNil)

		err = test.UploadImage(image1, baseURL, repo2, r2tag1)
		So(err, ShouldBeNil)
		err = test.UploadImage(image2, baseURL, repo2, r2tag2)
		So(err, ShouldBeNil)

		err = test.UploadImage(image1, baseURL, repo3, r3tag1)
		So(err, ShouldBeNil)
		err = test.UploadImage(image2, baseURL, repo3, r3tag2)
		So(err, ShouldBeNil)

		cmd := NewSearchCommand(new(searchService))

		Convey("JSON format", func() {
			args := []string{"searchtest", "--format", "json", "--query", "repo/alpine"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
		})

		Convey("YAML format", func() {
			args := []string{"searchtest", "--format", "yaml", "--query", "repo/alpine"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
		})

		Convey("Invalid format", func() {
			args := []string{"searchtest", "--format", "invalid", "--query", "repo/alpine"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestSearchCLIErrors(t *testing.T) {
	Convey("Errors", t, func() {
		cmd := NewSearchCommand(new(searchService))

		Convey("no url provided", func() {
			args := []string{"searchtest", "--format", "invalid", "--query", "repo/alpine"}

			configPath := makeConfigFile(`{"configs":[{"_name":"searchtest","showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("getConfigValue", func() {
			args := []string{"searchtest", "--format", "invalid", "--query", "repo/alpine"}

			configPath := makeConfigFile(`bad-json`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad showspinnerConfig ", func() {
			args := []string{"searchtest"}

			configPath := makeConfigFile(
				`{"configs":[{"_name":"searchtest", "url":"http://127.0.0.1:8080", "showspinner":"bad"}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad verifyTLSConfig ", func() {
			args := []string{"searchtest"}

			configPath := makeConfigFile(
				`{"configs":[{"_name":"searchtest", "url":"http://127.0.0.1:8080", "showspinner":false, "verify-tls": "bad"}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("url from config is empty", func() {
			args := []string{"searchtest", "--format", "invalid", "--query", "repo/alpine"}

			configPath := makeConfigFile(`{"configs":[{"_name":"searchtest", "url":"", "showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("no url provided error", func() {
			args := []string{}

			configPath := makeConfigFile(`bad-json`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("globalSearch without gql active", func() {
			err := globalSearch(searchConfig{
				user:      ref("t"),
				servURL:   ref("t"),
				verifyTLS: ref(false),
				debug:     ref(false),
				params: map[string]*string{
					"query": ref("t"),
				},
				resultWriter: io.Discard,
			})
			So(err, ShouldNotBeNil)
		})
	})
}

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
			args := []string{"query", "repo/al"}
			cmd := NewSearchCommand(mockService{})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "searchtest", "")
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
			args := []string{"repo/al"}
			cmd := NewSearchQueryCommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("subject", func() {
			err := test.UploadImage(test.CreateRandomImage(), baseURL, "repo", "tag")
			So(err, ShouldBeNil)

			args := []string{"subject", "repo:tag"}
			cmd := NewSearchCommand(mockService{})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "searchtest", "")
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
			args := []string{"repo:tag"}
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
			args := []string{"query", "repo/al"}
			cmd := NewSearchCommand(mockService{})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "searchtest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("subject", func() {
			err := test.UploadImage(test.CreateRandomImage(), baseURL, "repo", "tag")
			So(err, ShouldBeNil)

			args := []string{"subject", "repo:tag"}
			cmd := NewSearchCommand(mockService{})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "searchtest", "")
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
