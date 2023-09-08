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

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

const (
	customArtTypeV1 = "application/custom.art.type.v1"
	customArtTypeV2 = "application/custom.art.type.v2"
	repoName        = "repo"
)

func TestReferrerCLI(t *testing.T) {
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

		repo := repoName
		image := test.CreateRandomImage()

		err := test.UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		ref1 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := test.CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = test.UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		args := []string{"subject", repo + "@" + image.DigestStr(), "--config", "reftest"}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
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
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())

		fmt.Println(buff.String())

		os.Remove(configPath)

		args = []string{"subject", repo + ":" + "tag", "--config", "reftest"}

		configPath = makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd = NewSearchCommand(new(searchService))

		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())

		fmt.Println(buff.String())
	})

	Convey("Test REST", t, func() {
		rootDir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := false
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = rootDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		repo := repoName
		image := test.CreateRandomImage()

		err := test.UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		ref1 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := test.CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = test.UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		// get referrers by digest
		args := []string{"subject", repo + "@" + image.DigestStr(), "--config", "reftest"}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))

		cmd := NewSearchCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())
		fmt.Println(buff.String())

		os.Remove(configPath)

		args = []string{"subject", repo + ":" + "tag", "--config", "reftest"}

		configPath = makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())
		fmt.Println(buff.String())
	})
}

func TestFormatsReferrersCLI(t *testing.T) {
	Convey("Create server", t, func() {
		rootDir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := false
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = rootDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		repo := repoName
		image := test.CreateRandomImage()

		err := test.UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		// add referrers
		ref1 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := test.CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = test.UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		Convey("JSON format", func() {
			args := []string{"subject", repo + "@" + image.DigestStr(), "--format", "json", "--config", "reftest"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			cmd := NewSearchCommand(new(searchService))

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
		})
		Convey("YAML format", func() {
			args := []string{"subject", repo + "@" + image.DigestStr(), "--format", "yaml", "--config", "reftest"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			cmd := NewSearchCommand(new(searchService))

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
		})
		Convey("Invalid format", func() {
			args := []string{"subject", repo + "@" + image.DigestStr(), "--format", "invalid_format", "--config", "reftest"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			cmd := NewSearchCommand(new(searchService))

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestReferrersCLIErrors(t *testing.T) {
	Convey("Errors", t, func() {
		cmd := NewSearchCommand(new(searchService))

		Convey("no url provided", func() {
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "reftest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest","showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("getConfigValue", func() {
			args := []string{"subject", "repo/alpine", "--config", "reftest"}

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
			args := []string{"query", "repo", "--config", "reftest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":"bad"}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad verifyTLSConfig ", func() {
			args := []string{"query", "repo", "reftest"}

			configPath := makeConfigFile(
				`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":false, "verify-tls": "bad"}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("url from config is empty", func() {
			args := []string{"subject", "repo/alpine", "--config", "reftest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest", "url":"", "showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad params combination", func() {
			args := []string{"query", "repo", "reftest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
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

		args := []string{"query", "test/alpin", "--verbose", "--config", "searchtest"}

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

		args = []string{"query", "repo/alpine:", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--format", "json", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--format", "yaml", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--config", "searchtest"}

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
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"searchtest", "url":"", "showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
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
			err := test.UploadImage(test.CreateRandomImage(), baseURL, "repo", "tag")
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
			err := test.UploadImage(test.CreateRandomImage(), baseURL, "repo", "tag")
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
