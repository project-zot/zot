//go:build search

package client_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/cli/client"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
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
		image := CreateRandomImage()

		err := UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		ref1 := CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		args := []string{"subject", repo + "@" + image.DigestStr(), "--config", "reftest"}

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))

		cmd := client.NewSearchCommand(client.NewSearchService())

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

		args = []string{"subject", repo + ":" + "tag", "--config", "reftest"}

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))

		cmd = client.NewSearchCommand(client.NewSearchService())

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
		image := CreateRandomImage()

		err := UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		ref1 := CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		// get referrers by digest
		args := []string{"subject", repo + "@" + image.DigestStr(), "--config", "reftest"}

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))

		cmd := client.NewSearchCommand(client.NewSearchService())

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

		args = []string{"subject", repo + ":" + "tag", "--config", "reftest"}

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))

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
		image := CreateRandomImage()

		err := UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		// add referrers
		ref1 := CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		Convey("JSON format", func() {
			args := []string{"subject", repo + "@" + image.DigestStr(), "--format", "json", "--config", "reftest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			cmd := client.NewSearchCommand(client.NewSearchService())

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

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			cmd := client.NewSearchCommand(client.NewSearchService())

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

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			cmd := client.NewSearchCommand(client.NewSearchService())

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
		cmd := client.NewSearchCommand(client.NewSearchService())

		Convey("no url provided", func() {
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "reftest"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"reftest","showspinner":false}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("getConfigValue", func() {
			args := []string{"subject", "repo/alpine", "--config", "reftest"}

			_ = makeConfigFile(t, `bad-json`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad showspinnerConfig ", func() {
			args := []string{"query", "repo", "--config", "reftest"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":"bad"}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad verifyTLSConfig ", func() {
			args := []string{"query", "repo", "reftest"}

			_ = makeConfigFile(t,
				`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":false, "verify-tls": "bad"}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("url from config is empty", func() {
			args := []string{"subject", "repo/alpine", "--config", "reftest"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"reftest", "url":"", "showspinner":false}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad params combination", func() {
			args := []string{"query", "repo", "reftest"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":false}]}`)

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

		image1 := CreateImageWith().
			RandomLayers(1, 10).
			ImageConfig(ispec.Image{
				Created:  DefaultTimeRef(),
				Platform: ispec.Platform{OS: "Os", Architecture: "Arch"},
			}).
			Build()
		formatterDigest1 := image1.Digest().Encoded()[:8]

		image2 := CreateImageWith().
			RandomLayers(1, 10).
			DefaultConfig().
			Build()
		formatterDigest2 := image2.Digest().Encoded()[:8]

		err := UploadImage(image1, baseURL, repo1, r1tag1)
		So(err, ShouldBeNil)
		err = UploadImage(image2, baseURL, repo1, r1tag2)
		So(err, ShouldBeNil)

		err = UploadImage(image1, baseURL, repo2, r2tag1)
		So(err, ShouldBeNil)
		err = UploadImage(image2, baseURL, repo2, r2tag2)
		So(err, ShouldBeNil)

		err = UploadImage(image1, baseURL, repo3, r3tag1)
		So(err, ShouldBeNil)
		err = UploadImage(image2, baseURL, repo3, r3tag2)
		So(err, ShouldBeNil)

		// search by repos

		args := []string{"query", "test/alpin", "--verbose", "--config", "searchtest"}

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))

		cmd := client.NewSearchCommand(client.NewSearchService())

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "NAME SIZE LAST UPDATED DOWNLOADS STARS PLATFORMS")
		So(str, ShouldContainSubstring, "repo/test/alpine 1.1kB")
		So(str, ShouldContainSubstring, "+0000 UTC 0 0")
		So(str, ShouldContainSubstring, "Os/Arch")
		So(str, ShouldContainSubstring, "linux/amd64")

		fmt.Println("\n", buff.String())

		cmd = client.NewSearchCommand(client.NewSearchService())

		args = []string{"query", "repo/alpine:", "--config", "searchtest"}

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))

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

		image1 := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()
		image2 := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

		err := UploadImage(image1, baseURL, repo1, r1tag1)
		So(err, ShouldBeNil)
		err = UploadImage(image2, baseURL, repo1, r1tag2)
		So(err, ShouldBeNil)

		err = UploadImage(image1, baseURL, repo2, r2tag1)
		So(err, ShouldBeNil)
		err = UploadImage(image2, baseURL, repo2, r2tag2)
		So(err, ShouldBeNil)

		err = UploadImage(image1, baseURL, repo3, r3tag1)
		So(err, ShouldBeNil)
		err = UploadImage(image2, baseURL, repo3, r3tag2)
		So(err, ShouldBeNil)

		cmd := client.NewSearchCommand(client.NewSearchService())

		Convey("JSON format", func() {
			args := []string{"query", "repo/alpine", "--format", "json", "--config", "searchtest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
				baseURL))

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

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
				baseURL))

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

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
				baseURL))

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
		cmd := client.NewSearchCommand(client.NewSearchService())

		Convey("no url provided", func() {
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"searchtest","showspinner":false}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("getConfigValue", func() {
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

			_ = makeConfigFile(t, `bad-json`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad showspinnerConfig ", func() {
			args := []string{"query", "repo/alpine", "--config", "searchtest"}

			_ = makeConfigFile(t,
				`{"configs":[{"_name":"searchtest", "url":"http://127.0.0.1:8080", "showspinner":"bad"}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad verifyTLSConfig ", func() {
			args := []string{"query", "repo/alpine", "--config", "searchtest"}

			_ = makeConfigFile(t,
				`{"configs":[{"_name":"searchtest", "url":"http://127.0.0.1:8080", "showspinner":false, "verify-tls": "bad"}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("url from config is empty", func() {
			args := []string{"query", "repo/alpine", "--format", "invalid", "--config", "searchtest"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"searchtest", "url":"", "showspinner":false}]}`)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestSearchSort(t *testing.T) {
	rootDir := t.TempDir()
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        nil,
		},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = rootDir

	image1 := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2010, 1, 1, 1, 1, 1, 0, time.UTC)}).
		Build()

	image2 := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2020, 1, 1, 1, 1, 1, 0, time.UTC)}).
		Build()

	storeController := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)

	err := WriteImageToFileSystem(image1, "b-repo", "tag2", storeController)
	if err != nil {
		t.FailNow()
	}

	err = WriteImageToFileSystem(image2, "a-test-repo", "tag2", storeController)
	if err != nil {
		t.FailNow()
	}

	cm := test.NewControllerManager(ctlr)
	cm.StartAndWait(conf.HTTP.Port)

	defer cm.StopServer()

	Convey("test sorting", t, func() {
		args := []string{"query", "repo", "--sort-by", "relevance", "--url", baseURL}
		cmd := client.NewSearchCommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		str := buff.String()
		So(strings.Index(str, "b-repo"), ShouldBeLessThan, strings.Index(str, "a-test-repo"))

		args = []string{"query", "repo", "--sort-by", "alpha-asc", "--url", baseURL}
		cmd = client.NewSearchCommand(client.NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = buff.String()
		So(strings.Index(str, "a-test-repo"), ShouldBeLessThan, strings.Index(str, "b-repo"))
	})
}
