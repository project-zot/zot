//go:build search

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestSearchImageCmd(t *testing.T) {
	Convey("Test image help", t, func() {
		args := []string{"--help"}

		_ = makeConfigFile(t, "")

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()

		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)

		Convey("with the shorthand", func() {
			args[0] = "-h"

			_ = makeConfigFile(t, "")

			cmd := NewImageCommand(newMockService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()

			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test image no url", t, func() {
		args := []string{"name", "dummyIdRandom", "--config", "imagetest"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrNoURLProvided), ShouldBeTrue)
	})

	Convey("Test image invalid home directory", t, func() {
		args := []string{"name", "dummyImageName", "--config", "imagetest"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)

		err := os.Setenv("HOME", "nonExistentDirectory")
		if err != nil {
			panic(err)
		}

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		err = os.Setenv("HOME", home)
		if err != nil {
			log.Fatal(err)
		}
	})

	Convey("Test image no params", t, func() {
		args := []string{"--url", "someUrl"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test image invalid url", t, func() {
		args := []string{"name", "dummyImageName", "--url", "invalidUrl"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

		cmd := NewImageCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(strings.Contains(err.Error(), zerr.ErrInvalidURL.Error()), ShouldBeTrue)
		So(buff.String(), ShouldContainSubstring, "invalid URL format")
	})

	Convey("Test image invalid url port", t, func() {
		args := []string{"name", "dummyImageName", "--url", "http://localhost:99999"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

		cmd := NewImageCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid port")

		Convey("without flags", func() {
			args := []string{"list", "--url", "http://localhost:99999"}

			_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
			So(buff.String(), ShouldContainSubstring, "invalid port")
		})
	})

	Convey("Test image unreachable", t, func() {
		args := []string{"name", "dummyImageName", "--url", "http://localhost:9999"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

		cmd := NewImageCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image url from config", t, func() {
		args := []string{"name", "dummyImageName", "--config", "imagetest"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test image by name", t, func() {
		args := []string{"name", "dummyImageName", "--url", "http://127.0.0.1:8080"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","showspinner":false}]}`)

		imageCmd := NewImageCommand(newMockService())
		buff := &bytes.Buffer{}
		imageCmd.SetOut(buff)
		imageCmd.SetErr(buff)
		imageCmd.SetArgs(args)
		err := imageCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test image by digest", t, func() {
		searchConfig := getTestSearchConfig("http://127.0.0.1:8080", newMockService())
		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err := SearchImagesByDigest(searchConfig, "6e2f80bf")
		So(err, ShouldBeNil)

		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE anImage tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})
}

func TestListRepos(t *testing.T) {
	searchConfig := getTestSearchConfig("https://test-url.com", newMockService())

	Convey("Test listing repositories", t, func() {
		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err := SearchRepos(searchConfig)
		So(err, ShouldBeNil)
	})

	Convey("Test listing repositories with debug flag", t, func() {
		args := []string{"list", "--config", "config-test", "--debug"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewRepoCommand(NewSearchService())

		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "GET")
	})

	Convey("Test error on home directory", t, func() {
		args := []string{"list", "--config", "config-test"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)

		err := os.Setenv("HOME", "nonExistentDirectory")
		if err != nil {
			panic(err)
		}

		cmd := NewRepoCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		err = os.Setenv("HOME", home)
		if err != nil {
			log.Fatal(err)
		}
	})

	Convey("Test listing repositories error", t, func() {
		args := []string{"list", "--config", "config-test"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test",
        	"url":"https://invalid.invalid","showspinner":false}]}`)

		cmd := NewRepoCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test unable to get config value", t, func() {
		args := []string{"list", "--config", "config-test-nonexistent"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewRepoCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - no url provided", t, func() {
		args := []string{"list", "--config", "config-test"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test","url":"","showspinner":false}]}`)

		cmd := NewRepoCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - spinner config invalid", t, func() {
		args := []string{"list", "--config", "config-test"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test",
       		"url":"https://test-url.com","showspinner":invalid}]}`)

		cmd := NewRepoCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - verifyTLSConfig fails", t, func() {
		args := []string{"list", "--config", "config-test"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"config-test",
        	"verify-tls":"invalid", "url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewRepoCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestOutputFormat(t *testing.T) {
	Convey("Test text", t, func() {
		args := []string{"name", "dummyImageName", "--config", "imagetest", "-f", "text"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test json", t, func() {
		args := []string{"name", "dummyImageName", "--config", "imagetest", "-f", "json"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		// Output is supposed to be in json lines format, keep all spaces as is for verification
		So(buff.String(), ShouldEqual, `{"repoName":"dummyImageName","tag":"tag",`+
			`"digest":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",`+
			`"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
			`"manifests":[{"digest":"sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6",`+
			`"configDigest":"sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0",`+
			`"lastUpdated":"0001-01-01T00:00:00Z","size":"123445","platform":{"os":"os","arch":"arch",`+
			`"variant":""},"isSigned":false,"downloadCount":0,`+
			`"layers":[{"size":"","digest":"sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6",`+
			`"score":0}],"history":null,"vulnerabilities":{"maxSeverity":"","unknownCount":0,"lowCount":0,`+
			`"mediumCount":0,"highCount":0,"criticalCount":0,"count":0},`+
			`"referrers":null,"artifactType":"","signatureInfo":null}],"size":"123445",`+
			`"downloadCount":0,"lastUpdated":"0001-01-01T00:00:00Z","lastPullTimestamp":"0001-01-01T00:00:00Z",`+
			`"pushTimestamp":"0001-01-01T00:00:00Z","taggedTimestamp":"0001-01-01T00:00:00Z","description":"","isSigned":false,"licenses":"",`+
			`"labels":"","title":"","source":"","documentation":"","authors":"","vendor":"",`+
			`"vulnerabilities":{"maxSeverity":"","unknownCount":0,"lowCount":0,"mediumCount":0,"highCount":0,`+
			`"criticalCount":0,"count":0},"referrers":null,"signatureInfo":null}`+"\n")
		So(err, ShouldBeNil)
	})

	Convey("Test yaml", t, func() {
		args := []string{"name", "dummyImageName", "--config", "imagetest", "-f", "yaml"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(
			strings.TrimSpace(str),
			ShouldEqual,
			`--- reponame: dummyImageName tag: tag `+
				`digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 `+
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - `+
				`digest: sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6 `+
				`configdigest: sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0 `+
				`lastupdated: 0001-01-01T00:00:00Z size: "123445" platform: os: os arch: arch variant: "" `+
				`issigned: false downloadcount: 0 layers: - size: "" `+
				`digest: sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6 score: 0 `+
				`history: [] vulnerabilities: maxseverity: "" `+
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 `+
				`referrers: [] artifacttype: "" `+
				`signatureinfo: [] size: "123445" downloadcount: 0 `+
				`lastupdated: 0001-01-01T00:00:00Z lastpulltimestamp: 0001-01-01T00:00:00Z `+
				`pushtimestamp: 0001-01-01T00:00:00Z taggedtimestamp: 0001-01-01T00:00:00Z `+
				`description: "" issigned: false licenses: "" labels: "" `+
				`title: "" source: "" documentation: "" authors: "" vendor: "" vulnerabilities: maxseverity: "" `+
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 `+
				`count: 0 referrers: [] signatureinfo: []`,
		)
		So(err, ShouldBeNil)

		Convey("Test yml", func() {
			args := []string{"name", "dummyImageName", "--config", "imagetest", "-f", "yml"}

			_ = makeConfigFile(t,
				`{"configs":[{"_name":"imagetest",`+
					`"url":"https://test-url.com","showspinner":false}]}`,
			)

			cmd := NewImageCommand(newMockService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			So(
				strings.TrimSpace(str),
				ShouldEqual,
				`--- reponame: dummyImageName tag: tag `+
					`digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 `+
					`mediatype: application/vnd.oci.image.manifest.v1+json `+
					`manifests: - digest: sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6 `+
					`configdigest: sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0 `+
					`lastupdated: 0001-01-01T00:00:00Z size: "123445" platform: os: os arch: arch variant: "" `+
					`issigned: false downloadcount: 0 layers: - size: "" `+
					`digest: sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6 score: 0 `+
					`history: [] vulnerabilities: maxseverity: "" unknowncount: 0 lowcount: 0 mediumcount: 0 `+
					`highcount: 0 criticalcount: 0 count: 0 referrers: [] artifacttype: "" `+
					`signatureinfo: [] size: "123445" downloadcount: 0 `+
					`lastupdated: 0001-01-01T00:00:00Z lastpulltimestamp: 0001-01-01T00:00:00Z `+
					`pushtimestamp: 0001-01-01T00:00:00Z taggedtimestamp: 0001-01-01T00:00:00Z `+
					`description: "" issigned: false licenses: "" labels: "" `+
					`title: "" source: "" documentation: "" authors: "" vendor: "" vulnerabilities: maxseverity: "" `+
					`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 `+
					`count: 0 referrers: [] signatureinfo: []`,
			)
			So(err, ShouldBeNil)
		})
	})

	Convey("Test invalid", t, func() {
		args := []string{"name", "dummyImageName", "--config", "imagetest", "-f", "random"}

		_ = makeConfigFile(t, `{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)

		cmd := NewImageCommand(newMockService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid cli output format")
	})
}

func TestImagesCommandGQL(t *testing.T) {
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

	Convey("commands with gql", t, func() {
		err := removeLocalStorageContents(ctlr.StoreController.DefaultStore)
		So(err, ShouldBeNil)

		Convey("base and derived command", func() {
			baseImage := CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}},
			).DefaultConfig().Build()

			derivedImage := CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}, {44, 55, 66}},
			).DefaultConfig().Build()

			err := UploadImage(baseImage, baseURL, "repo", "base")
			So(err, ShouldBeNil)

			err = UploadImage(derivedImage, baseURL, "repo", "derived")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"base", "repo:derived", "--config", "imagetest"}

			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "repo base linux/amd64 df554ddd false 699B")
			args = []string{"derived", "repo:base", "--config", "imagetest"}

			cmd = NewImageCommand(NewSearchService())
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "repo derived linux/amd64 79f4b82e false 854B")
		})

		Convey("base and derived command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"too", "many", "args", "--config", "imagetest"}
			cmd := NewImageBaseCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			cmd = NewImageDerivedCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad input
			buff = bytes.NewBufferString("")
			args = []string{"only-repo"}
			cmd = NewImageBaseCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			cmd = NewImageDerivedCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{"repo:tag"}
			cmd = NewImageBaseCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			cmd = NewImageDerivedCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("digest command", func() {
			image := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"digest", image.DigestStr(), "--config", "imagetest"}

			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, fmt.Sprintf("repo img linux/amd64 %s false 552B",
				image.DigestStr()[7:7+8]))
		})

		Convey("digest command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"too", "many", "args", "--config", "imagetest"}
			cmd := NewImageDigestCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad input
			buff = bytes.NewBufferString("")
			args = []string{"bad-digest"}
			cmd = NewImageDigestCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{godigest.FromString("str").String()}
			cmd = NewImageDigestCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("list command", func() {
			image := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"list", "--config", "imagetest"}

			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			fmt.Println(actual)
			So(actual, ShouldContainSubstring, fmt.Sprintf("repo img linux/amd64 %s false 552B",
				image.DigestStr()[7:7+8]))
			fmt.Println(actual)
		})

		Convey("list command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"repo:img", "arg", "--config", "imagetest"}
			cmd := NewImageListCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{}
			cmd = NewImageListCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("name command", func() {
			image := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			err = UploadImage(CreateRandomImage(), baseURL, "repo", "img2")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"name", "repo:img", "--config", "imagetest"}

			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			fmt.Println(actual)
			So(actual, ShouldContainSubstring, fmt.Sprintf("repo img linux/amd64 %s false 552B",
				image.DigestStr()[7:7+8]))
			fmt.Println(actual)
		})

		Convey("name command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"repo:img", "arg", "--config", "imagetest"}
			cmd := NewImageNameCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad input
			buff = bytes.NewBufferString("")
			args = []string{":tag"}
			cmd = NewImageNameCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{"repo:tag"}
			cmd = NewImageNameCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("CVE", func() {
			vulnImage := CreateDefaultVulnerableImage()
			err := UploadImage(vulnImage, baseURL, "repo", "vuln")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"cve", "repo:vuln", "--config", "imagetest"}
			cmd := NewImageCommand(newMockService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 1")
			So(actual, ShouldContainSubstring, "dummyCVEID HIGH Title of that CVE")
		})

		Convey("CVE errors", func() {
			count := 0

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))

			args := []string{"cve", "repo:vuln", "--config", "imagetest"}
			cmd := NewImageCommand(&mockService{
				httpClient: NewHTTPClient(),
				getCveByImageGQLFn: func(ctx context.Context, config SearchConfig, username, password,
					imageName, searchedCVE string) (*cveResult, error,
				) {
					if count == 0 {
						count++
						fmt.Println("Count:", count)

						return &cveResult{}, zerr.ErrCVEDBNotFound
					}

					return &cveResult{}, zerr.ErrInjected
				},
			})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "[warning] CVE DB is not ready")
		})
	})

	Convey("Config error", t, func() {
		// Create config file with a different config name to test error when config doesn't exist
		_ = makeConfigFile(t, `{"configs":[{"_name":"other-config","url":"https://test-url.com","showspinner":false}]}`)
		args := []string{"base", "repo:derived", "--config", "imagetest"}
		cmd := NewImageCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldNotBeNil)

		args = []string{"derived", "repo:base"}
		cmd = NewImageCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"digest", ispec.DescriptorEmptyJSON.Digest.String()}
		cmd = NewImageCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"list"}
		cmd = NewImageCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"name", "repo:img"}
		cmd = NewImageCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"cve", "repo:vuln"}
		cmd = NewImageCommand(newMockService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestImageCommandREST(t *testing.T) {
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
		err := removeLocalStorageContents(ctlr.StoreController.DefaultStore)
		So(err, ShouldBeNil)

		Convey("base and derived command", func() {
			baseImage := CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}},
			).DefaultConfig().Build()

			derivedImage := CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}, {44, 55, 66}},
			).DefaultConfig().Build()

			err := UploadImage(baseImage, baseURL, "repo", "base")
			So(err, ShouldBeNil)

			err = UploadImage(derivedImage, baseURL, "repo", "derived")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"base", "repo:derived", "--config", "imagetest"}
			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			args = []string{"derived", "repo:base"}
			cmd = NewImageCommand(NewSearchService())
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("digest command", func() {
			image := CreateRandomImage()

			err := UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"digest", image.DigestStr(), "--config", "imagetest"}
			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("list command", func() {
			image := CreateRandomImage()

			err := UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"list", "--config", "imagetest"}
			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
			fmt.Println()
		})

		Convey("name command", func() {
			image := CreateRandomImage()

			err := UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			err = UploadImage(CreateRandomImage(), baseURL, "repo", "img2")
			So(err, ShouldBeNil)

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"name", "repo:img", "--config", "imagetest"}
			cmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
			fmt.Println()
		})

		Convey("CVE", func() {
			vulnImage := CreateDefaultVulnerableImage()
			err := UploadImage(vulnImage, baseURL, "repo", "vuln")
			So(err, ShouldBeNil)
			args := []string{"cve", "repo:vuln", "--config", "imagetest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))

			cmd := NewImageCommand(newMockService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

type mockService struct {
	getAllImagesFn func(ctx context.Context, config SearchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)

	getImagesGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		imageName string) (*common.ImageListResponse, error)

	getImageByNameFn func(ctx context.Context, config SearchConfig,
		username, password, imageName string, channel chan stringResult, wtgrp *sync.WaitGroup,
	)

	getImagesByDigestFn func(ctx context.Context, config SearchConfig, username,
		password, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
	)

	getReferrersFn func(ctx context.Context, config SearchConfig, username, password string,
		repo, digest string,
	) (referrersResult, error)

	globalSearchGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		query string,
	) (*common.GlobalSearch, error)

	getReferrersGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		repo, digest string,
	) (*common.ReferrersResp, error)

	getDerivedImageListGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		derivedImage string,
	) (*common.DerivedImageListResponse, error)

	getBaseImageListGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		derivedImage string,
	) (*common.BaseImageListResponse, error)

	getImagesForDigestGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		digest string,
	) (*common.ImagesForDigest, error)

	getCveByImageGQLFn func(ctx context.Context, config SearchConfig, username, password,
		imageName, searchedCVE string,
	) (*cveResult, error)

	getTagsForCVEGQLFn func(ctx context.Context, config SearchConfig, username, password,
		imageName, cveID string,
	) (*common.ImagesForCve, error)

	getFixedTagsForCVEGQLFn func(ctx context.Context, config SearchConfig, username, password,
		imageName, cveID string,
	) (*common.ImageListWithCVEFixedResponse, error)

	getCVEDiffListGQLFn func(ctx context.Context, config SearchConfig, username, password string,
		minuend, subtrahend ImageIdentifier,
	) (*cveDiffListResp, error)

	httpClient *HTTPClient
}

// newMockService creates a new mockService with httpClient initialized.
func newMockService() *mockService {
	return &mockService{
		httpClient: NewHTTPClient(),
	}
}

func (service *mockService) getHTTPClient() *HTTPClient {
	return service.httpClient
}

func (service *mockService) getCVEDiffListGQL(ctx context.Context, config SearchConfig, username, password string,
	minuend, subtrahend ImageIdentifier,
) (*cveDiffListResp, error) {
	if service.getCVEDiffListGQLFn != nil {
		return service.getCVEDiffListGQLFn(ctx, config, username, password, minuend, subtrahend)
	}

	return &cveDiffListResp{}, nil
}

func (service *mockService) getRepos(ctx context.Context, config SearchConfig, username,
	password string, channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	fmt.Fprintln(config.ResultWriter, "\n\nREPOSITORY NAME")

	fmt.Fprintln(config.ResultWriter, "repo1")
	fmt.Fprintln(config.ResultWriter, "repo2")
}

func (service *mockService) getReferrers(ctx context.Context, config SearchConfig, username, password string,
	repo, digest string,
) (referrersResult, error) {
	if service.getReferrersFn != nil {
		return service.getReferrersFn(ctx, config, username, password, repo, digest)
	}

	return referrersResult{
		common.Referrer{
			ArtifactType: "art.type",
			Digest:       ispec.DescriptorEmptyJSON.Digest.String(),
			MediaType:    ispec.MediaTypeImageManifest,
			Size:         100,
		},
	}, nil
}

func (service *mockService) globalSearchGQL(ctx context.Context, config SearchConfig, username, password string,
	query string,
) (*common.GlobalSearch, error) {
	if service.globalSearchGQLFn != nil {
		return service.globalSearchGQLFn(ctx, config, username, password, query)
	}

	return &common.GlobalSearch{
		Images: []common.ImageSummary{
			{
				RepoName:  "repo",
				MediaType: ispec.MediaTypeImageManifest,
				Size:      "100",
				Manifests: []common.ManifestSummary{
					{
						Digest:       godigest.FromString("str").String(),
						Size:         "100",
						ConfigDigest: ispec.DescriptorEmptyJSON.Digest.String(),
					},
				},
			},
		},
		Repos: []common.RepoSummary{
			{
				Name:        "repo",
				Size:        "100",
				LastUpdated: time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC),
			},
		},
	}, nil
}

func (service *mockService) getReferrersGQL(ctx context.Context, config SearchConfig, username, password string,
	repo, digest string,
) (*common.ReferrersResp, error) {
	if service.getReferrersGQLFn != nil {
		return service.getReferrersGQLFn(ctx, config, username, password, repo, digest)
	}

	return &common.ReferrersResp{
		ReferrersResult: common.ReferrersResult{
			Referrers: []common.Referrer{
				{
					MediaType:    "MediaType",
					ArtifactType: "ArtifactType",
					Size:         100,
					Digest:       "Digest",
				},
			},
		},
	}, nil
}

func (service *mockService) getDerivedImageListGQL(ctx context.Context, config SearchConfig, username, password string,
	derivedImage string,
) (*common.DerivedImageListResponse, error) {
	if service.getDerivedImageListGQLFn != nil {
		return service.getDerivedImageListGQLFn(ctx, config, username, password, derivedImage)
	}

	imageListGQLResponse := &common.DerivedImageListResponse{}
	imageListGQLResponse.DerivedImageList.Results = []common.ImageSummary{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Size:         "123445",
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
					Platform:     common.Platform{Os: "os", Arch: "arch"},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service *mockService) getBaseImageListGQL(ctx context.Context, config SearchConfig, username, password string,
	baseImage string,
) (*common.BaseImageListResponse, error) {
	if service.getBaseImageListGQLFn != nil {
		return service.getBaseImageListGQLFn(ctx, config, username, password, baseImage)
	}

	imageListGQLResponse := &common.BaseImageListResponse{}
	imageListGQLResponse.BaseImageList.Results = []common.ImageSummary{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Size:         "123445",
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
					Platform:     common.Platform{Os: "os", Arch: "arch"},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service *mockService) getImagesGQL(ctx context.Context, config SearchConfig, username, password string,
	imageName string,
) (*common.ImageListResponse, error) {
	if service.getImagesGQLFn != nil {
		return service.getImagesGQLFn(ctx, config, username, password, imageName)
	}

	imageListGQLResponse := &common.ImageListResponse{}
	imageListGQLResponse.PaginatedImagesResult.Results = []common.ImageSummary{
		{
			RepoName:  "dummyImageName",
			Tag:       "tag",
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    godigest.FromString("test").String(),
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Size:         "123445",
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
					Platform:     common.Platform{Os: "os", Arch: "arch"},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service *mockService) getImagesForDigestGQL(ctx context.Context, config SearchConfig, username, password string,
	digest string,
) (*common.ImagesForDigest, error) {
	if service.getImagesForDigestGQLFn != nil {
		return service.getImagesForDigestGQLFn(ctx, config, username, password, digest)
	}

	imageListGQLResponse := &common.ImagesForDigest{}
	imageListGQLResponse.Results = []common.ImageSummary{
		{
			RepoName:  "randomimageName",
			Tag:       "tag",
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    godigest.FromString("test").String(),
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
					Size:         "123445",
					Platform:     common.Platform{Os: "os", Arch: "arch"},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service *mockService) getTagsForCVEGQL(ctx context.Context, config SearchConfig, username, password,
	imageName, cveID string,
) (*common.ImagesForCve, error) {
	if service.getTagsForCVEGQLFn != nil {
		return service.getTagsForCVEGQLFn(ctx, config, username, password, imageName, cveID)
	}

	images := &common.ImagesForCve{
		Errors: nil,
		ImagesForCVEList: struct {
			common.PaginatedImagesResult `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
		}{},
	}

	if imageName == "" {
		imageName = "image-name"
	}

	images.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	images.Results = []common.ImageSummary{common.ImageSummary(mockedImage)}

	return images, nil
}

func (service *mockService) getFixedTagsForCVEGQL(ctx context.Context, config SearchConfig, username, password,
	imageName, cveID string,
) (*common.ImageListWithCVEFixedResponse, error) {
	if service.getFixedTagsForCVEGQLFn != nil {
		return service.getFixedTagsForCVEGQLFn(ctx, config, username, password, imageName, cveID)
	}

	fixedTags := &common.ImageListWithCVEFixedResponse{
		Errors: nil,
		ImageListWithCVEFixed: struct {
			common.PaginatedImagesResult `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
		}{},
	}

	fixedTags.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	fixedTags.Results = []common.ImageSummary{common.ImageSummary(mockedImage)}

	return fixedTags, nil
}

func (service *mockService) getCveByImageGQL(ctx context.Context, config SearchConfig, username, password,
	imageName, searchedCVE string,
) (*cveResult, error) {
	if service.getCveByImageGQLFn != nil {
		return service.getCveByImageGQLFn(ctx, config, username, password, imageName, searchedCVE)
	}
	cveRes := &cveResult{}
	cveRes.Data = cveData{
		CVEListForImage: cveListForImage{
			Tag: imageName,
			CVEList: []cve{
				{
					ID:          "dummyCVEID",
					Description: "Description of the CVE",
					Title:       "Title of that CVE",
					Severity:    "HIGH",
					PackageList: []packageList{
						{
							Name:             "packagename",
							FixedVersion:     "fixedver",
							InstalledVersion: "installedver",
						},
					},
				},
			},
			Summary: common.ImageVulnerabilitySummary{
				Count:         1,
				UnknownCount:  0,
				LowCount:      0,
				MediumCount:   0,
				HighCount:     1,
				CriticalCount: 0,
				MaxSeverity:   "HIGH",
			},
		},
	}

	return cveRes, nil
}

//nolint:goconst
func (service mockService) getMockedImageByName(imageName string) imageStruct {
	image := imageStruct{}
	image.RepoName = imageName
	image.Tag = "tag"
	image.MediaType = ispec.MediaTypeImageManifest
	image.Manifests = []common.ManifestSummary{
		{
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
			Size:         "123445",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
		},
	}
	image.Size = "123445"

	return image
}

func (service *mockService) getAllImages(ctx context.Context, config SearchConfig, username, password string,
	channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	if service.getAllImagesFn != nil {
		service.getAllImagesFn(ctx, config, username, password, channel, wtgrp)

		return
	}

	image := &imageStruct{}
	image.RepoName = "randomimageName"
	image.Tag = "tag"
	image.Digest = godigest.FromString("test").String()
	image.MediaType = ispec.MediaTypeImageManifest
	image.Manifests = []common.ManifestSummary{
		{
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
			Size:         "123445",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
		},
	}
	image.Size = "123445"

	str, err := image.string(config.OutputFormat, len(image.RepoName), len(image.Tag), len("os/Arch"), config.Verbose)
	if err != nil {
		channel <- stringResult{"", err}

		return
	}

	channel <- stringResult{str, nil}
}

func (service *mockService) getImageByName(ctx context.Context, config SearchConfig,
	username, password, imageName string, channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	if service.getImageByNameFn != nil {
		service.getImageByNameFn(ctx, config, username, password, imageName, channel, wtgrp)

		return
	}

	image := &imageStruct{}
	image.RepoName = imageName
	image.Tag = "tag"
	image.Digest = godigest.FromString("test").String()
	image.MediaType = ispec.MediaTypeImageManifest
	image.Manifests = []common.ManifestSummary{
		{
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
			Size:         "123445",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
		},
	}
	image.Size = "123445"

	str, err := image.string(config.OutputFormat, len(image.RepoName), len(image.Tag), len("os/Arch"), config.Verbose)
	if err != nil {
		channel <- stringResult{"", err}

		return
	}

	channel <- stringResult{str, nil}
}

func (service *mockService) getImagesByDigest(ctx context.Context, config SearchConfig, username,
	password, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	if service.getImagesByDigestFn != nil {
		defer wtgrp.Done()
		defer close(rch)

		service.getImagesByDigestFn(ctx, config, username, password, digest, rch, wtgrp)

		return
	}

	service.getImageByName(ctx, config, username, password, "anImage", rch, wtgrp)
}

func makeConfigFile(t *testing.T, content string) string {
	tempDir := t.TempDir()
	os.Setenv("HOME", tempDir)

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	configPath := path.Join(home, "/.zot")

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		panic(err)
	}

	return configPath
}

func getTestSearchConfig(url string, searchService SearchService) SearchConfig {
	var (
		user         string
		outputFormat string
		verbose      bool
		debug        bool
		verifyTLS    bool
	)

	return SearchConfig{
		SearchService: searchService,
		SortBy:        "alpha-asc",
		ServURL:       url,
		User:          user,
		OutputFormat:  outputFormat,
		Verbose:       verbose,
		Debug:         debug,
		VerifyTLS:     verifyTLS,
		ResultWriter:  nil,
	}
}

func removeLocalStorageContents(imageStore stypes.ImageStore) error {
	repos, err := imageStore.GetRepositories()
	if err != nil {
		return err
	}

	for _, repo := range repos {
		// take just the first path
		err = os.RemoveAll(filepath.Join(imageStore.RootDir(), filepath.SplitList(repo)[0]))
		if err != nil {
			return err
		}
	}

	return nil
}
