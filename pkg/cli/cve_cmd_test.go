//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/cobra"

	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

func TestSearchCVECmd(t *testing.T) {
	Convey("Test CVE help", t, func() {
		args := []string{"--help"}
		configPath := makeConfigFile("")
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
	})

	Convey("Test CVE help - with the shorthand", t, func() {
		args := []string{"-h"}
		configPath := makeConfigFile("")
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
	})

	Convey("Test CVE no url", t, func() {
		args := []string{"cvetest", "-i", "cveIdRandom"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zotErrors.ErrNoURLProvided)
	})

	Convey("Test CVE no params", t, func() {
		args := []string{"cvetest", "--url", "someUrl"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldEqual, zotErrors.ErrInvalidFlagsCombination)
	})

	Convey("Test CVE invalid url", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "invalidUrl"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
		So(buff.String(), ShouldContainSubstring, "invalid URL format")
	})

	Convey("Test CVE invalid url port", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "http://localhost:99999"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid port")
	})

	Convey("Test CVE unreachable", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "http://localhost:9999"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE url from config", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "ID SEVERITY TITLE dummyCVEID HIGH Title of that CVE")
		So(err, ShouldBeNil)
	})

	Convey("Test debug flag", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--debug"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldContainSubstring, "GET")
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by name and CVE ID - long option", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName", "--cve-id", "aCVEID", "--url", "someURL"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag 6e2f80bf false 123kB")
	})

	Convey("Test CVE by name and CVE ID - using shorthand", t, func() {
		args := []string{"cvetest", "-I", "dummyImageName", "--cve-id", "aCVEID", "--url", "someURL"}
		buff := bytes.NewBufferString("")
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag 6e2f80bf false 123kB")
	})

	Convey("Test CVE by image name - in text format", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "someURL"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "ID SEVERITY TITLE dummyCVEID HIGH Title of that CVE")
		So(err, ShouldBeNil)
	})

	Convey("Test CVE by image name - in json format", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "someURL", "-o", "json"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, `{ "Tag": "dummyImageName:tag", "CVEList": `+
			`[ { "Id": "dummyCVEID", "Severity": "HIGH", "Title": "Title of that CVE", `+
			`"Description": "Description of the CVE", "PackageList": [ { "Name": "packagename",`+
			` "InstalledVersion": "installedver", "FixedVersion": "fixedver" } ] } ] }`)
		So(err, ShouldBeNil)
	})

	Convey("Test CVE by image name - in yaml format", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "someURL", "-o", "yaml"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, `tag: dummyImageName:tag cvelist: - id: dummyCVEID`+
			` severity: HIGH title: Title of that CVE description: Description of the CVE packagelist: `+
			`- name: packagename installedversion: installedver fixedversion: fixedver`)
		So(err, ShouldBeNil)
	})
	Convey("Test CVE by image name - invalid format", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "someURL", "-o", "random"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldEqual, "Error: invalid output format")
	})

	Convey("Test images by CVE ID - positive", t, func() {
		args := []string{"cvetest", "--cve-id", "aCVEID", "--url", "someURL"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE anImage tag 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test images by CVE ID - invalid CVE ID", t, func() {
		args := []string{"cvetest", "--cve-id", "invalidCVEID"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test images by CVE ID - invalid url", t, func() {
		args := []string{"cvetest", "--cve-id", "aCVEID", "--url", "invalidURL"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
		So(buff.String(), ShouldContainSubstring, "invalid URL format")
	})

	Convey("Test fixed tags by and image name CVE ID - positive", t, func() {
		args := []string{"cvetest", "--cve-id", "aCVEID", "--image", "fixedImage", "--url", "someURL", "--fixed"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE fixedImage tag 6e2f80bf false 123kB")
	})

	Convey("Test fixed tags by and image name CVE ID - invalid image name", t, func() {
		args := []string{"cvetest", "--cve-id", "aCVEID", "--image", "invalidImageName"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestNegativeServerResponse(t *testing.T) {
	Convey("Test from real server without search endpoint", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		test.CopyTestFiles("../../test/data/zot-cve-test", path.Join(dir, "zot-cve-test"))

		conf.Storage.RootDirectory = dir
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: 2,
			Trivy:          trivyConfig,
		}
		defaultVal := false
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		_, err = test.ReadLogFileAndSearchString(logPath, "CVE config not provided, skipping CVE update", 90*time.Second)
		if err != nil {
			panic(err)
		}

		Convey("Status Code Not Found", func() {
			args := []string{"cvetest", "--image", "zot-cve-test:0.0.1"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cveCmd := NewCveCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cveCmd.SetOut(buff)
			cveCmd.SetErr(buff)
			cveCmd.SetArgs(args)
			err = cveCmd.Execute()
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			str = strings.TrimSpace(str)
			So(err, ShouldNotBeNil)
			So(str, ShouldContainSubstring, "404 page not found")
		})
	})

	Convey("Test non-existing manifest blob", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		test.CopyTestFiles("../../test/data/zot-cve-test", path.Join(dir, "zot-cve-test"))

		err := os.RemoveAll(path.Join(dir, "zot-cve-test/blobs"))
		if err != nil {
			panic(err)
		}

		conf.Storage.RootDirectory = dir
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: 2,
			Trivy:          trivyConfig,
		}
		defaultVal := true
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctx := context.Background()

		if err := ctlr.Init(ctx); err != nil {
			panic(err)
		}

		ctlr.CveInfo = getMockCveInfo(ctlr.RepoDB, ctlr.Log)

		go func() {
			if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		test.WaitTillServerReady(url)

		_, err = test.ReadLogFileAndSearchString(logPath, "DB update completed, next update scheduled", 90*time.Second)
		if err != nil {
			panic(err)
		}

		args := []string{"cvetest", "--cve-id", "CVE-2019-9923", "--image", "zot-cve-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

//nolint:dupl
func TestServerCVEResponse(t *testing.T) {
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	dir := t.TempDir()

	test.CopyTestFiles("../../test/data/zot-cve-test", path.Join(dir, "zot-cve-test"))

	conf.Storage.RootDirectory = dir
	trivyConfig := &extconf.TrivyConfig{
		DBRepository: "ghcr.io/project-zot/trivy-db",
	}
	cveConfig := &extconf.CVEConfig{
		UpdateInterval: 2,
		Trivy:          trivyConfig,
	}
	defaultVal := true
	searchConfig := &extconf.SearchConfig{
		BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		CVE:        cveConfig,
	}
	conf.Extensions = &extconf.ExtensionConfig{
		Search: searchConfig,
	}

	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	writers := io.MultiWriter(os.Stdout, logFile)

	ctlr := api.NewController(conf)
	ctlr.Log.Logger = ctlr.Log.Output(writers)

	ctx := context.Background()

	if err := ctlr.Init(ctx); err != nil {
		panic(err)
	}

	ctlr.CveInfo = getMockCveInfo(ctlr.RepoDB, ctlr.Log)

	go func() {
		if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	defer ctlr.Shutdown()

	test.WaitTillServerReady(url)

	_, err = test.ReadLogFileAndSearchString(logPath, "DB update completed, next update scheduled", 90*time.Second)
	if err != nil {
		panic(err)
	}

	Convey("Test CVE by image name - GQL - positive", t, func() {
		args := []string{"cvetest", "--image", "zot-cve-test:0.0.1"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "ID SEVERITY TITLE")
		So(str, ShouldContainSubstring, "CVE")
	})

	Convey("Test CVE by image name - GQL - invalid image", t, func() {
		args := []string{"cvetest", "--image", "invalid:0.0.1"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by image name - GQL - invalid image name and tag", t, func() {
		args := []string{"cvetest", "--image", "invalid:"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by image name - GQL - invalid output format", t, func() {
		args := []string{"cvetest", "--image", "zot-cve-test:0.0.1", "-o", "random"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test images by CVE ID - GQL - positive", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-9923"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE zot-cve-test 0.0.1 "+
			test.GetTestBlobDigest("zot-cve-test", "manifest").Encoded()[:8]+" false 75MB")
	})

	Convey("Test images by CVE ID - GQL - invalid CVE ID", t, func() {
		args := []string{"cvetest", "--cve-id", "invalid"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test images by CVE ID - GQL - invalid output format", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-9923", "-o", "random"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - positive", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-9923", "--image", "zot-cve-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - random cve", t, func() {
		args := []string{"cvetest", "--cve-id", "random", "--image", "zot-cve-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - random image", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-20807", "--image", "zot-cv-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - invalid image", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-20807", "--image", "zot-cv-test:tag", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - GQL - positive", t, func() {
		args := []string{"cvetest", "--image", "zot-cve-test", "--cve-id", "CVE-2019-9923"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE zot-cve-test 0.0.1 "+
			test.GetTestBlobDigest("zot-cve-test", "manifest").Encoded()[:8]+" false 75MB")
	})

	Convey("Test CVE by name and CVE ID - GQL - invalid name and CVE ID", t, func() {
		args := []string{"cvetest", "--image", "test", "--cve-id", "CVE-20807"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - GQL - invalid output format", t, func() {
		args := []string{"cvetest", "--image", "zot-cve-test", "--cve-id", "CVE-2019-9923", "-o", "random"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test CVE by image name - positive", t, func() {
		args := []string{"cvetest", "--image", "zot-cve-test:0.0.1"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "ID SEVERITY TITLE")
		So(str, ShouldContainSubstring, "CVE")
	})

	Convey("Test CVE by image name - invalid image", t, func() {
		args := []string{"cvetest", "--image", "invalid:0.0.1"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test images by CVE ID - positive", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-9923"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE zot-cve-test 0.0.1 "+
			test.GetTestBlobDigest("zot-cve-test", "manifest").Encoded()[:8]+" false 75MB")
	})

	Convey("Test images by CVE ID - invalid CVE ID", t, func() {
		args := []string{"cvetest", "--cve-id", "invalid"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by and image name CVE ID - positive", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-9923", "--image", "zot-cve-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "")
	})

	Convey("Test fixed tags by and image name CVE ID - random cve", t, func() {
		args := []string{"cvetest", "--cve-id", "random", "--image", "zot-cve-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by and image name CVE ID - invalid image", t, func() {
		args := []string{"cvetest", "--cve-id", "CVE-2019-20807", "--image", "zot-cv-test", "--fixed"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - positive", t, func() {
		args := []string{"cvetest", "--image", "zot-cve-test", "--cve-id", "CVE-2019-9923"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE zot-cve-test 0.0.1 "+
			test.GetTestBlobDigest("zot-cve-test", "manifest").Encoded()[:8]+" false 75MB")
	})

	Convey("Test CVE by name and CVE ID - invalid name and CVE ID", t, func() {
		args := []string{"cvetest", "--image", "test", "--cve-id", "CVE-20807"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := MockNewCveCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
	})
}

func MockNewCveCommand(searchService SearchService) *cobra.Command {
	searchCveParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var verifyTLS, fixedFlag, verbose, debug bool

	cveCmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}

			configPath := path.Join(home + "/.zot")
			if len(args) > 0 {
				urlFromConfig, err := getConfigValue(configPath, args[0], "url")
				if err != nil {
					cmd.SilenceUsage = true

					return err
				}

				if urlFromConfig == "" {
					return zotErrors.ErrNoURLProvided
				}

				servURL = urlFromConfig
			} else {
				return zotErrors.ErrNoURLProvided
			}

			if len(args) > 0 {
				var err error

				verifyTLS, err = parseBooleanConfig(configPath, args[0], verifyTLSConfig)
				if err != nil {
					cmd.SilenceUsage = true

					return err
				}
			}

			verbose = false
			debug = false

			searchConfig := searchConfig{
				params:        searchCveParams,
				searchService: searchService,
				servURL:       &servURL,
				user:          &user,
				outputFormat:  &outputFormat,
				fixedFlag:     &fixedFlag,
				verifyTLS:     &verifyTLS,
				verbose:       &verbose,
				debug:         &debug,
				resultWriter:  cmd.OutOrStdout(),
			}

			err = MockSearchCve(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true

				return err
			}

			return nil
		},
	}

	vars := cveFlagVariables{
		searchCveParams: searchCveParams,
		servURL:         &servURL,
		user:            &user,
		outputFormat:    &outputFormat,
		fixedFlag:       &fixedFlag,
		debug:           &debug,
	}

	setupCveFlags(cveCmd, vars)

	return cveCmd
}

func MockSearchCve(searchConfig searchConfig) error {
	searchers := getCveSearchers()

	for _, searcher := range searchers {
		found, err := searcher.search(searchConfig)
		if found {
			if err != nil {
				return err
			}

			return nil
		}
	}

	return zotErrors.ErrInvalidFlagsCombination
}

func getMockCveInfo(repoDB repodb.RepoDB, log log.Logger) cveinfo.CveInfo {
	// RepoDB loaded with initial data, mock the scanner
	severities := map[string]int{
		"UNKNOWN":  0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	// Setup test CVE data in mock scanner
	scanner := mocks.CveScannerMock{
		ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
			if image == "zot-cve-test:0.0.1" {
				return map[string]cvemodel.CVE{
					"CVE-2019-9923": {
						ID:          "CVE-2019-9923",
						Severity:    "HIGH",
						Title:       "Title for CVE-2019-9923",
						Description: "Description of CVE-2019-9923",
					},
				}, nil
			}

			// By default the image has no vulnerabilities
			return map[string]cvemodel.CVE{}, nil
		},
		CompareSeveritiesFn: func(severity1, severity2 string) int {
			return severities[severity2] - severities[severity1]
		},
		IsImageFormatScannableFn: func(image string) (bool, error) {
			// Almost same logic compared to actual Trivy specific implementation
			var imageDir string

			var inputTag string

			if strings.Contains(image, ":") {
				imageDir, inputTag, _ = strings.Cut(image, ":")
			} else {
				imageDir = image
			}

			repoMeta, err := repoDB.GetRepoMeta(imageDir)
			if err != nil {
				return false, err
			}

			manifestDigestStr, ok := repoMeta.Tags[inputTag]
			if !ok {
				return false, zotErrors.ErrTagMetaNotFound
			}

			manifestDigest, err := godigest.Parse(manifestDigestStr.Digest)
			if err != nil {
				return false, err
			}

			manifestData, err := repoDB.GetManifestData(manifestDigest)
			if err != nil {
				return false, err
			}

			var manifestContent ispec.Manifest

			err = json.Unmarshal(manifestData.ManifestBlob, &manifestContent)
			if err != nil {
				return false, zotErrors.ErrScanNotSupported
			}

			for _, imageLayer := range manifestContent.Layers {
				switch imageLayer.MediaType {
				case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):

					return true, nil
				default:

					return false, zotErrors.ErrScanNotSupported
				}
			}

			return false, nil
		},
	}

	return &cveinfo.BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		RepoDB:  repoDB,
	}
}
