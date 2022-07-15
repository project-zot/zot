//go:build ui_base
// +build ui_base

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
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
		Convey("with the shorthand", func() {
			args[0] = "-h"
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

		Convey("without flags", func() {
			args := []string{"cvetest", "--image", "dummyImageName:tag", "--url", "http://localhost:99999"}
			configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
			defer os.Remove(configPath)
			cmd := NewCveCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
			So(buff.String(), ShouldContainSubstring, "invalid port")
		})
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

	Convey("Test CVE by name and CVE ID", t, func() {
		args := []string{"cvetest", "--image", "dummyImageName", "--cve-id", "aCVEID", "--url", "someURL"}
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE dummyImageName tag DigestsA 123kB")
		So(err, ShouldBeNil)
		Convey("using shorthand", func() {
			args := []string{"cvetest", "-I", "dummyImageName", "--cve-id", "aCVEID", "--url", "someURL"}
			buff := bytes.NewBufferString("")
			configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
			defer os.Remove(configPath)
			cveCmd := NewCveCommand(new(mockService))
			cveCmd.SetOut(buff)
			cveCmd.SetErr(buff)
			cveCmd.SetArgs(args)
			err := cveCmd.Execute()

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE dummyImageName tag DigestsA 123kB")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test CVE by image name", t, func() {
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

		Convey("in json format", func() {
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

		Convey("in yaml format", func() {
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
		Convey("invalid format", func() {
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
	})

	Convey("Test images by CVE ID", t, func() {
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE anImage tag DigestsA 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test fixed tags by and image name CVE ID", t, func() {
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE fixedImage tag DigestsA 123kB")
	})
}

func TestServerCVEResponse(t *testing.T) {
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	dir := t.TempDir()

	err := test.CopyFiles("../../test/data/zot-cve-test", path.Join(dir, "zot-cve-test"))
	if err != nil {
		panic(err)
	}

	conf.Storage.RootDirectory = dir
	cveConfig := &extconf.CVEConfig{
		UpdateInterval: 2,
	}
	defaultVal := true
	searchConfig := &extconf.SearchConfig{
		CVE:    cveConfig,
		Enable: &defaultVal,
	}
	conf.Extensions = &extconf.ExtensionConfig{
		Search: searchConfig,
	}

	ctlr := api.NewController(conf)

	go func(controller *api.Controller) {
		// this blocks
		if err := controller.Run(context.Background()); err != nil {
			return
		}
	}(ctlr)
	// wait till ready
	for {
		res, err := resty.R().Get(url + constants.ExtSearchPrefix)
		if err == nil && res.StatusCode() == 422 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(90 * time.Second)

	defer func(controller *api.Controller) {
		ctx := context.Background()
		_ = controller.Server.Shutdown(ctx)
	}(ctlr)

	Convey("Test CVE by image name", t, func() {
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
		Convey("invalid image", func() {
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
	})

	Convey("Test images by CVE ID", t, func() {
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
		So(str, ShouldEqual, "IMAGE NAME TAG DIGEST SIZE zot-cve-test 0.0.1 63a795ca 75MB")
		Convey("invalid CVE ID", func() {
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
			So(str, ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
		})
	})

	Convey("Test fixed tags by and image name CVE ID", t, func() {
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
		Convey("random cve", func() {
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
			So(strings.TrimSpace(str), ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
		})

		Convey("invalid image", func() {
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
			So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
		})
	})

	Convey("Test CVE by name and CVE ID", t, func() {
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE zot-cve-test 0.0.1 63a795ca 75MB")
		Convey("invalidname and CVE ID", func() {
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
			So(strings.TrimSpace(str), ShouldNotContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
		})
	})
}
