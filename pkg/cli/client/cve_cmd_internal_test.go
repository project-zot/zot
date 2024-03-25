//go:build search
// +build search

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	zcommon "zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestSearchCVECmd(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	rootDir := t.TempDir()
	conf.Storage.RootDirectory = rootDir

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		},
	}

	ctlr := api.NewController(conf)
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(port)
	defer cm.StopServer()

	Convey("Test CVE help", t, func() {
		args := []string{"--help"}
		configPath := makeConfigFile("")
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(mockService))
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
		cmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
	})

	Convey("Test CVE no url", t, func() {
		args := []string{"affected", "CVE-cveIdRandom", "--config", "cvetest"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrNoURLProvided), ShouldBeTrue)
	})

	Convey("Test CVE invalid url", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", "invalidUrl"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidURL), ShouldBeTrue)
		So(buff.String(), ShouldContainSubstring, "invalid URL format")
	})

	Convey("Test CVE invalid url port", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", "http://localhost:99999"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid port")
	})

	Convey("Test CVE unreachable", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", "http://localhost:9999"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE url from config", t, func() {
		args := []string{"list", "dummyImageName:tag", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, baseURL))
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		outputLines := strings.Split(buff.String(), "\n")

		expected := []string{
			"CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 1",
			"",
			"ID SEVERITY TITLE VULNERABLE PACKAGE PATH INSTALL-VER FIXED-VER",
			"dummyCVEID HIGH Title of that CVE",
			"packagename - installedver fixedver",
		}

		for expectedLineIndex, expectedLine := range expected {
			currentOutputLine := outputLines[expectedLineIndex]
			str := space.ReplaceAllString(currentOutputLine, " ")
			So(strings.TrimSpace(str), ShouldEqual, expectedLine)
		}

		So(err, ShouldBeNil)
	})

	Convey("Test debug flag", t, func() {
		args := []string{"list", "dummyImageName:tag", "--debug", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, baseURL))
		defer os.Remove(configPath)
		cmd := NewCVECommand(new(searchService))
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
		args := []string{"affected", "CVE-CVEID", "--repo", "dummyImageName", "--url", baseURL}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
	})

	Convey("Test CVE by name and CVE ID - using shorthand", t, func() {
		args := []string{"affected", "CVE-CVEID", "--repo", "dummyImageName", "--url", baseURL}
		buff := bytes.NewBufferString("")
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
	})

	Convey("Test CVE by image name - in text format", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", baseURL}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		outputLines := strings.Split(buff.String(), "\n")

		expected := []string{
			"CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 1",
			"",
			"ID SEVERITY TITLE VULNERABLE PACKAGE PATH INSTALL-VER FIXED-VER",
			"dummyCVEID HIGH Title of that CVE",
			"packagename - installedver fixedver",
		}

		for expectedLineIndex, expectedLine := range expected {
			currentOutputLine := outputLines[expectedLineIndex]
			str := space.ReplaceAllString(currentOutputLine, " ")
			So(strings.TrimSpace(str), ShouldEqual, expectedLine)
		}

		So(err, ShouldBeNil)
	})

	Convey("Test CVE by image name - in text format - in verbose mode", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", baseURL, "--verbose"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()

		outputLines := strings.Split(buff.String(), "\n")
		expected := []string{
			"CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 1",
			"",
			"dummyCVEID",
			"Severity: HIGH",
			"Title: Title of that CVE",
			"Description:",
			"Description of the CVE",
			"",
			"Vulnerable Packages:",
			" Package Name: packagename",
			" Package Path: ",
			" Installed Version: installedver",
			" Fixed Version: fixedver",
			"",
			"",
		}

		for index, expectedLine := range expected {
			So(outputLines[index], ShouldEqual, expectedLine)
		}

		So(err, ShouldBeNil)
	})

	Convey("Test CVE by image name - in json format", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", baseURL, "-f", "json"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		// Output is supposed to be in json lines format, keep all spaces as is for verification
		So(buff.String(), ShouldEqual, `{"Tag":"dummyImageName:tag","CVEList":`+
			`[{"Id":"dummyCVEID","Severity":"HIGH","Title":"Title of that CVE",`+
			`"Description":"Description of the CVE","PackageList":[{"Name":"packagename",`+
			`"PackagePath":"","InstalledVersion":"installedver","FixedVersion":"fixedver"}]}],"Summary":`+
			`{"maxSeverity":"HIGH","unknownCount":0,"lowCount":0,"mediumCount":0,"highCount":1,`+
			`"criticalCount":0,"count":1}}`+"\n")
		So(err, ShouldBeNil)
	})

	Convey("Test CVE by image name - in yaml format", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", baseURL, "-f", "yaml"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, `--- tag: dummyImageName:tag cvelist: - id: dummyCVEID`+
			` severity: HIGH title: Title of that CVE description: Description of the CVE packagelist: `+
			`- name: packagename packagepath: "" installedversion: installedver fixedversion: fixedver `+
			`summary: maxseverity: HIGH unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 1 criticalcount: 0 count: 1`)
		So(err, ShouldBeNil)
	})
	Convey("Test CVE by image name - invalid format", t, func() {
		args := []string{"list", "dummyImageName:tag", "--url", baseURL, "-f", "random"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldContainSubstring, zerr.ErrInvalidOutputFormat.Error())
	})

	Convey("Test images by CVE ID - positive", t, func() {
		args := []string{"affected", "CVE-CVEID", "--repo", "anImage", "--url", baseURL}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE anImage tag os/arch 6e2f80bf false 123kB") //nolint:lll
		So(err, ShouldBeNil)
	})

	Convey("Test images by CVE ID - positive with retries", t, func() {
		args := []string{"affected", "CVE-CVEID", "--repo", "anImage", "--url", baseURL}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		mockService := mockServiceForRetry{succeedOn: 2} // CVE info will be provided in 2nd attempt
		cveCmd := NewCVECommand(&mockService)
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		t.Logf("Output: %s", str)
		So(strings.TrimSpace(str), ShouldContainSubstring,
			"[warning] CVE DB is not ready [1] - retry in "+strconv.Itoa(CveDBRetryInterval)+" seconds")
		So(strings.TrimSpace(str), ShouldContainSubstring,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE anImage tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test images by CVE ID - failed after retries", t, func() {
		args := []string{"affected", "CVE-CVEID", "--url", baseURL}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		mockService := mockServiceForRetry{succeedOn: -1} // CVE info will be unavailable on all retries
		cveCmd := NewCVECommand(&mockService)
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		t.Logf("Output: %s", str)
		So(strings.TrimSpace(str), ShouldContainSubstring,
			"[warning] CVE DB is not ready [1] - retry in "+strconv.Itoa(CveDBRetryInterval)+" seconds")
		So(strings.TrimSpace(str), ShouldNotContainSubstring,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE anImage tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldNotBeNil)
	})

	Convey("Test images by CVE ID - invalid CVE ID", t, func() {
		args := []string{"affected", "CVE-invalidCVEID", "--config", "cvetest"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test images by CVE ID - invalid url", t, func() {
		args := []string{"affected", "CVE-CVEID", "--url", "invalidURL"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidURL), ShouldBeTrue)
		So(buff.String(), ShouldContainSubstring, "invalid URL format")
	})

	Convey("Test fixed tags by and image name CVE ID - positive", t, func() {
		args := []string{"fixed", "fixedImage", "CVE-CVEID", "--url", baseURL}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(mockService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldEqual, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE fixedImage tag os/arch 6e2f80bf false 123kB") //nolint:lll
	})

	Convey("Test fixed tags by and image name CVE ID - invalid image name", t, func() {
		args := []string{"affected", "CVE-CVEID", "--image", "invalidImageName", "--config", "cvetest"}
		configPath := makeConfigFile(`{"configs":[{"_name":"cvetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(NewSearchService())
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestCVECommandGQL(t *testing.T) {
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
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, baseURL))
		defer os.Remove(configPath)

		Convey("cveid", func() {
			args := []string{"affected", "CVE-1942", "--config", "cvetest"}
			cmd := NewCVECommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "image-name tag os/arch 6e2f80bf false 123kB")
		})

		Convey("cveid db download wait", func() {
			count := 0
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"affected", "CVE-12345", "--config", "cvetest"}
			defer os.Remove(configPath)
			cmd := NewCVECommand(mockService{
				getTagsForCVEGQLFn: func(ctx context.Context, config SearchConfig, username, password,
					imageName, cveID string) (*zcommon.ImagesForCve, error,
				) {
					if count == 0 {
						count++
						fmt.Println("Count:", count)

						return &zcommon.ImagesForCve{}, zerr.ErrCVEDBNotFound
					}

					return &zcommon.ImagesForCve{}, zerr.ErrInjected
				},
			})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "[warning] CVE DB is not ready")
		})

		Convey("fixed", func() {
			args := []string{"fixed", "image-name", "CVE-123", "--config", "cvetest"}
			cmd := NewCVECommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "image-name tag os/arch 6e2f80bf false 123kB")
		})

		Convey("fixed db download wait", func() {
			count := 0
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"fixed", "repo", "CVE-2222", "--config", "cvetest"}
			defer os.Remove(configPath)
			cmd := NewCVECommand(mockService{
				getFixedTagsForCVEGQLFn: func(ctx context.Context, config SearchConfig, username, password,
					imageName, cveID string) (*zcommon.ImageListWithCVEFixedResponse, error,
				) {
					if count == 0 {
						count++
						fmt.Println("Count:", count)

						return &zcommon.ImageListWithCVEFixedResponse{}, zerr.ErrCVEDBNotFound
					}

					return &zcommon.ImageListWithCVEFixedResponse{}, zerr.ErrInjected
				},
			})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "[warning] CVE DB is not ready")
		})

		Convey("image", func() {
			args := []string{"list", "repo:tag", "--config", "cvetest"}
			cmd := NewCVECommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "CRITICAL 0, HIGH 1, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 1")
			So(actual, ShouldContainSubstring, "dummyCVEID HIGH Title of that CVE")
		})

		Convey("image db download wait", func() {
			count := 0
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"list", "repo:vuln", "--config", "cvetest"}
			defer os.Remove(configPath)
			cmd := NewCVECommand(mockService{
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
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "[warning] CVE DB is not ready")
		})
	})
}

func TestCVECommandErrors(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: ref(true)},
		},
	}

	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	Convey("commands without gql", t, func() {
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, baseURL))
		defer os.Remove(configPath)

		Convey("cveid", func() {
			args := []string{"affected", "CVE-1942"}
			cmd := NewCVECommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("cveid error", func() {
			// too many args
			args := []string{"too", "many", "args"}
			cmd := NewImagesByCVEIDCommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad args
			args = []string{"not-a-cve-id"}
			cmd = NewImagesByCVEIDCommand(mockService{})
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no URL
			args = []string{"CVE-1942"}
			cmd = NewImagesByCVEIDCommand(mockService{})
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("fixed command", func() {
			args := []string{"fixed", "image-name", "CVE-123"}
			cmd := NewCVECommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("fixed command error", func() {
			// too many args
			args := []string{"too", "many", "args", "args"}
			cmd := NewFixedTagsCommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad args
			args = []string{"repo-tag-instead-of-just-repo:fail-here", "CVE-123"}
			cmd = NewFixedTagsCommand(mockService{})
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no URL
			args = []string{"CVE-1942"}
			cmd = NewFixedTagsCommand(mockService{})
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("image", func() {
			args := []string{"list", "repo:tag"}
			cmd := NewCVECommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("image command error", func() {
			// too many args
			args := []string{"too", "many", "args", "args"}
			cmd := NewCveForImageCommand(mockService{})
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad args
			args = []string{"repo-tag-instead-of-just-repo:fail-here", "CVE-123"}
			cmd = NewCveForImageCommand(mockService{})
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no URL
			args = []string{"CVE-1942"}
			cmd = NewCveForImageCommand(mockService{})
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

type mockServiceForRetry struct {
	mockService
	retryCounter int
	succeedOn    int
}

func (service *mockServiceForRetry) getTagsForCVEGQL(ctx context.Context, config SearchConfig, username, password, repo,
	cveID string,
) (*zcommon.ImagesForCve, error) {
	service.retryCounter += 1

	if service.retryCounter < service.succeedOn || service.succeedOn < 0 {
		return &zcommon.ImagesForCve{}, zerr.ErrCVEDBNotFound
	}

	return service.mockService.getTagsForCVEGQL(ctx, config, username, password, repo, cveID)
}
