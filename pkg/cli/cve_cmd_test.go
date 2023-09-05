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
	"strconv"
	"strings"
	"testing"
	"time"

	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	zcommon "zotregistry.io/zot/pkg/common"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
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

	cm.StartServer()
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
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "ID SEVERITY TITLE dummyCVEID HIGH Title of that CVE")
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
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "ID SEVERITY TITLE dummyCVEID HIGH Title of that CVE")
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
			`"InstalledVersion":"installedver","FixedVersion":"fixedver"}]}]}`+"\n")
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
			`- name: packagename installedversion: installedver fixedversion: fixedver`)
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

func TestNegativeServerResponse(t *testing.T) {
	Convey("Test from real server without search endpoint", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		srcStorageCtlr := test.GetDefaultStoreController(dir, log.NewLogger("debug", ""))
		err := test.WriteImageToFileSystem(test.CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

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
			args := []string{"list", "zot-cve-test:0.0.1", "--config", "cvetest"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cveCmd := NewCVECommand(new(searchService))
			buff := bytes.NewBufferString("")
			cveCmd.SetOut(buff)
			cveCmd.SetErr(buff)
			cveCmd.SetArgs(args)
			err = cveCmd.Execute()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, zerr.ErrExtensionNotEnabled.Error())
		})
	})

	Convey("Test non-existing manifest blob", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		imageStore := local.NewImageStore(dir, false, false, 0, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		num := 10
		config, layers, manifest, err := test.GetRandomImageComponents(num) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Manifest: manifest,
				Layers:   layers,
				Config:   config,
			}, "zot-cve-test", "0.0.1", storeController,
		)
		So(err, ShouldBeNil)

		err = os.RemoveAll(path.Join(dir, "zot-cve-test/blobs"))
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

		ctlr.CveInfo = getMockCveInfo(ctlr.MetaDB, ctlr.Log)

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

		args := []string{"fixed", "zot-cve-test", "CVE-2019-9923", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
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

	ctlr.CveInfo = getMockCveInfo(ctlr.MetaDB, ctlr.Log)

	go func() {
		if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	defer ctlr.Shutdown()

	test.WaitTillServerReady(url)

	config, layers, manifest, err := test.GetImageComponents(100) //nolint:staticcheck
	if err != nil {
		panic(err)
	}

	err = test.PushTestImage("zot-cve-test", "0.0.1", url,
		manifest, config, layers)
	if err != nil {
		panic(err)
	}

	_, err = test.ReadLogFileAndSearchString(logPath, "DB update completed, next update scheduled", 90*time.Second)
	if err != nil {
		panic(err)
	}

	Convey("Test CVE by image name - GQL - positive", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
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

	Convey("Test CVE by image name - GQL - search CVE by title in results", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--cve-id", "CVE-C1", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
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
		So(str, ShouldContainSubstring, "CVE-C1")
		So(str, ShouldNotContainSubstring, "CVE-2")
	})

	Convey("Test CVE by image name - GQL - search CVE by id in results", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--cve-id", "CVE-2", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
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
		So(str, ShouldContainSubstring, "CVE-2")
		So(str, ShouldNotContainSubstring, "CVE-1")
	})

	Convey("Test CVE by image name - GQL - search nonexistent CVE", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "--cve-id", "CVE-100", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldContainSubstring, "No CVEs found for image")
	})

	Convey("Test CVE by image name - GQL - invalid image", t, func() {
		args := []string{"list", "invalid:0.0.1", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by image name - GQL - invalid image name and tag", t, func() {
		args := []string{"list", "invalid:", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test CVE by image name - GQL - invalid output format", t, func() {
		args := []string{"list", "zot-cve-test:0.0.1", "-f", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test images by CVE ID - GQL - positive", t, func() {
		args := []string{"affected", "CVE-2019-9923", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldEqual, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE zot-cve-test 0.0.1 linux/amd64 40d1f749 false 605B")
	})

	Convey("Test images by CVE ID - GQL - invalid CVE ID", t, func() {
		args := []string{"affected", "CVE-invalid", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(str, ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test images by CVE ID - GQL - invalid output format", t, func() {
		args := []string{"affected", "CVE-2019-9923", "-f", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - positive", t, func() {
		args := []string{"fixed", "zot-cve-test", "CVE-2019-9923", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
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
		args := []string{"fixed", "zot-cve-test", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - random image", t, func() {
		args := []string{"fixed", "zot-cv-test", "CVE-2019-20807", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test fixed tags by image name and CVE ID - GQL - invalid image", t, func() {
		args := []string{"fixed", "zot-cv-test:tag", "CVE-2019-20807", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		str = strings.TrimSpace(str)
		So(err, ShouldNotBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - GQL - positive", t, func() {
		args := []string{"affected", "CVE-2019-9923", "--repo", "zot-cve-test", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE zot-cve-test 0.0.1 linux/amd64 40d1f749 false 605B")
	})

	Convey("Test CVE by name and CVE ID - GQL - invalid name and CVE ID", t, func() {
		args := []string{"affected", "CVE-20807", "--repo", "test", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err := cveCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(err, ShouldBeNil)
		So(strings.TrimSpace(str), ShouldNotContainSubstring, "REPOSITORY TAG OS/ARCH SIGNED SIZE")
	})

	Convey("Test CVE by name and CVE ID - GQL - invalid output format", t, func() {
		args := []string{"affected", "CVE-2019-9923", "--repo", "zot-cve-test", "-f", "random", "--config", "cvetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})
}

func TestCVESort(t *testing.T) {
	rootDir := t.TempDir()
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE: &extconf.CVEConfig{
				UpdateInterval: 2,
				Trivy: &extconf.TrivyConfig{
					DBRepository: "ghcr.io/project-zot/trivy-db",
				},
			},
		},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = rootDir

	image1 := test.CreateRandomImage()

	storeController := test.GetDefaultStoreController(rootDir, ctlr.Log)

	err := test.WriteImageToFileSystem(image1, "repo", "tag", storeController)
	if err != nil {
		t.FailNow()
	}

	ctx := context.Background()

	if err := ctlr.Init(ctx); err != nil {
		panic(err)
	}

	severities := map[string]int{
		"UNKNOWN":  0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	ctlr.CveInfo = cveinfo.BaseCveInfo{
		Log:    ctlr.Log,
		MetaDB: mocks.MetaDBMock{},
		Scanner: mocks.CveScannerMock{
			CompareSeveritiesFn: func(severity1, severity2 string) int {
				return severities[severity2] - severities[severity1]
			},
			ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
				return map[string]cvemodel.CVE{
					"CVE-2023-1255": {
						ID:       "CVE-2023-1255",
						Severity: "LOW",
						Title:    "Input buffer over-read in AES-XTS implementation and testing",
					},
					"CVE-2023-2650": {
						ID:       "CVE-2023-2650",
						Severity: "MEDIUM",
						Title:    "Possible DoS translating ASN.1 object identifier and executer",
					},
					"CVE-2023-2975": {
						ID:       "CVE-2023-2975",
						Severity: "HIGH",
						Title:    "AES-SIV cipher implementation contains a bug that can break",
					},
					"CVE-2023-3446": {
						ID:       "CVE-2023-3446",
						Severity: "CRITICAL",
						Title:    "Excessive time spent checking DH keys and parenthesis",
					},
					"CVE-2023-3817": {
						ID:       "CVE-2023-3817",
						Severity: "MEDIUM",
						Title:    "Excessive time spent checking DH q parameter and arguments",
					},
				}, nil
			},
		},
	}

	go func() {
		if err := ctlr.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	defer ctlr.Shutdown()

	test.WaitTillServerReady(baseURL)

	space := regexp.MustCompile(`\s+`)

	Convey("test sorting", t, func() {
		args := []string{"list", "repo:tag", "--sort-by", "severity", "--url", baseURL}
		cmd := NewCVECommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldResemble,
			"ID SEVERITY TITLE "+
				"CVE-2023-3446 CRITICAL Excessive time spent checking DH keys and par... "+
				"CVE-2023-2975 HIGH AES-SIV cipher implementation contains a bug ... "+
				"CVE-2023-2650 MEDIUM Possible DoS translating ASN.1 object identif... "+
				"CVE-2023-3817 MEDIUM Excessive time spent checking DH q parameter ... "+
				"CVE-2023-1255 LOW Input buffer over-read in AES-XTS implementat...")

		args = []string{"list", "repo:tag", "--sort-by", "alpha-asc", "--url", baseURL}
		cmd = NewCVECommand(new(searchService))
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldResemble,
			"ID SEVERITY TITLE "+
				"CVE-2023-1255 LOW Input buffer over-read in AES-XTS implementat... "+
				"CVE-2023-2650 MEDIUM Possible DoS translating ASN.1 object identif... "+
				"CVE-2023-2975 HIGH AES-SIV cipher implementation contains a bug ... "+
				"CVE-2023-3446 CRITICAL Excessive time spent checking DH keys and par... "+
				"CVE-2023-3817 MEDIUM Excessive time spent checking DH q parameter ...")

		args = []string{"list", "repo:tag", "--sort-by", "alpha-dsc", "--url", baseURL}
		cmd = NewCVECommand(new(searchService))
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldResemble,
			"ID SEVERITY TITLE "+
				"CVE-2023-3817 MEDIUM Excessive time spent checking DH q parameter ... "+
				"CVE-2023-3446 CRITICAL Excessive time spent checking DH keys and par... "+
				"CVE-2023-2975 HIGH AES-SIV cipher implementation contains a bug ... "+
				"CVE-2023-2650 MEDIUM Possible DoS translating ASN.1 object identif... "+
				"CVE-2023-1255 LOW Input buffer over-read in AES-XTS implementat...")
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
				getTagsForCVEGQLFn: func(ctx context.Context, config searchConfig, username, password,
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
				getFixedTagsForCVEGQLFn: func(ctx context.Context, config searchConfig, username, password,
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
			So(actual, ShouldContainSubstring, "dummyCVEID HIGH Title of that CVE")
		})

		Convey("image db download wait", func() {
			count := 0
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"cvetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"list", "repo:vuln", "--config", "cvetest"}
			defer os.Remove(configPath)
			cmd := NewCVECommand(mockService{
				getCveByImageGQLFn: func(ctx context.Context, config searchConfig, username, password,
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

func getMockCveInfo(metaDB mTypes.MetaDB, log log.Logger) cveinfo.CveInfo {
	// MetaDB loaded with initial data, mock the scanner
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
			if image == "zot-cve-test@sha256:40d1f74918aefed733c590f798d7eafde8fc0a7ec63bb8bc52eaae133cf92495" ||
				image == "zot-cve-test:0.0.1" {
				return map[string]cvemodel.CVE{
					"CVE-1": {
						ID:          "CVE-1",
						Severity:    "CRITICAL",
						Title:       "Title for CVE-C1",
						Description: "Description of CVE-1",
					},
					"CVE-2019-9923": {
						ID:          "CVE-2019-9923",
						Severity:    "HIGH",
						Title:       "Title for CVE-2",
						Description: "Description of CVE-2",
					},
					"CVE-3": {
						ID:          "CVE-3",
						Severity:    "MEDIUM",
						Title:       "Title for CVE-3",
						Description: "Description of CVE-3",
					},
					"CVE-4": {
						ID:          "CVE-4",
						Severity:    "LOW",
						Title:       "Title for CVE-4",
						Description: "Description of CVE-4",
					},
					"CVE-5": {
						ID:          "CVE-5",
						Severity:    "UNKNOWN",
						Title:       "Title for CVE-5",
						Description: "Description of CVE-5",
					},
				}, nil
			}

			// By default the image has no vulnerabilities
			return map[string]cvemodel.CVE{}, nil
		},
		CompareSeveritiesFn: func(severity1, severity2 string) int {
			return severities[severity2] - severities[severity1]
		},
		IsImageFormatScannableFn: func(repo string, reference string) (bool, error) {
			// Almost same logic compared to actual Trivy specific implementation
			imageDir := repo
			inputTag := reference

			repoMeta, err := metaDB.GetRepoMeta(imageDir)
			if err != nil {
				return false, err
			}

			manifestDigestStr := reference

			if zcommon.IsTag(reference) {
				var ok bool

				descriptor, ok := repoMeta.Tags[inputTag]
				if !ok {
					return false, zerr.ErrTagMetaNotFound
				}

				manifestDigestStr = descriptor.Digest
			}

			manifestDigest, err := godigest.Parse(manifestDigestStr)
			if err != nil {
				return false, err
			}

			manifestData, err := metaDB.GetManifestData(manifestDigest)
			if err != nil {
				return false, err
			}

			var manifestContent ispec.Manifest

			err = json.Unmarshal(manifestData.ManifestBlob, &manifestContent)
			if err != nil {
				return false, zerr.ErrScanNotSupported
			}

			for _, imageLayer := range manifestContent.Layers {
				switch imageLayer.MediaType {
				case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):

					return true, nil
				default:

					return false, zerr.ErrScanNotSupported
				}
			}

			return false, nil
		},
	}

	return &cveinfo.BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		MetaDB:  metaDB,
	}
}

type mockServiceForRetry struct {
	mockService
	retryCounter int
	succeedOn    int
}

func (service *mockServiceForRetry) getTagsForCVEGQL(ctx context.Context, config searchConfig, username, password, repo,
	cveID string,
) (*zcommon.ImagesForCve, error) {
	service.retryCounter += 1

	if service.retryCounter < service.succeedOn || service.succeedOn < 0 {
		return &zcommon.ImagesForCve{}, zerr.ErrCVEDBNotFound
	}

	return service.mockService.getTagsForCVEGQL(ctx, config, username, password, repo, cveID)
}
