//go:build search && ui

package extensions_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/log"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestUIExtension(t *testing.T) {
	Convey("Verify zot with UI extension starts successfully", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf.HTTP.Port = port
		conf.Commit = "abc123"
		conf.ReleaseTag = "v2.1.0"
		conf.BinaryType = "server"
		conf.GoVersion = "go1.24.0"
		conf.DistSpecVersion = "1.1.1"

		// we won't use the logging config feature as we want logs in both
		// stdout and a file
		logFile := test.MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		logPath := logFile.Name()

		writers := io.MultiWriter(os.Stdout, logFile)

		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.UI = &extconf.UIConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultValue},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		ctlr.Log = log.NewLoggerWithWriter("debug", writers)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logPath, "\"UI\":{\"Enable\":true}", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logPath, "setting up ui routes", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		image := CreateRandomImage()

		repoName := "test-repo"
		tagName := "test-tag"

		// Upload a test image
		err = UploadImage(image, baseURL, repoName, tagName)
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/home")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(string(resp.Body()), ShouldContainSubstring, "/assets/zot-version-info.js")

		resp, err = resty.R().Get(baseURL + "/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(string(resp.Body()), ShouldContainSubstring, "/assets/zot-version-info.js")

		resp, err = resty.R().Get(baseURL + "/index.html")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(string(resp.Body()), ShouldContainSubstring, "/assets/zot-version-info.js")

		resp, err = resty.R().Get(baseURL + "/assets/zot-version-info.js")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(string(resp.Body()), ShouldContainSubstring, "zot-version-info")

		resp, err = resty.R().Get(baseURL + "/assets/zot-version.json")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Header().Get("Content-Type"), ShouldContainSubstring, "application/json")

		versionInfo := struct {
			Commit          string `json:"commit"`
			ReleaseTag      string `json:"releaseTag"`
			BinaryType      string `json:"binaryType"`
			GoVersion       string `json:"goVersion"`
			DistSpecVersion string `json:"distSpecVersion"`
		}{}
		err = json.Unmarshal(resp.Body(), &versionInfo)
		So(err, ShouldBeNil)
		So(versionInfo.Commit, ShouldEqual, "abc123")
		So(versionInfo.ReleaseTag, ShouldEqual, "v2.1.0")
		So(versionInfo.BinaryType, ShouldEqual, "server")
		So(versionInfo.GoVersion, ShouldEqual, "go1.24.0")
		So(versionInfo.DistSpecVersion, ShouldEqual, "1.1.1")

		resp, err = resty.R().Get(baseURL + "/image/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/" + repoName)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/" + repoName + "/tag/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/" + repoName + "/tag/" + tagName)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/badurl/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}
