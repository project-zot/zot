//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package log_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/log"
	test "zotregistry.dev/zot/pkg/test/common"
)

type AuditLog struct {
	Level    string `json:"level"`
	ClientIP string `json:"clientIP"` //nolint:tagliatelle // keep IP
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Object   string `json:"object"`
	Status   int    `json:"status"`
	Time     string `json:"time"`
	Message  string `json:"message"`
}

func TestAuditLogMessages(t *testing.T) {
	Convey("Make a new controller", t, func() {
		dir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()

		outputPath := dir + "/zot.log"
		auditPath := dir + "/zot-audit.log"
		conf.Log = &config.LogConfig{Level: "debug", Output: outputPath, Audit: auditPath}

		conf.HTTP.Port = port

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		ctlr.Config.Storage.RootDirectory = dir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		Convey("Open auditLog file", func() {
			auditFile, err := os.Open(auditPath)
			if err != nil {
				t.Log("Cannot open file")
				panic(err)
			}
			defer auditFile.Close()

			Convey("Test GET request", func() {
				resp, err := resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				byteValue, _ := io.ReadAll(auditFile)
				So(len(byteValue), ShouldEqual, 0)
			})

			Convey("Test POST request", func() {
				repoName := "everyone/isallowed"
				path := "/v2/" + repoName + "/blobs/uploads/"
				resp, err := resty.R().SetBasicAuth(username, password).Post(baseURL + path)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

				// wait until the file is populated
				byteValue, _ := io.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = io.ReadAll(auditFile)
				}

				var auditLog AuditLog
				err = json.Unmarshal(byteValue, &auditLog)
				if err != nil {
					panic(err)
				}

				So(auditLog.Subject, ShouldEqual, username)
				So(auditLog.Action, ShouldEqual, http.MethodPost)
				So(auditLog.Status, ShouldEqual, http.StatusAccepted)
				So(auditLog.Object, ShouldEqual, path)
			})

			Convey("Test PUT and DELETE request", func() {
				// create upload
				path := "/v2/repo/blobs/uploads/"
				resp, err := resty.R().SetBasicAuth(username, password).Post(baseURL + path)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				loc := test.Location(baseURL, resp)
				So(loc, ShouldNotBeEmpty)
				location := resp.Header().Get("Location")
				So(location, ShouldNotBeEmpty)

				// wait until the file is populated
				byteValue, _ := io.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = io.ReadAll(auditFile)
				}

				var auditLog AuditLog
				err = json.Unmarshal(byteValue, &auditLog)
				if err != nil {
					panic(err)
				}

				So(auditLog.Subject, ShouldEqual, username)
				So(auditLog.Action, ShouldEqual, http.MethodPost)
				So(auditLog.Status, ShouldEqual, http.StatusAccepted)
				So(auditLog.Object, ShouldEqual, path)

				content := []byte("this is a blob")
				digest := godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)

				// blob upload
				resp, err = resty.R().SetQueryParam("digest", digest.String()).
					SetBasicAuth(username, password).
					SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
				blobLoc := test.Location(baseURL, resp)
				So(blobLoc, ShouldNotBeEmpty)
				So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

				// wait until the file is populated
				byteValue, _ = io.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = io.ReadAll(auditFile)
				}

				err = json.Unmarshal(byteValue, &auditLog)
				if err != nil {
					panic(err)
				}

				So(auditLog.Subject, ShouldEqual, username)
				So(auditLog.Action, ShouldEqual, http.MethodPut)
				So(auditLog.Status, ShouldEqual, http.StatusCreated)

				putPath := location + "?digest=" + strings.ReplaceAll(digest.String(), ":", "%3A")
				So(auditLog.Object, ShouldEqual, putPath)

				// delete this blob
				resp, err = resty.R().SetBasicAuth(username, password).Delete(blobLoc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				So(resp.Header().Get("Content-Length"), ShouldEqual, "0")

				// wait until the file is populated
				byteValue, _ = io.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = io.ReadAll(auditFile)
				}

				err = json.Unmarshal(byteValue, &auditLog)
				if err != nil {
					panic(err)
				}

				So(auditLog.Subject, ShouldEqual, username)
				So(auditLog.Action, ShouldEqual, http.MethodDelete)
				So(auditLog.Status, ShouldEqual, http.StatusAccepted)

				deletePath := strings.ReplaceAll(path, "uploads/", digest.String())
				So(auditLog.Object, ShouldEqual, deletePath)
			})

			Convey("Test PATCH request", func() {
				path := "/v2/repo/blobs/uploads/"
				resp, err := resty.R().SetBasicAuth(username, password).Post(baseURL + path)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				loc := test.Location(baseURL, resp)
				So(loc, ShouldNotBeEmpty)
				location := resp.Header().Get("Location")
				So(location, ShouldNotBeEmpty)

				// wait until the file is populated
				byteValue, _ := io.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = io.ReadAll(auditFile)
				}

				var auditLog AuditLog
				err = json.Unmarshal(byteValue, &auditLog)
				if err != nil {
					panic(err)
				}

				So(auditLog.Subject, ShouldEqual, username)
				So(auditLog.Action, ShouldEqual, http.MethodPost)
				So(auditLog.Status, ShouldEqual, http.StatusAccepted)
				So(auditLog.Object, ShouldEqual, path)

				var buf bytes.Buffer
				chunk := []byte("this is a chunk")
				n, err := buf.Write(chunk)
				So(n, ShouldEqual, len(chunk))
				So(err, ShouldBeNil)

				// write a chunk
				contentRange := fmt.Sprintf("%d-%d", 0, len(chunk)-1)
				resp, err = resty.R().SetBasicAuth(username, password).
					SetHeader("Content-Type", "application/octet-stream").
					SetHeader("Content-Range", contentRange).SetBody(chunk).Patch(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

				// wait until the file is populated
				byteValue, _ = io.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = io.ReadAll(auditFile)
				}

				err = json.Unmarshal(byteValue, &auditLog)
				if err != nil {
					panic(err)
				}

				So(auditLog.Subject, ShouldEqual, username)
				So(auditLog.Action, ShouldEqual, http.MethodPatch)
				So(auditLog.Status, ShouldEqual, http.StatusAccepted)

				patchPath := location
				So(auditLog.Object, ShouldEqual, patchPath)
			})
		})
	})
}

func TestLogErrors(t *testing.T) {
	Convey("Get error with unknown log level", t, func() {
		So(func() { _ = log.NewLogger("invalid", "test.out") }, ShouldPanic)
	})

	Convey("Get error when opening log file", t, func() {
		dir := t.TempDir()
		logPath := path.Join(dir, "logFile")
		err := os.WriteFile(logPath, []byte{}, 0o000)
		So(err, ShouldBeNil)
		So(func() {
			_ = log.NewLogger(zerolog.DebugLevel.String(), logPath)
		}, ShouldPanic)
	})
}

func TestNewAuditLogger(t *testing.T) {
	Convey("Get error with unknown audit log level", t, func() {
		So(func() { _ = log.NewAuditLogger("invalid", "test.out") }, ShouldPanic)
	})

	Convey("Get error when opening audit file", t, func() {
		dir := t.TempDir()
		logPath := path.Join(dir, "logFile")
		err := os.WriteFile(logPath, []byte{}, 0o000)
		So(err, ShouldBeNil)
		So(func() {
			_ = log.NewAuditLogger(zerolog.DebugLevel.String(), logPath)
		}, ShouldPanic)
	})
}
