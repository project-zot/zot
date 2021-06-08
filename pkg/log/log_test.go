// +build extended

package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/api/config"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	BaseURL               = "http://127.0.0.1:8086"
	SecurePort            = "8086"
	username              = "test"
	passphrase            = "test"
	ServerCert            = "../../test/data/server.cert"
	AuthorizedNamespace   = "everyone/isallowed"
	UnauthorizedNamespace = "fortknox/notallowed"
)

type AuditLog struct {
	Level    string `json:"level"`
	ClientIP string `json:"clientIP"`
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Object   string `json:"object"`
	Status   int    `json:"status"`
	Time     string `json:"time"`
	Message  string `json:"message"`
}

func makeHtpasswdFile() string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte("test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n")
	if err := ioutil.WriteFile(f.Name(), content, 0600); err != nil {
		panic(err)
	}

	return f.Name()
}

func copyFiles(sourceDir string, destDir string) error {
	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return err
	}

	files, err := ioutil.ReadDir(sourceDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		sourceFilePath := path.Join(sourceDir, file.Name())
		destFilePath := path.Join(destDir, file.Name())

		if file.IsDir() {
			if err = copyFiles(sourceFilePath, destFilePath); err != nil {
				return err
			}
		} else {
			sourceFile, err := os.Open(sourceFilePath)
			if err != nil {
				return err
			}
			defer sourceFile.Close()

			destFile, err := os.Create(destFilePath)
			if err != nil {
				return err
			}
			defer destFile.Close()

			if _, err = io.Copy(destFile, sourceFile); err != nil {
				return err
			}
		}
	}

	return nil
}

func Location(baseURL string, resp *resty.Response) string {
	// For some API responses, the Location header is set and is supposed to
	// indicate an opaque value. However, it is not clear if this value is an
	// absolute URL (https://server:port/v2/...) or just a path (/v2/...)
	// zot implements the latter as per the spec, but some registries appear to
	// return the former - this needs to be clarified
	loc := resp.Header().Get("Location")
	if loc[0] == '/' {
		return baseURL + loc
	}

	return loc
}

func TestAuditLogMessages(t *testing.T) {
	Convey("Make a new controller", t, func() {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		err = copyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}

		conf := config.New()

		outputPath := dir + "/zot.log"
		auditPath := dir + "/zot-audit.log"
		conf.Log = &config.LogConfig{Level: "debug", Output: outputPath, Audit: auditPath}

		conf.HTTP.Port = SecurePort

		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		c := api.NewController(conf)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		Convey("Open auditLog file", func() {
			auditFile, err := os.Open(auditPath)
			if err != nil {
				t.Log("Cannot open file")
				panic(err)
			}
			defer auditFile.Close()

			Convey("Test GET request", func() {
				resp, err := resty.R().SetBasicAuth(username, passphrase).
					Get(BaseURL + "/v2/")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				byteValue, _ := ioutil.ReadAll(auditFile)
				So(len(byteValue), ShouldEqual, 0)
			})

			Convey("Test POST request", func() {
				path := "/v2/" + AuthorizedNamespace + "/blobs/uploads/"
				resp, err := resty.R().SetBasicAuth(username, passphrase).
					Post(BaseURL + path)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

				// wait until the file is populated
				byteValue, _ := ioutil.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = ioutil.ReadAll(auditFile)
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
				resp, err := resty.R().SetBasicAuth(username, passphrase).Post(BaseURL + path)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				loc := Location(BaseURL, resp)
				So(loc, ShouldNotBeEmpty)
				location := resp.Header().Get("Location")
				So(location, ShouldNotBeEmpty)

				// wait until the file is populated
				byteValue, _ := ioutil.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = ioutil.ReadAll(auditFile)
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
					SetBasicAuth(username, passphrase).
					SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
				blobLoc := Location(BaseURL, resp)
				So(blobLoc, ShouldNotBeEmpty)
				So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

				// wait until the file is populated
				byteValue, _ = ioutil.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = ioutil.ReadAll(auditFile)
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
				resp, err = resty.R().SetBasicAuth(username, passphrase).Delete(blobLoc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				So(resp.Header().Get("Content-Length"), ShouldEqual, "0")

				// wait until the file is populated
				byteValue, _ = ioutil.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = ioutil.ReadAll(auditFile)
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
				resp, err := resty.R().SetBasicAuth(username, passphrase).Post(BaseURL + path)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				loc := Location(BaseURL, resp)
				So(loc, ShouldNotBeEmpty)
				location := resp.Header().Get("Location")
				So(location, ShouldNotBeEmpty)

				// wait until the file is populated
				byteValue, _ := ioutil.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = ioutil.ReadAll(auditFile)
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
				resp, err = resty.R().SetBasicAuth(username, passphrase).
					SetHeader("Content-Type", "application/octet-stream").
					SetHeader("Content-Range", contentRange).SetBody(chunk).Patch(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

				// wait until the file is populated
				byteValue, _ = ioutil.ReadAll(auditFile)
				for {
					if len(byteValue) != 0 {
						break
					}
					time.Sleep(100 * time.Millisecond)
					byteValue, _ = ioutil.ReadAll(auditFile)
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
