// nolint: lll
package cveinfo_test

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/log"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

// nolint:gochecknoglobals
var (
	cve   *cveinfo.CveInfo
	dbDir string
)

const (
	BaseURL1    = "http://127.0.0.1:8085"
	SecurePort1 = "8085"
	username    = "test"
	passphrase  = "test"
)

type CveResult struct {
	ImgList ImgList `json:"data"`
}

type ImgList struct {
	CVEResultForImage CVEResultForImage `json:"CVEListForImage"`
}

type CVEResultForImage struct {
	Tag     string `json:"Tag"`
	CVEList []CVE  `json:"CVEList"`
}

type CVE struct {
	ID          string `json:"Id"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
}

func testSetup() error {
	dir, err := ioutil.TempDir("", "util_test")
	if err != nil {
		return err
	}

	cve = &cveinfo.CveInfo{Log: log.NewLogger("debug", "")}

	dbDir = dir

	err = copyFiles("./testdata", dbDir)
	if err != nil {
		return err
	}

	return nil
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

func TestDownloadDB(t *testing.T) {
	Convey("Download DB", t, func() {
		err := testSetup()
		So(err, ShouldBeNil)
		err = cveinfo.UpdateCVEDb(dbDir, cve.Log, 1, true)
		So(err, ShouldBeNil)
	})
}

func TestCVESearch(t *testing.T) {
	Convey("Test image vulenrability scanning", t, func() {
		config := api.NewConfig()
		config.HTTP.Port = SecurePort1
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		c := api.NewController(config)
		defer os.RemoveAll(dbDir)
		c.Config.Storage.RootDirectory = dbDir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveResult CveResult
		err = json.Unmarshal(resp.Body(), &cveResult)
		So(err, ShouldBeNil)
		So(len(cveResult.ImgList.CVEResultForImage.CVEList), ShouldNotBeZeroValue)

		id := cveResult.ImgList.CVEResultForImage.CVEList[0].ID

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageListForCVE(id:\"" + id + "\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-squashfs-test:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveSquashFSResult CveResult
		err = json.Unmarshal(resp.Body(), &cveSquashFSResult)
		So(err, ShouldBeNil)
		So(len(cveSquashFSResult.ImgList.CVEResultForImage.CVEList), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-squashfs-noindex:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-squashfs-invalid-index:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-squashfs-noblobs:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-squashfs-invalid-blob:commit-aaa7c6e7-squashfs\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-squashfs-test\"){Tag%20CVEList{Id%20Description%20Severity%20PackageList{Name%20InstalledVersion%20FixedVersion}}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"cntos\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageListForCVE(id:\"CVE-201-20482\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test\"){Tag%20CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){Tag}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.1\"){CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){CVEList{Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){CVEList{Id%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){CVEList{Id%20Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){CVEList{Id}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){CVEList{Description}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Testing Invalid Search URL
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(image:\"zot-test:1.0.0\"){Ta%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageListForCVE(tet:\"CVE-2018-20482\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageistForCVE(id:\"CVE-2018-20482\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageListForCVE(id:\"CVE-2018-20482\"){ame%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(reo:\"zot-test:1.0.0\"){Tag%20CVEList{Id%20Description%20Severity}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)
	})
}
