// nolint:lll
package cveinfo_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/extensions/search"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

type Result struct {
	Data Data `json:"data"`
}

type CveResult struct {
	CveData CveData `json:"data"`
}

type CveData struct {
	CveDetail CveDetail `json:"CVE"`
}

type CveDetail struct {
	Name       string      `json:"name"`
	VulDesc    string      `json:"VulDesc"`
	VulDetails []VulDetail `json:"VulDetails"`
}

type VulDetail struct {
	PkgVendor  string `json:"PkgVendor"`
	PkgName    string `json:"PkgName"`
	PkgVersion string `json:"PkgVersion"`
}

type Data struct {
	List []Pkgvendor `json:"CVEListForPkgVendor"`
}

type Pkgvendor struct {
	Name string `json:"name"`
}

const (
	BaseURL1    = "http://127.0.0.1:8081"
	SecurePort1 = "8081"
	username    = "test"
	passphrase  = "test"
)

func TestUtil(t *testing.T) {
	err := testSetup()
	if err != nil {
		t.Fatal("Unable to Setup Test environment")
	}

	err = cve.StartUpdate(dbDir, 2002, 2003, false)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}
}

func TestRepeatDownload(t *testing.T) {
	err := cve.StartUpdate(dbDir, 2002, 2003, false)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}

	err = cve.StartUpdate(dbDir, 2004, 2005, false)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}

	// Testing Invlaid Year, it should return error
	err = cve.StartUpdate(dbDir, 1980, 1981, false)
	if err == nil {
		t.Fatal("Error should not be nil")
	}

	// Not able to create a directory with invalid directory name
	err = cve.StartUpdate("/000", 1999, 2020, false)
	if err == nil {
		t.Fatal("Error should not be nil")
	}
}

func TestSearchCveId(t *testing.T) {
	db := cve.InitDB(dbPath, true)

	result := cve.QueryByCVEId(db, "CVE-1999-0001")
	if result == nil {
		t.Fatal("Not able to search CVEID")
	} else {
		if result.CveID != "CVE-1999-0001" {
			t.Fatal("Retrieved Incorrect CVEId")
		} else {
			//nolint:lll
			if result.VulDesc != "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets." {
				t.Fatal("Retrieved Incorrect Vulnerability Description")
			} else if len(result.VulDetails) == 0 {
				t.Fatal("Empty list of packages")
			}
		}
	}
	defer cveinfo.Close(db)
}

func TestSearchPkgVendor(t *testing.T) {
	db := cve.InitDB(dbPath, true)

	result := cve.QueryByPkgType("NvdPkgVendor", db, "freebsd")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer cveinfo.Close(db)
}

func TestSearchPkgName(t *testing.T) {
	db := cve.InitDB(dbPath, true)

	result := cve.QueryByPkgType("NvdPkgName", db, "bsd_os")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer cveinfo.Close(db)
}

func TestSearchPkgNameVer(t *testing.T) {
	db := cve.InitDB(dbPath, true)

	result := cve.QueryByPkgType("NvdPkgNameVer", db, "bsd_os3.1")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer cveinfo.Close(db)
}

func TestInvalidSearch(t *testing.T) {
	Convey("Test Invalid Search", t, func() {
		db := cve.InitDB(dbPath, true)
		defer cveinfo.Close(db)
		So(db, ShouldNotBeNil)

		result := cve.QueryByPkgType("NvdPkgNameVer", db, "")
		So(len(result), ShouldEqual, 0)

		result = cve.QueryByPkgType("NvdPkgName", db, "")
		So(len(result), ShouldEqual, 0)

		result = cve.QueryByPkgType("NvdPkgName", db, "")
		So(len(result), ShouldEqual, 0)

		result = cve.QueryByPkgType("NvdInvalid", db, "freebsd")
		So(len(result), ShouldEqual, 0)

		result = cve.QueryByPkgType("", db, "freebsd")
		So(len(result), ShouldEqual, 0)

		cveresult := cve.QueryByCVEId(db, "")
		So(len(cveresult.VulDetails), ShouldEqual, 0)
	})
}
func TestServerResponse(t *testing.T) {
	Convey("Make a new controller", t, func() {
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
			_ = cveinfo.Close(search.ResConfig.DB)
		}()

		// Test PkgVendor, PkgName and PkgNameVer
		resp, _ := resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForPkgVendor(text:\"openbsd\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveids Result
		err := json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldNotBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForPkgName(text:\"bsd_os\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldNotBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForPkgNameVer(text:\"bsd_os3.1\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldNotBeZeroValue)

		// Test CveId
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVE(text:\"CVE-1999-0001\"){name%20VulDesc%20VulDetails{PkgVendor%20PkgName%20PkgVersion}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveresult CveResult
		err = json.Unmarshal(resp.Body(), &cveresult)
		So(err, ShouldBeNil)
		So(cveresult.CveData.CveDetail.Name, ShouldEqual, "CVE-1999-0001")
		So(len(cveresult.CveData.CveDetail.VulDetails), ShouldNotEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(repo:\"zot-test\"){tag%20CVEIdList{name}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(repo:\"zot-test\"){tag%20CVEIdList{name}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Testing Invalid Data
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForPkgVendor(text:\"\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForPkgName(text:\"\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldBeZeroValue)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForPkgNameVer(text:\"\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldBeZeroValue)

		// Test CveId
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVE(text:\"\"){name%20VulDesc%20VulDetails{PkgVendor%20PkgName%20PkgVersion}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveresult)
		So(err, ShouldBeNil)
		So(len(cveresult.CveData.CveDetail.VulDetails), ShouldEqual, 0)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(repo:\"zo-test\"){tag%20CVEIdList{name}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageListForCVE(text:\"CVE-2002-1119\"){name%20tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={ImageListForCVE(text:\"CVE-202-001\"){name%20tags}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImageTag(repo:\"zot-test\",tag:\"1.0.0\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImageTag(repo:\"zot-est\",tag:\"1.0.0\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Test Invalid URL
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEidSearch(text:\"\"){name%20VulDesc%20VulDetails{PkgVendor%20PkgName%20PkgVersion}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldNotEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVE(text:\"\")")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldNotEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldNotEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CVEListForImage(repo:\"zot-test\"){tg%20CVEIdList{name}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldNotEqual, 200)
	})
}

func TestRemoveData(t *testing.T) {
	err := os.RemoveAll(dbDir)
	if err != nil {
		t.Fatal("Unable to remove test data")
	}
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
