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
	CveDetail CveDetail `json:"CveIdSearch"`
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
	List []Pkgvendor `json:"PkgVendor"`
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

	err = cve.StartUpdate(dbDir, 2002, 2003)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}
}

func TestRepeatDownload(t *testing.T) {
	err := cve.StartUpdate(dbDir, 2002, 2003)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}

	// Testing Invlaid Year, it should return error
	err = cve.StartUpdate(dbDir, 1980, 1981)
	if err == nil {
		t.Fatal("Error should not be nil")
	}
}

func TestSearchCveId(t *testing.T) {
	db := cve.InitDB(dbPath)

	result := cve.SearchByCVEId(db, "CVE-1999-0001")
	if result == nil {
		t.Fatal("Not able to search CVEID")
	} else {
		if result.CveID != "CVE-1999-0001" {
			t.Fatal("Retrieved Incorrect CVEId")
		} else {
			//nolint : lll
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
	db := cve.InitDB(dbPath)

	result := cve.SearchByPkgType("NvdPkgVendor", db, "freebsd")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer cveinfo.Close(db)
}

func TestSearchPkgName(t *testing.T) {
	db := cve.InitDB(dbPath)

	result := cve.SearchByPkgType("NvdPkgName", db, "bsd_os")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer cveinfo.Close(db)
}

func TestSearchPkgNameVer(t *testing.T) {
	db := cve.InitDB(dbPath)

	result := cve.SearchByPkgType("NvdPkgNameVer", db, "bsd_os3.1")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer cveinfo.Close(db)
}

func TestInvalidSearch(t *testing.T) {
	Convey("Test Invalid Search", t, func() {
		db := cve.InitDB(dbPath)
		defer cveinfo.Close(db)
		So(db, ShouldNotBeNil)

		result := cve.SearchByPkgType("NvdPkgNameVer", db, "")
		So(len(result), ShouldEqual, 0)

		result = cve.SearchByPkgType("NvdPkgName", db, "")
		So(len(result), ShouldEqual, 0)

		result = cve.SearchByPkgType("NvdPkgName", db, "")
		So(len(result), ShouldEqual, 0)

		result = cve.SearchByPkgType("NvdInvalid", db, "freebsd")
		So(len(result), ShouldEqual, 0)

		result = cve.SearchByPkgType("", db, "freebsd")
		So(len(result), ShouldEqual, 0)

		cveresult := cve.SearchByCVEId(db, "")
		So(len(cveresult.VulDetails), ShouldEqual, 0)
	})
}

func makeHtpasswdFile() string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte("test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n")
	if err := ioutil.WriteFile(f.Name(), content, 0644); err != nil {
		panic(err)
	}

	return f.Name()
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
		// nolint (lll)
		resp, _ := resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={PkgVendor(text:\"openbsd\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveids Result
		err := json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldNotBeZeroValue)

		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={PkgName(text:\"bsd_os\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldNotBeZeroValue)

		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={PkgNameVer(text:\"bsd_os3.1\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldNotBeZeroValue)

		// Test CveId
		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CveIdSearch(text:\"CVE-1999-0001\"){name%20VulDesc%20VulDetails{PkgVendor%20PkgName%20PkgVersion}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cveresult CveResult
		err = json.Unmarshal(resp.Body(), &cveresult)
		So(err, ShouldBeNil)
		So(cveresult.CveData.CveDetail.Name, ShouldEqual, "CVE-1999-0001")
		So(len(cveresult.CveData.CveDetail.VulDetails), ShouldNotEqual, 0)

		// Testing Invalid Dataß
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={PkgVendor(text:\"\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldBeZeroValue)

		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={PkgName(text:\"\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldBeZeroValue)

		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={PkgNameVer(text:\"\"){name}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveids)
		So(err, ShouldBeNil)
		So(len(cveids.Data.List), ShouldBeZeroValue)

		// Test CveId
		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CveIdSearch(text:\"\"){name%20VulDesc%20VulDetails{PkgVendor%20PkgName%20PkgVersion}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &cveresult)
		So(err, ShouldBeNil)
		So(len(cveresult.CveData.CveDetail.VulDetails), ShouldEqual, 0)

		// Test Invalid URL
		// nolint (lll)
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CveIdearch(text:\"\"){name%20VulDesc%20VulDetails{PkgVendor%20PkgName%20PkgVersion}}}")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldNotEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={CveIdearch(text:\"\")")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldNotEqual, 200)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/query?query={}")
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
