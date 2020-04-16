package utils_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/anuvu/zot/pkg/extensions/search/utils"
)

// nolint (gochecknoglobals)
var (
	DBPath = ""
	DBdir  = ""
)

func testSetup() error {
	dir, err := ioutil.TempDir("", "util_test")
	if err != nil {
		return err
	}

	DBdir = dir

	DBPath = path.Join(DBdir, "Test.db")

	return nil
}

func TestUtil(t *testing.T) {
	err := testSetup()
	if err != nil {
		t.Fatal("Unable to Setup Test environment")
	}

	db := utils.InitSearch(DBPath)
	defer db.Close()

	if db == nil {
		t.Fatal("Unable to open db")
	}

	err = utils.GetNvdData(DBdir, 2002, 2003, db)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}
}

func TestSearchCveId(t *testing.T) {
	db := utils.InitSearch(DBPath)

	result := utils.SearchByCVEId(db, "CVE-1999-0001")
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
	defer db.Close()
}

func TestSearchPkgVendor(t *testing.T) {
	db := utils.InitSearch(DBPath)

	result := utils.SearchByPkgType("NvdPkgVendor", db, "freebsd")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer db.Close()
}

func TestSearchPkgName(t *testing.T) {
	db := utils.InitSearch(DBPath)

	result := utils.SearchByPkgType("NvdPkgName", db, "bsd_os")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer db.Close()
}

func TestSearchPkgNameVer(t *testing.T) {
	db := utils.InitSearch(DBPath)

	result := utils.SearchByPkgType("NvdPkgNameVer", db, "bsd_os3.1")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}

	defer db.Close()
}

func TestRemoveData(t *testing.T) {
	err := os.RemoveAll(DBdir)
	if err != nil {
		t.Fatal("Unable to remove test data")
	}
}
