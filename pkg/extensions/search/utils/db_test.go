package utils

import (
	"testing"
)

const filePath = "./testdata/db/Test.db"
const dbName = "NvdJSON"

func TestConn(t *testing.T) {
	db := Conn(filePath)
	if db == nil {
		t.Fatal("Unable to open db")
	}
	defer db.Close()
}

func TestCreateDb(t *testing.T) {
	db := Conn(filePath)
	if db == nil {
		t.Fatal("Unable to open db")
	}

	hasCreated := CreateDB(dbName, db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}

	hasCreated = CreateDB("NvdPkgVendor", db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}

	hasCreated = CreateDB("NvdPkgName", db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}
	hasCreated = CreateDB("NvdPkgNameVer", db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}

	hasCreated = CreateDB("NvdMeta", db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}
	defer db.Close()
}
func TestUpdate(t *testing.T) {
	db := Conn(filePath)
	if db == nil {
		t.Fatal("Unable to open db")
	}
	// Trying to Update NVD Packages
	pkgvendor := make(map[string][]CVEId)
	pkgname := make(map[string][]CVEId)
	pkgnamever := make(map[string][]CVEId)
	cveidlist := []CVEId{}
	cveid := CVEId{}
	cveid.Name = "CVE-2021-001"
	cveidlist = append(cveidlist, cveid)
	pkgvendor["TestVendor"] = cveidlist
	err := updateNVDPkg("NvdPkgVendor", pkgvendor, db)
	if err != nil {
		t.Fatal("Unable to Update the Vendor bucket")
	}

	pkgname["TestName"] = cveidlist
	err = updateNVDPkg("NvdPkgName", pkgname, db)
	if err != nil {
		t.Fatal("Unable to Update the Package Name bucket")
	}

	pkgnamever["TestNameV1"] = cveidlist
	err = updateNVDPkg("NvdPkgNameVer", pkgnamever, db)
	if err != nil {
		t.Fatal("Unable to Update the Package Name-Version bucket")
	}
	defer db.Close()
}

func TestSearch(t *testing.T) {
	db := Conn(filePath)
	// Trying to Search By PkgVendor
	ans := SearchByPkgType("NvdPkgVendor", db, "TestVendor")
	if len(ans) == 0 {
		t.Fatal("Package Name not found")
	}
	if ans[0].Name != "CVE-2021-001" {
		t.Fatal("Invalid CVEId corresponding to given Package")
	}

	// Trying to Search By PkgName
	ans = SearchByPkgType("NvdPkgName", db, "TestName")
	if len(ans) == 0 {
		t.Fatal("Package Name not found")
	}
	if ans[0].Name != "CVE-2021-001" {
		t.Fatal("Invalid CVEId corresponding to given Package")
	}

	// Trying to Search By PkgNameVersion

	ans = SearchByPkgType("NvdPkgNameVer", db, "TestNameV1")
	if len(ans) == 0 {
		t.Fatal("Package Name and Version not found")
	}
	if ans[0].Name != "CVE-2021-001" {
		t.Fatal("Invalid CVEId corresponding to given Package")
	}
}
