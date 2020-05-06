package cveinfo_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	. "github.com/smartystreets/goconvey/convey"
)

const dbName = "NvdJSON"

// nolint (gochecknoglobals)
var (
	dbPath = ""
	dbDir  = ""
	cve    *cveinfo.CveInfo
)

func testSetup() error {
	dir, err := ioutil.TempDir("", "util_test")
	if err != nil {
		return err
	}

	dbDir = dir

	dbPath = path.Join(dbDir, "search.db")

	cve = &cveinfo.CveInfo{}

	return nil
}

func TestConn(t *testing.T) {
	err := testSetup()
	if err != nil {
		t.Fatal("Unable to Setup Test environment")
	}

	db := cve.Connect(dbPath)
	defer cveinfo.Close(db)

	if db == nil {
		t.Fatal("Unable to open db")
	}
}

func TestInvalidPathConn(t *testing.T) {
	Convey("Test usage", t, func() {
		db := cve.Connect(".")
		So(db, ShouldBeNil)
	})
}

func TestInvalidDb(t *testing.T) {
	Convey("Test usage", t, func() {
		db := cve.Connect(dbPath)
		defer cveinfo.Close(db)
		So(db, ShouldNotBeNil)
		hasCreated := cve.CreateBucket("", db)
		So(hasCreated, ShouldEqual, false)
	})
}

func TestCreateDb(t *testing.T) {
	db := cve.Connect(dbPath)
	defer cveinfo.Close(db)

	if db == nil {
		t.Fatal("Unable to open db")
	}

	hasCreated := cve.CreateBucket(dbName, db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}

	err := os.RemoveAll(dbDir)
	if err != nil {
		t.Fatal("Not able to remove Test Db file")
	}
}
