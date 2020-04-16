package utils

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

const dbName = "NvdJSON"

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

func TestConn(t *testing.T) {
	err := testSetup()
	if err != nil {
		t.Fatal("Unable to Setup Test environment")
	}

	db := Conn(DBPath)
	defer db.Close()

	if db == nil {
		t.Fatal("Unable to open db")
	}
}
func TestCreateDb(t *testing.T) {
	db := Conn(DBPath)
	defer db.Close()

	if db == nil {
		t.Fatal("Unable to open db")
	}

	hasCreated := CreateDB(dbName, db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}

	err := os.RemoveAll(DBdir)
	if err != nil {
		t.Fatal("Not able to remove Test Db file")
	}
}
