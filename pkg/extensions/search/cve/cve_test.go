package cveinfo_test

import (
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/log"
	. "github.com/smartystreets/goconvey/convey"
)

const dbName = "NvdJSON"

// nolint:gochecknoglobals
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

	err = copyFiles("./testdata", dir)
	if err != nil {
		return err
	}

	dbDir = dir

	dbPath = path.Join(dbDir, "search.db")

	cve = &cveinfo.CveInfo{Log: log.NewLogger("debug", ""), RootDir: dbDir}

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

func TestConn(t *testing.T) {
	err := testSetup()
	if err != nil {
		t.Fatal("Unable to Setup Test environment")
	}

	db := cve.Connect(dbPath, false)
	defer cveinfo.Close(db)

	if db == nil {
		t.Fatal("Unable to open db")
	}
}

func TestInvalidPathConn(t *testing.T) {
	Convey("Test usage", t, func() {
		db := cve.Connect(".", false)
		So(db, ShouldBeNil)
	})
}

func TestInvalidDb(t *testing.T) {
	Convey("Test usage", t, func() {
		db := cve.Connect(dbPath, false)
		defer cveinfo.Close(db)
		So(db, ShouldNotBeNil)
		hasCreated := cve.CreateBucket("", db)
		So(hasCreated, ShouldEqual, false)
	})
}

func TestCreateDb(t *testing.T) {
	db := cve.Connect(dbPath, false)
	defer cveinfo.Close(db)

	if db == nil {
		t.Fatal("Unable to open db")
	}

	hasCreated := cve.CreateBucket(dbName, db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}
}

func TestImageAnnotations(t *testing.T) {
	Convey("Image Annotations", t, func() {
		pkgList, err := cve.GetImageAnnotations("zot-test")
		So(err, ShouldBeNil)
		So(len(pkgList), ShouldNotBeZeroValue)
	})

	Convey("Tag Not Specified", t, func() {
		_, err := cve.GetImageAnnotations("zot-test7")
		So(err, ShouldBeNil)
	})

	Convey("Invalid Image Repo Annotations", t, func() {
		_, err := cve.GetImageAnnotations("zot-tes")
		So(err, ShouldNotBeNil)
	})

	Convey("Image Repo without index.json", t, func() {
		_, err := cve.GetImageAnnotations("zot-test1")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid index.json Image Annotations", t, func() {
		_, err := cve.GetImageAnnotations("zot-test2")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid Blob/Sha256 File Name", t, func() {
		_, err := cve.GetImageAnnotations("zot-test3")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid Blob/Sha256 File Image Annotations", t, func() {
		_, err := cve.GetImageAnnotations("zot-test6")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid Blob/Sha256 Layer File Image Annotations", t, func() {
		_, err := cve.GetImageAnnotations("zot-test4")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid Label", t, func() {
		_, err := cve.GetImageAnnotations("zot-test5")
		So(err, ShouldNotBeNil)
	})

	err := os.RemoveAll(dbDir)
	if err != nil {
		t.Fatal("Unable to remove test data")
	}
}
