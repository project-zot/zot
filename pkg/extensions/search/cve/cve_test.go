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

// nolint:gochecknoglobals
var (
	cve   *cveinfo.CveInfo
	dbDir string
)

func testSetup() error {
	dir, err := ioutil.TempDir("", "util_test")
	if err != nil {
		return err
	}

	cve = &cveinfo.CveInfo{Log: log.NewLogger("debug", "")}

	dbDir = dir

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

func TestDownloadDB(t *testing.T) {
	Convey("Download DB", t, func() {
		err := testSetup()
		So(err, ShouldBeNil)
		err = cveinfo.UpdateCVEDb(dbDir, cve.Log, 1, true)
		So(err, ShouldBeNil)
	})
}
