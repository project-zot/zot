package cveinfo_test

/*import (
	"io"
	"io/ioutil"
	"os"
	"path"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/log"
)

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
}*/
