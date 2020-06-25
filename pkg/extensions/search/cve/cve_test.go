package cveinfo_test

import (
	"io/ioutil"
	"os"
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

func TestDownloadDB(t *testing.T) {
	Convey("Download DB", t, func() {
		err := testSetup()
		So(err, ShouldBeNil)
		err = cveinfo.UpdateCVEDb(dbDir, cve.Log)
		So(err, ShouldBeNil)
		os.RemoveAll(dbDir)
	})
}
