package common_test

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"

	tcommon "zotregistry.dev/zot/pkg/test/common"
)

var ErrTestError = errors.New("ErrTestError")

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := tcommon.CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir := t.TempDir()

		err := tcommon.CopyFiles("../../../test/data", dir)
		So(err, ShouldBeNil)

		err = tcommon.CopyFiles(dir, "/etc/passwd")
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir does not have read permissions", t, func() {
		dir := t.TempDir()

		err := os.Chmod(dir, 0o300)
		So(err, ShouldBeNil)

		err = tcommon.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a subfolder that does not have read permissions", t, func() {
		dir := t.TempDir()

		sdir := "subdir"
		err := os.Mkdir(path.Join(dir, sdir), 0o300)
		So(err, ShouldBeNil)

		err = tcommon.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a file that does not have read permissions", t, func() {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := os.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(filePath, 0o300)
		So(err, ShouldBeNil)

		err = tcommon.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir contains a folder starting with invalid characters", t, func() {
		srcDir := t.TempDir()
		dstDir := t.TempDir()

		err := os.MkdirAll(path.Join(srcDir, "_trivy", "db"), 0o755)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(path.Join(srcDir, "test-index"), 0o755)
		if err != nil {
			panic(err)
		}

		filePathTrivy := path.Join(srcDir, "_trivy", "db", "trivy.db")
		err = os.WriteFile(filePathTrivy, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		content, err := json.Marshal(index)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(srcDir, "test-index", "index.json"), content, 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = tcommon.CopyFiles(srcDir, dstDir)
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(dstDir, "_trivy", "db", "trivy.db"))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(path.Join(dstDir, "test-index", "index.json"))
		So(err, ShouldBeNil)
	})
}

func TestCopyFile(t *testing.T) {
	Convey("destFilePath does not exist", t, func() {
		err := tcommon.CopyFile("/path/to/srcFile", "~/path/to/some/unexisting/destDir/file")
		So(err, ShouldNotBeNil)
	})

	Convey("sourceFile does not exist", t, func() {
		err := tcommon.CopyFile("/path/to/some/unexisting/file", path.Join(t.TempDir(), "destFile.txt"))
		So(err, ShouldNotBeNil)
	})
}

func TestReadLogFileAndSearchString(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = tcommon.ReadLogFileAndSearchString("invalidPath",
			"cve-db update completed, next update scheduled after interval", 1*time.Second)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := tcommon.ReadLogFileAndSearchString(logPath, "invalid string", time.Microsecond)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestReadLogFileAndCountStringOccurence(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	_, err = logFile.WriteString("line1\n line2\n line3 line1 line2\n line1")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = tcommon.ReadLogFileAndCountStringOccurence("invalidPath",
			"cve-db update completed, next update scheduled after interval", 1*time.Second, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := tcommon.ReadLogFileAndCountStringOccurence(logPath, "invalid string", time.Microsecond, 1)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Count occurrence working", t, func() {
		ok, err := tcommon.ReadLogFileAndCountStringOccurence(logPath, "line1", 90*time.Second, 3)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})
}

func TestCopyTestKeysAndCerts(t *testing.T) {
	Convey("CopyTestKeysAndCerts", t, func() {
		// ------- Make test files unreadable -------
		dir := t.TempDir()
		file := filepath.Join(dir, "ca.crt")

		_, err := os.Create(file)
		So(err, ShouldBeNil)

		err = os.Chmod(file, 0o000)
		So(err, ShouldBeNil)

		err = tcommon.CopyTestKeysAndCerts(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(file, 0o777)
		So(err, ShouldBeNil)

		// ------- Copy fails -------

		err = os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		err = tcommon.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o777)
		So(err, ShouldBeNil)

		// ------- Folder creation fails -------

		file = filepath.Join(dir, "a-file.file")
		_, err = os.Create(file)
		So(err, ShouldBeNil)

		_, err = os.Stat(file)
		So(err, ShouldBeNil)

		err = tcommon.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)

		// ----- /test/data doesn't exist ------
		workDir, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(workDir) }()

		dir = t.TempDir()
		file = filepath.Join(dir, "go.mod")
		_, err = os.Create(file)
		So(err, ShouldBeNil)
		_, err = os.Stat(file)
		So(err, ShouldBeNil)
		err = os.Chdir(dir)
		So(err, ShouldBeNil)
		err = tcommon.CopyTestKeysAndCerts(dir)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "CopyFiles os.Stat failed")

		// --- GetProjectRootDir call fails -----
		err = os.Chdir(os.TempDir())
		So(err, ShouldBeNil)
		err = tcommon.CopyTestKeysAndCerts(os.TempDir())
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, tcommon.ErrNoGoModFileFound)
	})
}

func TestGetProjectRootDir(t *testing.T) {
	Convey("GetProjectRootDir", t, func() {
		path, err := tcommon.GetProjectRootDir()
		So(err, ShouldBeNil)
		So(len(path), ShouldBeGreaterThan, 0)
	})
	Convey("GetProjectRootDir negative testing", t, func() {
		workDir, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(workDir) }()

		err = os.Chdir(os.TempDir())
		So(err, ShouldBeNil)
		path, err := tcommon.GetProjectRootDir()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, tcommon.ErrNoGoModFileFound)
		So(path, ShouldBeZeroValue)
	})
}

func TestGetCredString(t *testing.T) {
	Convey("GetCredString panics", t, func() {
		passwordSize := 100
		pass := make([]byte, passwordSize)
		for i := 0; i < passwordSize; i++ {
			pass[i] = 'Y'
		}
		f := func() { tcommon.GetCredString("testUser", string(pass)) }
		So(f, ShouldPanicWith, bcrypt.ErrPasswordTooLong)
	})
}
