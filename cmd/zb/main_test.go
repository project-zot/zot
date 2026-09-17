package main //nolint:testpackage // separate binary

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

var (
	errSomethingElse     = errors.New("something else")
	errIOTimeout         = errors.New("i/o timeout")
	errDeadlineExceeded  = errors.New("context deadline exceeded")
	errClosedConn        = errors.New("write tcp: use of closed network connection")
	errUnexpectedStatus  = errors.New("unexpected status")
	errConnectionRefused = errors.New("connection refused")
)

func TestIntegration(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		c := api.NewController(conf)
		So(c, ShouldNotBeNil)

		cl := NewPerfRootCmd()
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}

func TestMaxTimeoutFailuresFlag(t *testing.T) {
	Convey("max-timeout-failures flag is registered with default 0", t, func() {
		cl := NewPerfRootCmd()
		flag := cl.Flags().Lookup("max-timeout-failures")
		So(flag, ShouldNotBeNil)
		So(flag.DefValue, ShouldEqual, "0")
	})
}

func TestCreateWorkDir(t *testing.T) {
	Convey("with an explicit base dir, blobs live in a zb-* subdir and only that subdir is removed", t, func() {
		baseDir := t.TempDir()
		userFile := filepath.Join(baseDir, "keep.txt")
		So(os.WriteFile(userFile, []byte("keep"), defaultFilePerms), ShouldBeNil)

		workDir, err := createWorkDir(baseDir)
		So(err, ShouldBeNil)
		So(filepath.Dir(workDir), ShouldEqual, baseDir)
		So(strings.HasPrefix(filepath.Base(workDir), "zb-"), ShouldBeTrue)

		So(setup(workDir, []int{smallBlob}), ShouldBeNil)
		_, err = os.Stat(filepath.Join(workDir, "1048576.blob"))
		So(err, ShouldBeNil)

		teardown(workDir)

		_, err = os.Stat(workDir)
		So(os.IsNotExist(err), ShouldBeTrue)
		// user-provided directory and its unrelated content are left untouched
		_, err = os.Stat(userFile)
		So(err, ShouldBeNil)
	})

	Convey("with no base dir, the zb-* subdir is created under the current working dir", t, func() {
		cwd := t.TempDir()
		t.Chdir(cwd)

		workDir, err := createWorkDir("")
		So(err, ShouldBeNil)

		realCwd, err := filepath.EvalSymlinks(cwd)
		So(err, ShouldBeNil)
		realWorkDir, err := filepath.EvalSymlinks(workDir)
		So(err, ShouldBeNil)
		So(filepath.Dir(realWorkDir), ShouldEqual, realCwd)
		So(strings.HasPrefix(filepath.Base(workDir), "zb-"), ShouldBeTrue)

		teardown(workDir)

		entries, err := os.ReadDir(cwd)
		So(err, ShouldBeNil)
		So(entries, ShouldBeEmpty)
	})

	Convey("a missing base dir is created", t, func() {
		baseDir := filepath.Join(t.TempDir(), "nested", "dir")

		workDir, err := createWorkDir(baseDir)
		So(err, ShouldBeNil)
		So(filepath.Dir(workDir), ShouldEqual, baseDir)

		teardown(workDir)
	})

	if os.Getuid() == 0 {
		// root ignores directory permission bits, so the read-only dir would not fail
		return
	}

	Convey("setup returns an error instead of exiting so the caller can clean up", t, func() {
		workDir, err := createWorkDir(t.TempDir())
		So(err, ShouldBeNil)

		// make the work dir read-only so blob creation fails
		So(os.Chmod(workDir, 0o500), ShouldBeNil)

		err = setup(workDir, []int{smallBlob})
		So(err, ShouldNotBeNil)

		So(os.Chmod(workDir, defaultDirPerms), ShouldBeNil)
		teardown(workDir)

		_, err = os.Stat(workDir)
		So(os.IsNotExist(err), ShouldBeTrue)
	})
}

func TestShouldFailRun(t *testing.T) {
	Convey("run fails on hard failures or timeout budget overrun", t, func() {
		So(shouldFailRun(0, 0, 0), ShouldBeFalse)
		So(shouldFailRun(0, 1, 0), ShouldBeTrue)
		So(shouldFailRun(0, 1, 1), ShouldBeFalse)
		So(shouldFailRun(0, 2, 1), ShouldBeTrue)
		So(shouldFailRun(1, 0, 5), ShouldBeTrue)
		So(shouldFailRun(1, 1, 1), ShouldBeTrue)
		So(shouldFailRun(0, 0, 5), ShouldBeFalse)
	})
}

func TestIsTimeoutError(t *testing.T) {
	Convey("timeout error classification", t, func() {
		So(isTimeoutError(nil), ShouldBeFalse)
		So(isTimeoutError(errSomethingElse), ShouldBeFalse)
		So(isTimeoutError(errIOTimeout), ShouldBeTrue)
		So(isTimeoutError(errDeadlineExceeded), ShouldBeTrue)
		So(isTimeoutError(errClosedConn), ShouldBeTrue)
		So(isTimeoutError(&timeoutNetError{}), ShouldBeTrue)
	})
}

type timeoutNetError struct{}

func (e *timeoutNetError) Error() string   { return "read tcp: i/o timeout" }
func (e *timeoutNetError) Timeout() bool   { return true }
func (e *timeoutNetError) Temporary() bool { return true }

var _ net.Error = (*timeoutNetError)(nil)

func TestUpdateStatsTimeoutCount(t *testing.T) {
	Convey("timeoutErrorCount increments only for timeout errors", t, func() {
		summary := newStatsSummary("test")

		updateStats(&summary, statsRecord{
			latency:    time.Second,
			isConnFail: true,
			err:        errIOTimeout,
		})
		updateStats(&summary, statsRecord{
			latency: time.Second,
			isErr:   true,
			err:     errUnexpectedStatus,
		})
		updateStats(&summary, statsRecord{
			latency:    time.Second,
			isConnFail: true,
			err:        errConnectionRefused,
		})

		So(summary.errorCount, ShouldEqual, 3)
		So(summary.timeoutErrorCount, ShouldEqual, 1)
	})
}
