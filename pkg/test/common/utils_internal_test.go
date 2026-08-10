package common

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestWaitForKernelChosenPortBaseURLTimeout(t *testing.T) {
	Convey("panics when the kernel-chosen port never appears", t, func() {
		logPath := path.Join(t.TempDir(), "missing-zot-log.txt")
		timeout := 50 * time.Millisecond

		So(func() {
			waitForKernelChosenPortBaseURL(logPath, timeout)
		}, ShouldPanicWith, fmt.Sprintf(
			"timed out after %s waiting for kernel chosen port in %s",
			timeout, logPath,
		))
	})

	Convey("panics when log lines never yield a positive port", t, func() {
		logPath := path.Join(t.TempDir(), "zot-log.txt")
		content := "" +
			`{"level":"info","message":"unrelated"}` + "\n" +
			`{"level":"info","message":"port is unspecified, listening on kernel chosen port","port":0}` + "\n" +
			`{"level":"info","message":"port is unspecified, listening on kernel chosen port","port":"bad"}` + "\n"
		So(os.WriteFile(logPath, []byte(content), 0o600), ShouldBeNil)

		timeout := 50 * time.Millisecond
		So(func() {
			waitForKernelChosenPortBaseURL(logPath, timeout)
		}, ShouldPanicWith, fmt.Sprintf(
			"timed out after %s waiting for kernel chosen port in %s",
			timeout, logPath,
		))
	})
}

func TestWaitForKernelChosenPortBaseURLSkipsInvalidPortLines(t *testing.T) {
	Convey("skips non-positive and unparsable ports then returns the first valid one", t, func() {
		logPath := path.Join(t.TempDir(), "zot-log.txt")
		content := "" +
			`{"level":"info","message":"port is unspecified, listening on kernel chosen port","port":0}` + "\n" +
			`{"level":"info","message":"port is unspecified, listening on kernel chosen port","port":-1}` + "\n" +
			`{"level":"info","message":"port is unspecified, listening on kernel chosen port","port":"bad"}` + "\n" +
			`not-json port is unspecified, listening on kernel chosen port` + "\n" +
			`{"level":"info","message":"port is unspecified, listening on kernel chosen port","port":34567}` + "\n"
		So(os.WriteFile(logPath, []byte(content), 0o600), ShouldBeNil)

		So(waitForKernelChosenPortBaseURL(logPath, time.Second), ShouldEqual, GetBaseURL("34567"))
	})
}
