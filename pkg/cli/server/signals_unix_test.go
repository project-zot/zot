//go:build !windows

package server //nolint:testpackage // white-box test for unexported ignoreAsyncSignals

import (
	"os/exec"
	"os/signal"
	"syscall"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestIgnoreAsyncSignalsKeepsChildProcessesWaitable(t *testing.T) {
	Convey("A child process can be waited for after the server ignores its signals", t, func() {
		ignoreAsyncSignals()

		defer signal.Reset(syscall.SIGPIPE, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)

		// With SIGCHLD ignored this returns "waitid: no child processes".
		err := exec.Command("true").Run()
		So(err, ShouldBeNil)
	})
}
