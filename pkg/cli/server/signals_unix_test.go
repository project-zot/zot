//go:build !windows

package server //nolint:testpackage // white-box test for unexported ignoreAsyncSignals

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

const ignoreAsyncSignalsChildEnv = "ZOT_TEST_IGNORE_ASYNC_SIGNALS_CHILD"

func TestIgnoreAsyncSignalsKeepsChildProcessesWaitable(t *testing.T) {
	Convey("A child process can be waited for after the server ignores its signals", t, func() {
		ignoreAsyncSignals()

		defer signal.Reset()

		So(signal.Ignored(syscall.SIGCHLD), ShouldBeFalse)

		// With SIGCHLD ignored this returns "waitid: no child processes".
		err := exec.CommandContext(t.Context(), "true").Run()
		So(err, ShouldBeNil)
	})
}

func TestIgnoreAsyncSignalsSurvivesStopAndTerminateSignals(t *testing.T) {
	signals := []syscall.Signal{
		syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU,
		syscall.SIGPIPE, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2,
	}

	// In the child, the default action of any of these signals stops or
	// terminates the process, so the test runs in a separate process.
	if os.Getenv(ignoreAsyncSignalsChildEnv) == "1" {
		ignoreAsyncSignals()

		for _, sig := range signals {
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				os.Exit(1)
			}
		}

		// Give a signal delivered to another thread time to take effect.
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}

	Convey("The server process is neither stopped nor terminated by async signals", t, func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIgnoreAsyncSignalsSurvivesStopAndTerminateSignals$")
		cmd.Env = append(os.Environ(), ignoreAsyncSignalsChildEnv+"=1")
		// A process group of its own keeps the group from being orphaned:
		// the kernel discards SIGTSTP, SIGTTIN and SIGTTOU sent to an
		// orphaned process group instead of stopping it.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

		// A stopped child does not exit, so Run returns only when the
		// context kills it.
		err := cmd.Run()
		So(ctx.Err(), ShouldBeNil)
		So(err, ShouldBeNil)
	})
}
