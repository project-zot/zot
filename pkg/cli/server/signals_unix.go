//go:build !windows

package server

import (
	"os/signal"
	"syscall"
)

// numSignals is the bound os/signal uses for signal numbers. signal.Ignore
// does nothing for numbers the platform does not define and for signals the
// runtime does not let a program ignore, such as SIGKILL and SIGSEGV.
const numSignals = 65

// ignoreAsyncSignals ignores every asynchronous signal except SIGCHLD, the
// same set signal.Ignore() with no arguments ignores minus SIGCHLD. This keeps
// the server from being stopped by the job-control signals (SIGTSTP, SIGTTIN,
// SIGTTOU) or terminated or dumped by the others (SIGPIPE, SIGQUIT, SIGUSR1,
// ...).
//
// SIGCHLD must not be ignored: with SIGCHLD set to SIG_IGN the kernel reaps
// child processes as they exit, so os/exec cannot wait for a child the server
// starts and fails with ECHILD ("waitid: no child processes"). That breaks,
// for example, an AWS credential_process used by the sync extension's ECR
// credential helper. Calling signal.Reset(syscall.SIGCHLD) after
// signal.Ignore() does not undo it, because the runtime leaves SIG_IGN in
// place for signals it handles itself.
func ignoreAsyncSignals() {
	for sig := syscall.Signal(1); sig < numSignals; sig++ {
		if sig != syscall.SIGCHLD {
			signal.Ignore(sig)
		}
	}
}
