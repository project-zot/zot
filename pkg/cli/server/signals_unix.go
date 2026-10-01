//go:build !windows

package server

import (
	"os/signal"
	"syscall"
)

// ignoreAsyncSignals ignores the asynchronous signals that would otherwise
// stop or dump the server. SIGCHLD must not be ignored: with SIGCHLD set to
// SIG_IGN the kernel reaps child processes as they exit, so os/exec cannot
// wait for a child the server starts and fails with ECHILD ("waitid: no
// child processes"). That breaks, for example, an AWS credential_process
// used by the sync extension's ECR credential helper.
func ignoreAsyncSignals() {
	signal.Ignore(syscall.SIGPIPE, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
}
