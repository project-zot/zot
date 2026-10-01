//go:build windows

package server

import "os/signal"

// ignoreAsyncSignals ignores all asynchronous signals. Windows has no
// SIGCHLD, so the concern that shapes the Unix list does not apply.
func ignoreAsyncSignals() {
	signal.Ignore()
}
