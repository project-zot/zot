//go:build !windows
// +build !windows

package api

import (
	"os"
	"runtime"
	"strings"
	"syscall"

	"zotregistry.dev/zot/pkg/log"
)

// DumpRuntimeParams dumps important runtime state such as file and socket limits.
func DumpRuntimeParams(log log.Logger) {
	var rLimit syscall.Rlimit

	evt := log.Info().Int("cpus", runtime.NumCPU()) //nolint: zerologlint

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err == nil {
		evt = evt.Uint64("max. open files", uint64(rLimit.Cur)) //nolint: unconvert // required for *BSD
	}

	if content, err := os.ReadFile("/proc/sys/net/core/somaxconn"); err == nil {
		evt = evt.Str("listen backlog", strings.TrimSuffix(string(content), "\n"))
	}

	if content, err := os.ReadFile("/proc/sys/user/max_inotify_watches"); err == nil {
		evt = evt.Str("max. inotify watches", strings.TrimSuffix(string(content), "\n"))
	}

	evt.Msg("runtime params")
}
