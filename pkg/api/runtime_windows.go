//go:build windows
// +build windows

package api

import (
	"runtime"
	"syscall"
	"unsafe"

	"zotregistry.dev/zot/v2/pkg/log"
)

func getCurrentHandleCount() (uint32, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")

	getProcessHandleCount := kernel32.NewProc("GetProcessHandleCount")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	currentProcess, _, _ := getCurrentProcess.Call()

	var handleCount uint32
	ret, _, err := getProcessHandleCount.Call(
		currentProcess,
		uintptr(unsafe.Pointer(&handleCount)),
	)

	if ret == 0 {
		return 0, err
	}

	return handleCount, nil
}

// DumpRuntimeParams dumps important runtime state such as file and socket limits.
func DumpRuntimeParams(log log.Logger) {
	evt := log.Info().Int("cpus", runtime.NumCPU()) //nolint: zerologlint

	nofile, err := getCurrentHandleCount()
	if err == nil {
		evt = evt.Uint64("curr. open files", uint64(nofile)) //nolint: unconvert // required for *BSD
	}

	evt.Msg("runtime params")
}
