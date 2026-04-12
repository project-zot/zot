//go:build windows

package local

import (
	"golang.org/x/sys/windows"
)

// renameReplace moves src to dst, replacing dst if it already exists.
// When commit is true, MOVEFILE_WRITE_THROUGH is set so the rename is flushed to disk, aligning
// with the local driver's commit semantics on WriteFile/Close. When commit is false, only
// MOVEFILE_REPLACE_EXISTING is used so large moves are not forced fully synchronous.
func renameReplace(src, dst string, commit bool) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}

	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}

	var flags uint32 = windows.MOVEFILE_REPLACE_EXISTING
	if commit {
		flags |= windows.MOVEFILE_WRITE_THROUGH
	}

	return windows.MoveFileEx(from, to, flags)
}
