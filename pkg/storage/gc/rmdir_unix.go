//go:build !windows

package gc

import (
	"errors"
	"syscall"
)

// isDirNotEmpty reports whether err from syscall.Rmdir means the directory
// still has entries.
func isDirNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST)
}
