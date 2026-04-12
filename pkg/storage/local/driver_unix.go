//go:build !windows

package local

import "os"

// renameReplace moves src to dst, replacing dst if it already exists (POSIX rename).
// commit is ignored on Unix; durability for committed writers is handled via fsync in fileWriter.Close.
func renameReplace(_ bool, src, dst string) error {
	return os.Rename(src, dst)
}
