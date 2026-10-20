//go:build !windows

package local

import (
	"os"
	"path"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// renameReplace moves src to dst, replacing dst if it already exists (POSIX rename).
//
// When commit is true the destination's parent directory is fsynced after the rename. The
// fsync in fileWriter.Close makes the staged file's contents durable, but it says nothing
// about the directory entry the rename creates: that entry lives in the page cache until the
// parent directory itself is synced, so after a power loss the old file is back and the write
// is lost even though it was acknowledged.
func renameReplace(src, dst string, commit bool) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}

	if !commit {
		return nil
	}

	if err := syncDirFn(path.Dir(dst)); err != nil {
		// The rename is in place; only its durability failed. Mark the failure so a
		// caller that would accept the destination's content as a completed move
		// cannot report success.
		return errclass.Wrap(zerr.ErrStorageNotDurable, err)
	}

	return nil
}

// syncDir fsyncs a directory so entries created, removed or renamed inside it survive a crash.
// Unix requires the directory to be opened (read-only is enough) to sync it.
func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}

	syncErr := file.Sync()
	closeErr := file.Close()

	if syncErr != nil {
		return syncErr
	}

	return closeErr
}
