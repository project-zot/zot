//go:build !windows

package local

import (
	"errors"
	"os"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// recordSyncedDirs replaces the directory-sync seam so the tests can assert which directories
// are made durable; the real fsync leaves nothing observable behind.
func recordSyncedDirs(t *testing.T) *[]string {
	t.Helper()

	synced := &[]string{}
	previous := syncDirFn

	syncDirFn = func(dir string) error {
		*synced = append(*synced, dir)

		return nil
	}

	t.Cleanup(func() { syncDirFn = previous })

	return synced
}

func TestRenameReplaceDurability(t *testing.T) {
	Convey("renameReplace with commit syncs the destination directory", t, func() {
		synced := recordSyncedDirs(t)
		dir := t.TempDir()
		src := path.Join(dir, "staged")
		dst := path.Join(dir, "index.json")

		So(os.WriteFile(src, []byte("new"), 0o600), ShouldBeNil)
		So(os.WriteFile(dst, []byte("old"), 0o600), ShouldBeNil)

		So(renameReplace(src, dst, true), ShouldBeNil)

		content, err := os.ReadFile(dst)
		So(err, ShouldBeNil)
		So(string(content), ShouldEqual, "new")
		So(*synced, ShouldResemble, []string{dir})
	})

	Convey("renameReplace without commit does not sync", t, func() {
		synced := recordSyncedDirs(t)
		dir := t.TempDir()
		src := path.Join(dir, "staged")
		dst := path.Join(dir, "index.json")

		So(os.WriteFile(src, []byte("new"), 0o600), ShouldBeNil)

		So(renameReplace(src, dst, false), ShouldBeNil)

		content, err := os.ReadFile(dst)
		So(err, ShouldBeNil)
		So(string(content), ShouldEqual, "new")
		So(*synced, ShouldBeEmpty)
	})

	Convey("renameReplace reports a missing source", t, func() {
		dir := t.TempDir()

		So(renameReplace(path.Join(dir, "absent"), path.Join(dir, "dst"), true), ShouldNotBeNil)
	})

	Convey("renameReplace reports a failed directory sync", t, func() {
		previous := syncDirFn

		syncDirFn = func(string) error { return errors.New("sync failed") } //nolint:err113
		t.Cleanup(func() { syncDirFn = previous })

		dir := t.TempDir()
		src := path.Join(dir, "staged")
		So(os.WriteFile(src, []byte("new"), 0o600), ShouldBeNil)

		err := renameReplace(src, path.Join(dir, "index.json"), true)
		So(err, ShouldNotBeNil)
		So(errclass.IsStorageNotDurable(err), ShouldBeTrue)
	})
}

func TestSyncDir(t *testing.T) {
	Convey("syncDir syncs an existing directory", t, func() {
		So(syncDir(t.TempDir()), ShouldBeNil)
	})

	Convey("syncDir reports a missing directory", t, func() {
		So(syncDir(path.Join(t.TempDir(), "absent")), ShouldNotBeNil)
	})
}

func TestMoveDurability(t *testing.T) {
	Convey("Move syncs the destination directory when commit is on", t, func() {
		synced := recordSyncedDirs(t)
		driver := New(true)
		root := t.TempDir()
		dstDir := path.Join(root, "repo", "blobs")
		src := path.Join(root, "staged")

		So(os.MkdirAll(dstDir, 0o700), ShouldBeNil)
		So(os.WriteFile(src, []byte("blob"), 0o600), ShouldBeNil)

		So(driver.Move(src, path.Join(dstDir, "blob")), ShouldBeNil)
		So(*synced, ShouldResemble, []string{dstDir})
	})

	Convey("Move without commit does not sync", t, func() {
		synced := recordSyncedDirs(t)
		driver := New(false)
		root := t.TempDir()
		src := path.Join(root, "staged")
		dst := path.Join(root, "a", "b", "blob")

		So(os.WriteFile(src, []byte("blob"), 0o600), ShouldBeNil)
		So(driver.Move(src, dst), ShouldBeNil)

		_, err := os.Stat(dst)
		So(err, ShouldBeNil)
		So(*synced, ShouldBeEmpty)
	})

	Convey("Move surfaces a failed directory sync as not durable", t, func() {
		previous := syncDirFn

		syncDirFn = func(string) error { return errors.New("sync failed") } //nolint:err113
		t.Cleanup(func() { syncDirFn = previous })

		driver := New(true)
		root := t.TempDir()
		src := path.Join(root, "staged")

		So(os.WriteFile(src, []byte("blob"), 0o600), ShouldBeNil)

		err := driver.Move(src, path.Join(root, "a", "blob"))
		So(err, ShouldNotBeNil)
		So(errclass.IsStorageNotDurable(err), ShouldBeTrue)
	})
}
