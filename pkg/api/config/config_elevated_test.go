//go:build needprivileges && linux

package config_test

import (
	"syscall"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestMountConfig(t *testing.T) {
	Convey("Test config utils mounting same directory", t, func() {
		// If two dirs are mounting to same location SameFile should be same
		dir1 := t.TempDir()
		dir2 := t.TempDir()
		dir3 := t.TempDir()

		err := syscall.Mount(dir3, dir1, "", syscall.MS_BIND, "")
		So(err, ShouldBeNil)

		err = syscall.Mount(dir3, dir2, "", syscall.MS_BIND, "")
		So(err, ShouldBeNil)

		isSame, err := config.SameFile(dir1, dir2)
		So(err, ShouldBeNil)
		So(isSame, ShouldBeTrue)
	})
}
