package common_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/common"
)

func TestOCI(t *testing.T) {
	Convey("Test image dir and digest", t, func() {
		repo, digest := common.GetImageDirAndDigest("image")
		So(repo, ShouldResemble, "image")
		So(digest, ShouldResemble, "")
	})
}
