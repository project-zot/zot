package common_test

import (
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/common"
)

func TestOCI(t *testing.T) {
	Convey("Test image dir and digest", t, func() {
		repo, digest := common.GetImageDirAndDigest("image")
		So(repo, ShouldResemble, "image")
		So(digest, ShouldResemble, "")
	})

	Convey("LooksLikeDigestReference", t, func() {
		So(common.LooksLikeDigestReference("sha256:baddigeststring"), ShouldBeTrue)
		So(common.LooksLikeDigestReference("sha256:"+strings.Repeat("a", 64)), ShouldBeFalse)
		So(common.LooksLikeDigestReference("1.0"), ShouldBeFalse)
		So(common.LooksLikeDigestReference("latest"), ShouldBeFalse)
	})
}
