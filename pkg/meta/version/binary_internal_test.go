package version

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBinaryVersion(t *testing.T) {
	Convey("binaryVersion combines release tag and commit", t, func() {
		So(binaryVersion("v2.3.4", "abc123"), ShouldEqual, "v2.3.4+abc123")
	})

	Convey("binaryVersion distinguishes a retagged release", t, func() {
		// Same tag re-pointed at a different commit must yield a different stamp
		So(binaryVersion("v2.3.4", "abc123"), ShouldNotEqual, binaryVersion("v2.3.4", "def456"))
	})

	Convey("binaryVersion falls back to the bare tag when commit is unset", t, func() {
		So(binaryVersion("v2.3.4", ""), ShouldEqual, "v2.3.4")
	})

	Convey("binaryVersion falls back to dev-<commit> without a release tag", t, func() {
		So(binaryVersion("", "abc123"), ShouldEqual, "dev-abc123")
	})

	Convey("binaryVersion returns empty when neither is set", t, func() {
		So(binaryVersion("", ""), ShouldEqual, "")
	})
}
