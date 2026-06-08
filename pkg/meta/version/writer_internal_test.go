package version

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestWriterVersion(t *testing.T) {
	Convey("writerVersion combines release tag and commit", t, func() {
		So(writerVersion("v2.3.4", "abc123"), ShouldEqual, "v2.3.4+abc123")
	})

	Convey("writerVersion distinguishes a retagged release", t, func() {
		// Same tag re-pointed at a different commit must yield a different stamp
		So(writerVersion("v2.3.4", "abc123"), ShouldNotEqual, writerVersion("v2.3.4", "def456"))
	})

	Convey("writerVersion falls back to the bare tag when commit is unset", t, func() {
		So(writerVersion("v2.3.4", ""), ShouldEqual, "v2.3.4")
	})

	Convey("writerVersion falls back to dev-<commit> without a release tag", t, func() {
		So(writerVersion("", "abc123"), ShouldEqual, "dev-abc123")
	})

	Convey("writerVersion returns empty when neither is set", t, func() {
		So(writerVersion("", ""), ShouldEqual, "")
	})
}
