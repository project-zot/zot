package version

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestWriterVersion(t *testing.T) {
	Convey("writerVersion prefers the release tag", t, func() {
		So(writerVersion("v2.3.4", "abc123"), ShouldEqual, "v2.3.4")
	})

	Convey("writerVersion falls back to dev-<commit>", t, func() {
		So(writerVersion("", "abc123"), ShouldEqual, "dev-abc123")
	})

	Convey("writerVersion returns empty when neither is set", t, func() {
		So(writerVersion("", ""), ShouldEqual, "")
	})
}
