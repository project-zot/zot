package common_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/common"
)

func TestCommon(t *testing.T) {
	Convey("test Contains()", t, func() {
		first := []string{"apple", "biscuit"}
		So(common.Contains(first, "apple"), ShouldBeTrue)
		So(common.Contains(first, "peach"), ShouldBeFalse)
		So(common.Contains([]string{}, "apple"), ShouldBeFalse)
	})
}
