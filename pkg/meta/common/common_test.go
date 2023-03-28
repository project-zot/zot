package common_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/meta/common"
)

func TestUtils(t *testing.T) {
	Convey("GetReferredSubject", t, func() {
		_, err := common.GetReferredSubject([]byte("bad json"))
		So(err, ShouldNotBeNil)
	})

	Convey("MatchesArtifactTypes", t, func() {
		res := common.MatchesArtifactTypes("", nil)
		So(res, ShouldBeTrue)

		res = common.MatchesArtifactTypes("type", []string{"someOtherType"})
		So(res, ShouldBeFalse)
	})
}
