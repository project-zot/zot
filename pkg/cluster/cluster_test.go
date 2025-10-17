package cluster_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/cluster"
)

func TestComputeTargetMember(t *testing.T) {
	Convey("Should panic when the hashKey is not long enough", t, func() {
		So(func() { cluster.ComputeTargetMember("lorem", []string{"member1", "member2"}, "zot-test") }, ShouldPanic)
	})

	Convey("Should panic when there are no members", t, func() {
		So(func() { cluster.ComputeTargetMember("loremipsumdolors", []string{}, "zot-test") }, ShouldPanic)
	})

	Convey("Should return a valid result when input is valid", t, func() {
		index, member := cluster.ComputeTargetMember("loremipsumdolors", []string{"member1", "member2"}, "zot-test")
		So(index, ShouldEqual, 1)
		So(member, ShouldEqual, "member2")
	})
}
