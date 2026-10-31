package protectedtags_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/protectedtags"
)

func TestMatcher(t *testing.T) {
	Convey("protected tag matcher", t, func() {
		Convey("matches exact tags", func() {
			matcher, err := protectedtags.Compile(protectedtags.Config{Exact: []string{"prod"}})
			So(err, ShouldBeNil)
			So(matcher.Matches("prod"), ShouldBeTrue)
			So(matcher.Matches("production"), ShouldBeFalse)
		})

		Convey("matches complete wildcard patterns", func() {
			matcher, err := protectedtags.Compile(protectedtags.Config{Wildcard: []string{"release-*", "v?.0"}})
			So(err, ShouldBeNil)
			So(matcher.Matches("release-1.2.3"), ShouldBeTrue)
			So(matcher.Matches("release"), ShouldBeFalse)
			So(matcher.Matches("v1.0"), ShouldBeTrue)
			So(matcher.Matches("v10.0"), ShouldBeFalse)
		})

		Convey("matches complete regular expressions", func() {
			matcher, err := protectedtags.Compile(protectedtags.Config{Regex: []string{`v[0-9]+\.[0-9]+\.[0-9]+`}})
			So(err, ShouldBeNil)
			So(matcher.Matches("v1.2.3"), ShouldBeTrue)
			So(matcher.Matches("build-v1.2.3"), ShouldBeFalse)
		})

		Convey("rejects invalid rules", func() {
			_, err := protectedtags.Compile(protectedtags.Config{Exact: []string{"bad/tag"}})
			So(err, ShouldNotBeNil)

			_, err = protectedtags.Compile(protectedtags.Config{Wildcard: []string{"bad["}})
			So(err, ShouldNotBeNil)

			_, err = protectedtags.Compile(protectedtags.Config{Regex: []string{"["}})
			So(err, ShouldNotBeNil)

			_, err = protectedtags.Compile(protectedtags.Config{Regex: []string{`prod)|(?:release`}})
			So(err, ShouldNotBeNil)
		})
	})
}
