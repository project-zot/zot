package search //nolint

import (
	"errors"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		Convey("GetRepoLastUpdated fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetRepoLastUpdatedFn: func(repo string) (time.Time, error) {
					return time.Time{}, ErrTestError
				},
			}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("GetImageTagsWithTimestamp fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageTagsWithTimestampFn: func(repo string) ([]common.TagInfo, error) {
					return []common.TagInfo{}, ErrTestError
				},
			}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("GetExpandedRepoInfo fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetExpandedRepoInfoFn: func(name string) (common.RepoInfo, error) {
					return common.RepoInfo{}, ErrTestError
				},
			}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("Bad layer digest in manifest", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetExpandedRepoInfoFn: func(name string) (common.RepoInfo, error) {
					return common.RepoInfo{
						Manifests: []common.Manifest{
							{
								Tag: "latest",
								Layers: []common.Layer{
									{
										Size:   "this is a bad size format",
										Digest: "digest",
									},
								},
							},
						},
					}, nil
				},
				GetImageManifestSizeFn: func(repo string, manifestDigest godigest.Digest) int64 {
					return 100
				},
				GetImageConfigSizeFn: func(repo string, manifestDigest godigest.Digest) int64 {
					return 100
				},
				GetImageTagsWithTimestampFn: func(repo string) ([]common.TagInfo, error) {
					return []common.TagInfo{
						{
							Name:   "test",
							Digest: "test",
						},
					}, nil
				},
			}
			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("Tag given, no layer match", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetExpandedRepoInfoFn: func(name string) (common.RepoInfo, error) {
					return common.RepoInfo{
						Manifests: []common.Manifest{
							{
								Tag: "latest",
								Layers: []common.Layer{
									{
										Size:   "100",
										Digest: "sha256:855b1556a45637abf05c63407437f6f305b4627c4361fb965a78e5731999c0c7",
									},
								},
							},
						},
					}, nil
				},
				GetImageManifestSizeFn: func(repo string, manifestDigest godigest.Digest) int64 {
					return 100
				},
				GetImageConfigSizeFn: func(repo string, manifestDigest godigest.Digest) int64 {
					return 100
				},
				GetImageTagsWithTimestampFn: func(repo string) ([]common.TagInfo, error) {
					return []common.TagInfo{
						{
							Name:   "test",
							Digest: "test",
						},
					}, nil
				},
			}
			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})
	})
}

func TestMatching(t *testing.T) {
	pine := "pine"

	Convey("Perfect Matching", t, func() {
		query := "alpine"
		score := calculateImageMatchingScore("alpine", strings.Index("alpine", query), true)
		So(score, ShouldEqual, 0)
	})

	Convey("Partial Matching", t, func() {
		query := pine
		score := calculateImageMatchingScore("alpine", strings.Index("alpine", query), true)
		So(score, ShouldEqual, 2)
	})

	Convey("Complex Partial Matching", t, func() {
		query := pine
		score := calculateImageMatchingScore("repo/test/alpine", strings.Index("alpine", query), true)
		So(score, ShouldEqual, 2)

		query = pine
		score = calculateImageMatchingScore("repo/alpine/test", strings.Index("alpine", query), true)
		So(score, ShouldEqual, 2)

		query = pine
		score = calculateImageMatchingScore("alpine/repo/test", strings.Index("alpine", query), true)
		So(score, ShouldEqual, 2)

		query = pine
		score = calculateImageMatchingScore("alpine/repo/test", strings.Index("alpine", query), false)
		So(score, ShouldEqual, 12)
	})
}
