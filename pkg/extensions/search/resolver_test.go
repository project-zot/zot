package search //nolint

import (
	"errors"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
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
				GetRepoLastUpdatedFn: func(repo string) (common.TagInfo, error) {
					return common.TagInfo{}, ErrTestError
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

		Convey("GetImageManifests fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(name string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{}, ErrTestError
				},
			}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("Manifests given, bad image blob manifest", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(name string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{
						{
							Digest: "digest",
							Size:   -1,
							Annotations: map[string]string{
								ispec.AnnotationRefName: "this is a bad format",
							},
						},
					}, nil
				},
				GetImageBlobManifestFn: func(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
					return v1.Manifest{}, ErrTestError
				},
			}
			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("Manifests given, no manifest tag", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(name string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{
						{
							Digest: "digest",
							Size:   -1,
						},
					}, nil
				},
			}

			globalSearch([]string{"repo1"}, "test", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("Global search success, no tag", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetRepoLastUpdatedFn: func(repo string) (common.TagInfo, error) {
					return common.TagInfo{
						Digest: "sha256:855b1556a45637abf05c63407437f6f305b4627c4361fb965a78e5731999c0c7",
					}, nil
				},
				GetImageManifestsFn: func(name string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{
						{
							Digest: "sha256:855b1556a45637abf05c63407437f6f305b4627c4361fb965a78e5731999c0c7",
							Size:   -1,
							Annotations: map[string]string{
								ispec.AnnotationRefName: "this is a bad format",
							},
						},
					}, nil
				},
				GetImageBlobManifestFn: func(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
					return v1.Manifest{
						Layers: []v1.Descriptor{
							{
								Size:   0,
								Digest: v1.Hash{},
							},
						},
					}, nil
				},
			}
			globalSearch([]string{"repo1/name"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
		})

		Convey("Manifests given, bad image config info", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(name string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{
						{
							Digest: "digest",
							Size:   -1,
							Annotations: map[string]string{
								ispec.AnnotationRefName: "this is a bad format",
							},
						},
					}, nil
				},
				GetImageConfigInfoFn: func(repo string, manifestDigest godigest.Digest) (ispec.Image, error) {
					return ispec.Image{}, ErrTestError
				},
			}
			globalSearch([]string{"repo1/name"}, "name", "tag", mockOlum, log.NewLogger("debug", ""))
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
