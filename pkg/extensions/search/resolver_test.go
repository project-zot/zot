package search //nolint

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
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
			mockCve := mocks.CveInfoMock{}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
		})

		Convey("GetImageTagsWithTimestamp fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageTagsWithTimestampFn: func(repo string) ([]common.TagInfo, error) {
					return []common.TagInfo{}, ErrTestError
				},
			}
			mockCve := mocks.CveInfoMock{}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
		})

		Convey("GetImageManifests fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(name string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{}, ErrTestError
				},
			}
			mockCve := mocks.CveInfoMock{}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
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
			mockCve := mocks.CveInfoMock{}

			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
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
			mockCve := mocks.CveInfoMock{}

			globalSearch([]string{"repo1"}, "test", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
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
			mockCve := mocks.CveInfoMock{}
			globalSearch([]string{"repo1/name"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
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
			mockCve := mocks.CveInfoMock{}
			globalSearch([]string{"repo1/name"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
		})

		Convey("Tag given, no layer match", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetExpandedRepoInfoFn: func(name string) (common.RepoInfo, error) {
					return common.RepoInfo{
						ImageSummaries: []common.ImageSummary{
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
			mockCve := mocks.CveInfoMock{}
			globalSearch([]string{"repo1"}, "name", "tag", mockOlum, mockCve, log.NewLogger("debug", ""))
		})
	})
}

func TestRepoListWithNewestImage(t *testing.T) {
	Convey("repoListWithNewestImage", t, func() {
		Convey("GetImageManifests fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(image string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{}, ErrTestError
				},
			}

			ctx := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter, graphql.Recover)
			mockCve := mocks.CveInfoMock{}
			_, err := repoListWithNewestImage(ctx, []string{"repo1"}, mockOlum, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)

			errs := graphql.GetErrors(ctx)
			So(errs, ShouldNotBeEmpty)
		})

		Convey("GetImageBlobManifest fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageBlobManifestFn: func(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
					return v1.Manifest{}, ErrTestError
				},
				GetImageManifestsFn: func(image string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{
						{
							MediaType: "application/vnd.oci.image.layer.v1.tar",
							Size:      int64(0),
						},
					}, nil
				},
			}

			ctx := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter, graphql.Recover)
			mockCve := mocks.CveInfoMock{}
			_, err := repoListWithNewestImage(ctx, []string{"repo1"}, mockOlum, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)

			errs := graphql.GetErrors(ctx)
			So(errs, ShouldNotBeEmpty)
		})

		Convey("GetImageConfigInfo fail", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageManifestsFn: func(image string) ([]ispec.Descriptor, error) {
					return []ispec.Descriptor{
						{
							MediaType: "application/vnd.oci.image.layer.v1.tar",
							Size:      int64(0),
						},
					}, nil
				},
				GetImageConfigInfoFn: func(repo string, manifestDigest godigest.Digest) (ispec.Image, error) {
					return ispec.Image{
						Author: "test",
					}, ErrTestError
				},
			}

			ctx := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter, graphql.Recover)
			mockCve := mocks.CveInfoMock{}
			_, err := repoListWithNewestImage(ctx, []string{"repo1"}, mockOlum, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)

			errs := graphql.GetErrors(ctx)
			So(errs, ShouldNotBeEmpty)
		})
	})
}

func TestUserAvailableRepos(t *testing.T) {
	Convey("Type assertion fails", t, func() {
		var invalid struct{}

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		dir := t.TempDir()
		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := storage.NewImageStore(dir, false, 0, false, false, log, metrics, nil)

		repoList, err := defaultStore.GetRepositories()
		So(err, ShouldBeNil)

		ctx := context.TODO()
		key := localCtx.GetContextKey()
		ctx = context.WithValue(ctx, key, invalid)

		repos, err := userAvailableRepos(ctx, repoList)
		So(err, ShouldNotBeNil)
		So(repos, ShouldBeEmpty)
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
