package search //nolint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage/local"
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
				GetImageBlobManifestFn: func(imageDir string, digest godigest.Digest) (ispec.Manifest, error) {
					return ispec.Manifest{}, ErrTestError
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
				GetImageBlobManifestFn: func(imageDir string, digest godigest.Digest) (ispec.Manifest, error) {
					return ispec.Manifest{
						Layers: []ispec.Descriptor{
							{
								Size:   0,
								Digest: godigest.FromString(""),
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
								Layers: []common.LayerSummary{
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
				GetImageBlobManifestFn: func(imageDir string, digest godigest.Digest) (ispec.Manifest, error) {
					return ispec.Manifest{}, ErrTestError
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
		defaultStore := local.NewImageStore(dir, false, 0, false, false, log, metrics, nil, nil)

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

func TestExtractImageDetails(t *testing.T) {
	Convey("repoListWithNewestImage", t, func() {
		// log := log.Logger{Logger: zerolog.New(os.Stdout)}
		content := []byte("this is a blob5")
		testLogger := log.NewLogger("debug", "")
		layerDigest := godigest.FromBytes(content)
		config := ispec.Image{
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author: "some author",
		}

		ctx := context.TODO()
		authzCtxKey := localCtx.GetContextKey()
		ctx = context.WithValue(ctx, authzCtxKey,
			localCtx.AccessControlContext{
				GlobPatterns: map[string]bool{"*": true, "**": true},
				Username:     "jane_doe",
			})
		configBlobContent, _ := json.MarshalIndent(&config, "", "\t")
		configDigest := godigest.FromBytes(configBlobContent)

		localTestManifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlobContent)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(content)),
				},
			},
		}
		localTestDigestTry, _ := json.Marshal(localTestManifest)
		localTestDigest := godigest.FromBytes(localTestDigestTry)

		Convey("extractImageDetails good workflow", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageConfigInfoFn: func(repo string, digest godigest.Digest) (
					ispec.Image, error,
				) {
					return config, nil
				},
				GetImageManifestFn: func(repo string, tag string) (
					ispec.Manifest, godigest.Digest, error,
				) {
					return localTestManifest, localTestDigest, nil
				},
			}
			resDigest, resManifest, resIspecImage, resErr := extractImageDetails(ctx,
				mockOlum, "zot-test", "latest", testLogger)
			So(string(resDigest), ShouldContainSubstring, "sha256:d004018b9f")
			So(resManifest.Config.Digest.String(), ShouldContainSubstring, configDigest.Encoded())

			So(resIspecImage.Architecture, ShouldContainSubstring, "amd64")
			So(resErr, ShouldBeNil)
		})

		Convey("extractImageDetails bad ispec.ImageManifest", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageConfigInfoFn: func(repo string, digest godigest.Digest) (
					ispec.Image, error,
				) {
					return config, nil
				},
				GetImageManifestFn: func(repo string, tag string) (
					ispec.Manifest, godigest.Digest, error,
				) {
					return ispec.Manifest{}, localTestDigest, ErrTestError
				},
			}
			resDigest, resManifest, resIspecImage, resErr := extractImageDetails(ctx,
				mockOlum, "zot-test", "latest", testLogger)
			So(resErr, ShouldEqual, ErrTestError)
			So(string(resDigest), ShouldEqual, "")
			So(resManifest, ShouldBeNil)

			So(resIspecImage, ShouldBeNil)
		})

		Convey("extractImageDetails bad imageConfig", func() {
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageConfigInfoFn: func(repo string, digest godigest.Digest) (
					ispec.Image, error,
				) {
					return config, nil
				},
				GetImageManifestFn: func(repo string, tag string) (
					ispec.Manifest, godigest.Digest, error,
				) {
					return localTestManifest, localTestDigest, ErrTestError
				},
			}
			resDigest, resManifest, resIspecImage, resErr := extractImageDetails(ctx,
				mockOlum, "zot-test", "latest", testLogger)
			So(string(resDigest), ShouldEqual, "")
			So(resManifest, ShouldBeNil)

			So(resIspecImage, ShouldBeNil)
			So(resErr, ShouldEqual, ErrTestError)
		})

		Convey("extractImageDetails without proper authz", func() {
			ctx = context.WithValue(ctx, authzCtxKey,
				localCtx.AccessControlContext{
					GlobPatterns: map[string]bool{},
					Username:     "jane_doe",
				})
			mockOlum := mocks.OciLayoutUtilsMock{
				GetImageConfigInfoFn: func(repo string, digest godigest.Digest) (
					ispec.Image, error,
				) {
					return config, nil
				},
				GetImageManifestFn: func(repo string, tag string) (
					ispec.Manifest, godigest.Digest, error,
				) {
					return localTestManifest, localTestDigest, ErrTestError
				},
			}
			resDigest, resManifest, resIspecImage, resErr := extractImageDetails(ctx,
				mockOlum, "zot-test", "latest", testLogger)
			So(string(resDigest), ShouldEqual, "")
			So(resManifest, ShouldBeNil)

			So(resIspecImage, ShouldBeNil)
			So(resErr, ShouldNotBeNil)
			So(strings.ToLower(resErr.Error()), ShouldContainSubstring, "unauthorized access")
		})
	})
}
