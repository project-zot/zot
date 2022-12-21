package search //nolint

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		const query = "repo1"
		Convey("RepoDB SearchRepos error", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo is successful", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
								"1.0.2": {
									Digest:    "digestTag1.0.2",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
					}

					createTime := time.Now()
					configBlob1, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{
								ispec.AnnotationVendor: "TestVendor1",
							},
						},
						Created: &createTime,
					})
					So(err, ShouldBeNil)

					configBlob2, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{
								ispec.AnnotationVendor: "TestVendor2",
							},
						},
					})
					So(err, ShouldBeNil)

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			const query = "repo1"
			limit := 1
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)
			So(len(repos[0].Vendors), ShouldEqual, 2)
		})

		Convey("RepoDB SearchRepo Bad manifest referenced", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
					}

					configBlob, err := json.Marshal(ispec.Image{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: []byte("bad manifest blob"),
							ConfigBlob:   configBlob,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			query := "repo1"
			limit := 1
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"

			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo good manifest referenced and bad config blob", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
					}

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   []byte("bad config blob"),
						},
					}

					return repos, manifestMetas, nil
				},
			}

			query := "repo1"
			limit := 1
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"
			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags gives error", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			const query = "repo1:1.0.1"
			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags is successful", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
					}

					configBlob1, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{
								ispec.AnnotationVendor: "TestVendor1",
							},
						},
					})
					So(err, ShouldBeNil)

					configBlob2, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{
								ispec.AnnotationVendor: "TestVendor2",
							},
						},
					})
					So(err, ShouldBeNil)

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			const query = "repo1:1.0.1"
			limit := 1
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldNotBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})
	})
}

func TestRepoListWithNewestImage(t *testing.T) {
	Convey("RepoListWithNewestImage", t, func() {
		Convey("RepoDB SearchRepos error", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			limit := 1
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaUpdateTime
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockRepoDB)
			So(err, ShouldNotBeNil)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo Bad manifest referenced", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
						{
							Name: "repo2",
							Tags: map[string]repodb.Descriptor{
								"1.0.2": {
									Digest:    "digestTag1.0.2",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
					}

					configBlob1, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{},
						},
					})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: []byte("bad manifest blob"),
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: []byte("bad manifest blob"),
							ConfigBlob:   configBlob1,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			limit := 1
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaUpdateTime
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockRepoDB)
			So(err, ShouldBeNil)
			So(repos, ShouldNotBeEmpty)
		})

		Convey("Working SearchRepo function", func() {
			createTime := time.Now()
			createTime2 := createTime.Add(time.Second)
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
					So(err, ShouldBeNil)

					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
						{
							Name: "repo2",
							Tags: map[string]repodb.Descriptor{
								"1.0.2": {
									Digest:    "digestTag1.0.2",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Stars: 100,
						},
					}

					for _, repoMeta := range repos {
						pageFinder.Add(repodb.DetailedRepoMeta{
							RepoMeta:   repoMeta,
							UpdateTime: createTime,
						})
						createTime = createTime.Add(time.Second)
					}

					repos = pageFinder.Page()

					configBlob1, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{},
						},
						Created: &createTime,
					})
					So(err, ShouldBeNil)

					configBlob2, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{},
						},
						Created: &createTime2,
					})
					So(err, ShouldBeNil)

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestMetas, nil
				},
			}
			Convey("RepoDB missing requestedPage", func() {
				responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
					graphql.DefaultRecover)
				mockCve := mocks.CveInfoMock{}
				repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), nil, mockRepoDB)
				So(err, ShouldBeNil)
				So(repos, ShouldNotBeEmpty)
			})

			Convey("RepoDB SearchRepo is successful", func() {
				limit := 2
				ofset := 0
				sortCriteria := gql_generated.SortCriteriaUpdateTime
				pageInput := gql_generated.PageInput{
					Limit:  &limit,
					Offset: &ofset,
					SortBy: &sortCriteria,
				}

				responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
					graphql.DefaultRecover)

				mockCve := mocks.CveInfoMock{}
				repos, err := repoListWithNewestImage(responseContext, mockCve,
					log.NewLogger("debug", ""), &pageInput, mockRepoDB)
				So(err, ShouldBeNil)
				So(repos, ShouldNotBeEmpty)
				So(len(repos), ShouldEqual, 2)
				So(*repos[0].Name, ShouldEqual, "repo2")
				So(*repos[0].LastUpdated, ShouldEqual, createTime2)
			})
		})
	})
}

func TestGetReferrers(t *testing.T) {
	Convey("getReferrers", t, func() {
		Convey("GetReferrers returns error", func() {
			testLogger := log.NewLogger("debug", "")
			mockedStore := mocks.MockedImageStore{
				GetReferrersFn: func(repo string, digest godigest.Digest, artifactType string) (ispec.Index, error) {
					return ispec.Index{}, ErrTestError
				},
			}

			_, err := getReferrers(mockedStore, "test", "", "", testLogger)
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers return index of descriptors", func() {
			testLogger := log.NewLogger("debug", "")
			referrerDescriptor := ispec.Descriptor{
				MediaType:    ispec.MediaTypeArtifactManifest,
				ArtifactType: "com.artifact.test",
				Size:         403,
				Digest:       godigest.FromString("test"),
				Annotations: map[string]string{
					"key": "value",
				},
			}
			mockedStore := mocks.MockedImageStore{
				GetReferrersFn: func(repo string, digest godigest.Digest, artifactType string) (ispec.Index, error) {
					return ispec.Index{
						Manifests: []ispec.Descriptor{
							referrerDescriptor,
						},
					}, nil
				},
			}

			referrers, err := getReferrers(mockedStore, "test", "", "", testLogger)
			So(err, ShouldBeNil)
			So(*referrers[0].ArtifactType, ShouldEqual, referrerDescriptor.ArtifactType)
			So(*referrers[0].MediaType, ShouldEqual, referrerDescriptor.MediaType)
			So(*referrers[0].Size, ShouldEqual, referrerDescriptor.Size)
			So(*referrers[0].Digest, ShouldEqual, referrerDescriptor.Digest)
			So(*referrers[0].Annotations[0].Value, ShouldEqual, referrerDescriptor.Annotations["key"])
		})
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
				ReadGlobPatterns: map[string]bool{"*": true, "**": true},
				Username:         "jane_doe",
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
					ReadGlobPatterns: map[string]bool{},
					Username:         "jane_doe",
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

func TestQueryResolverErrors(t *testing.T) {
	Convey("Errors", t, func() {
		log := log.NewLogger("debug", "")
		ctx := context.Background()

		Convey("ImageListForCve olu.GetRepositories() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return nil, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "id")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForCve cveInfo.GetImageListForCVE() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"repo"}, nil
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{
					GetImageListForCVEFn: func(repo, cveID string) ([]cveinfo.ImageInfoByCVE, error) {
						return nil, ErrTestError
					},
				},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "a")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForCve olu.GetImageConfigInfo() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"repo"}, nil
						},
						GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
							return nil, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{
					GetImageListForCVEFn: func(repo, cveID string) ([]cveinfo.ImageInfoByCVE, error) {
						return []cveinfo.ImageInfoByCVE{{}}, nil
					},
				},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "a")
			So(err, ShouldNotBeNil)
		})

		Convey("RepoListWithNewestImage repoListWithNewestImage errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.RepoDBMock{
					SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter,
						requestedPage repodb.PageInput) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata,
						error) {
						return nil, nil, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.RepoListWithNewestImage(ctx, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListWithCVEFixed olu.GetImageBlobManifest() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
							return nil, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{
					GetImageListWithCVEFixedFn: func(repo, cveID string) ([]common.TagInfo, error) {
						return []common.TagInfo{{}}, nil
					},
				},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListWithCVEFixed(ctx, "a", "d")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListWithCVEFixed olu.GetImageConfigInfo() errors", func() {
			getBlobContentCallCounter := 0

			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
							if getBlobContentCallCounter == 1 {
								getBlobContentCallCounter++

								return nil, ErrTestError
							}
							getBlobContentCallCounter++

							return []byte("{}"), nil
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{
					GetImageListWithCVEFixedFn: func(repo, cveID string) ([]common.TagInfo, error) {
						return []common.TagInfo{{}}, nil
					},
				},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListWithCVEFixed(ctx, "a", "d")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForDigest defaultStore.GetRepositories() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return nil, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForDigest(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForDigest getImageListForDigest() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"repo"}, nil
						},
						GetIndexContentFn: func(repo string) ([]byte, error) {
							return nil, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForDigest(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForDigest substores store.GetRepositories() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetIndexContentFn: func(repo string) ([]byte, error) {
							return []byte("{}"), nil
						},
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"repo"}, nil
						},
					},
					SubStore: map[string]storage.ImageStore{
						"sub1": mocks.MockedImageStore{
							GetRepositoriesFn: func() ([]string, error) {
								return []string{"repo"}, ErrTestError
							},
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForDigest(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForDigest substores getImageListForDigest() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetIndexContentFn: func(repo string) ([]byte, error) {
							return []byte("{}"), nil
						},
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"repo"}, nil
						},
					},
					SubStore: map[string]storage.ImageStore{
						"/sub1": mocks.MockedImageStore{
							GetRepositoriesFn: func() ([]string, error) {
								return []string{"sub1/repo"}, nil
							},
							GetIndexContentFn: func(repo string) ([]byte, error) {
								return nil, ErrTestError
							},
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForDigest(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("RepoListWithNewestImage repoListWithNewestImage() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.RepoDBMock{
					SearchReposFn: func(ctx context.Context, searchText string,
						filter repodb.Filter, requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
						return nil, nil, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.RepoListWithNewestImage(ctx, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageList getImageList() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return nil, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageList(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ImageList subpaths getImageList() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"sub1/repo"}, nil
						},
					},
					SubStore: map[string]storage.ImageStore{
						"/sub1": mocks.MockedImageStore{
							GetRepositoriesFn: func() ([]string, error) {
								return nil, ErrTestError
							},
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageList(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("DerivedImageList ExpandedRepoInfo() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"sub1/repo"}, nil
						},
						GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
							return []byte("{}"), "digest", "str", nil
						},
					},
				},
				mocks.RepoDBMock{
					GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
						return repodb.RepoMetadata{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.DerivedImageList(ctx, "repo:tag")
			So(err, ShouldNotBeNil)
		})

		Convey("BaseImageList ExpandedRepoInfo() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{"sub1/repo"}, nil
						},
						GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
							return []byte("{}"), "digest", "str", nil
						},
					},
				},
				mocks.RepoDBMock{
					GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
						return repodb.RepoMetadata{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.BaseImageList(ctx, "repo:tag")
			So(err, ShouldNotBeNil)
		})
	})
}
