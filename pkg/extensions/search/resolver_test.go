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

	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage/repodb"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		const query = "repo1"
		Convey("RepoDB SearchRepos error", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo is successful", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
								"1.0.2": "digestTag1.0.2",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Descriptions repo1",
							LogoPath:    "test/logoPath",
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
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob1,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
						"digestTag1.0.2": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob2,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			const query = "repo1"
			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)
			So(len(repos[0].Vendors), ShouldEqual, 2)
		})

		Convey("RepoDB SearchRepo Bad manifest refferenced", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Descriptions repo1",
							LogoPath:    "test/logoPath",
						},
					}

					configBlob, err := json.Marshal(ispec.Image{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob:  []byte("bad manifest blob"),
							ConfigBlob:    configBlob,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			query := "repo1"
			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"

			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockSearchDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo good manifest refferenced and bad config blob", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Descriptions repo1",
							LogoPath:    "test/logoPath",
						},
					}

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

					manifestMetas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    []byte("bad config blob"),
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			query := "repo1"
			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"
			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockSearchDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags gives error", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			const query = "repo1:1.0.1"
			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags is successful", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Descriptions repo1",
							LogoPath:    "test/logoPath",
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
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob1,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
						"digestTag1.0.2": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob2,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			const query = "repo1:1.0.1"
			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB,
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
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaUpdateTime
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockSearchDB)
			So(err, ShouldNotBeNil)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo Bad manifest refferenced", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
						{
							Name: "repo2",
							Tags: map[string]string{
								"1.0.2": "digestTag1.0.2",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo2",
							LogoPath:    "test/logoPath",
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
							ManifestBlob:  []byte("bad manifest blob"),
							ConfigBlob:    configBlob1,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
						"digestTag1.0.2": {
							ManifestBlob:  []byte("bad manifest blob"),
							ConfigBlob:    configBlob1,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetas, nil
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaUpdateTime
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockSearchDB)
			So(err, ShouldBeNil)
			So(repos, ShouldNotBeEmpty)
		})

		Convey("Working SearchRepo function", func() {
			createTime := time.Now()
			createTime2 := createTime.Add(time.Second)
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
					So(err, ShouldBeNil)

					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
						{
							Name: "repo2",
							Tags: map[string]string{
								"1.0.2": "digestTag1.0.2",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo2",
							LogoPath:    "test/logoPath",
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
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob1,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
						"digestTag1.0.2": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob2,
							DownloadCount: 100,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetas, nil
				},
			}
			Convey("RepoDB missing requestedPage", func() {
				responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
					graphql.DefaultRecover)
				mockCve := mocks.CveInfoMock{}
				repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), nil, mockSearchDB)
				So(err, ShouldBeNil)
				So(repos, ShouldNotBeEmpty)
			})

			Convey("RepoDB SearchRepo is successful", func() {
				limit := 2
				offset := 0
				sortCriteria := gql_generated.SortCriteriaUpdateTime
				pageInput := gql_generated.PageInput{
					Limit:  &limit,
					Offset: &offset,
					SortBy: &sortCriteria,
				}

				responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
					graphql.DefaultRecover)

				mockCve := mocks.CveInfoMock{}
				repos, err := repoListWithNewestImage(responseContext, mockCve,
					log.NewLogger("debug", ""), &pageInput, mockSearchDB)
				So(err, ShouldBeNil)
				So(repos, ShouldNotBeEmpty)
				So(len(repos), ShouldEqual, 2)
				So(*repos[0].Name, ShouldEqual, "repo2")
				So(*repos[0].LastUpdated, ShouldEqual, createTime2)
			})
		})
	})
}

func TestImageListForDigest(t *testing.T) {
	Convey("getImageList", t, func() {
		Convey("no page requested, SearchRepoFn returns error", func() {
			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err := getImageListForDigest(responseContext, "invalid", mockSearchDB, mocks.CveInfoMock{}, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("invalid manifest blob", func() {
			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]string{
								"1.0.1": "digestTag1.0.1",
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
					}

					configBlob, err := json.Marshal(ispec.Image{
						Config: ispec.ImageConfig{
							Labels: map[string]string{},
						},
					})
					So(err, ShouldBeNil)

					manifestBlob := []byte("invalid")

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					return repos, manifestMetaDatas, nil
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageList, err := getImageListForDigest(responseContext, "test", mockSearchDB, mocks.CveInfoMock{}, nil)
			So(err, ShouldBeNil)
			So(imageList, ShouldBeEmpty)
		})

		Convey("valid repoListForDigest returned for matching manifest digest", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]string{
								"1.0.1": manifestDigest,
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
					}

					configBlob, err := json.Marshal(ispec.ImageConfig{})
					So(err, ShouldBeNil)

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDigest := range repos[0].Tags {
						if !filter(repos[0], manifestMetaDatas[manifestDigest]) {
							delete(matchedTags, tag)
							delete(manifestMetaDatas, manifestDigest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestMetaDatas, nil
				},
			}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageListForDigest(responseContext, manifestDigest,
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 1)

			imageSummaries, err = getImageListForDigest(responseContext, "invalid",
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 0)
		})

		Convey("valid repoListForDigest returned for matching config digest", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			configDigest := godigest.FromBytes(configBlob)

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]string{
								"1.0.1": manifestDigest,
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
					}

					manifestBlob, err := json.Marshal(ispec.Manifest{
						Config: ispec.Descriptor{
							Digest: configDigest,
						},
					})
					So(err, ShouldBeNil)

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDigest := range repos[0].Tags {
						if !filter(repos[0], manifestMetaDatas[manifestDigest]) {
							delete(matchedTags, tag)
							delete(manifestMetaDatas, manifestDigest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestMetaDatas, nil
				},
			}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageListForDigest(responseContext, configDigest.String(),
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 1)
		})

		Convey("valid repoListForDigest returned for matching layer digest", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			layerDigest := godigest.Digest("validDigest")

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]string{
								"1.0.1": manifestDigest,
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
					}

					manifestBlob, err := json.Marshal(ispec.Manifest{
						Layers: []ispec.Descriptor{
							{
								Digest: layerDigest,
							},
						},
					})
					So(err, ShouldBeNil)

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDigest := range repos[0].Tags {
						if !filter(repos[0], manifestMetaDatas[manifestDigest]) {
							delete(matchedTags, tag)
							delete(manifestMetaDatas, manifestDigest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestMetaDatas, nil
				},
			}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageListForDigest(responseContext, layerDigest.String(),
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 1)
		})

		Convey("valid repoListForDigest, multiple matching tags", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]string{
								"1.0.1": manifestDigest,
								"1.0.2": manifestDigest,
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
					}

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					for i, repo := range repos {
						matchedTags := repo.Tags

						for tag, manifestDigest := range repo.Tags {
							if !filter(repo, manifestMetaDatas[manifestDigest]) {
								delete(matchedTags, tag)
								delete(manifestMetaDatas, manifestDigest)

								continue
							}
						}

						repos[i].Tags = matchedTags
					}

					return repos, manifestMetaDatas, nil
				},
			}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageListForDigest(responseContext, manifestDigest,
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 2)
		})

		Convey("valid repoListForDigest, multiple matching tags limited by pageInput", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
					}

					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]string{
								"1.0.1": manifestDigest,
								"1.0.2": manifestDigest,
							},
							Signatures:  []string{"testSignature"},
							Stars:       100,
							Description: "Description repo1",
							LogoPath:    "test/logoPath",
						},
					}

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures:    make(map[string][]string),
							Dependencies:  make([]string, 0),
							Dependants:    make([]string, 0),
							BlobsSize:     0,
							BlobCount:     0,
						},
					}

					for i, repo := range repos {
						matchedTags := repo.Tags

						for tag, manifestDigest := range repo.Tags {
							if !filter(repo, manifestMetaDatas[manifestDigest]) {
								delete(matchedTags, tag)
								delete(manifestMetaDatas, manifestDigest)

								continue
							}
						}

						repos[i].Tags = matchedTags

						pageFinder.Add(repodb.DetailedRepoMeta{
							RepoMeta: repo,
						})
					}

					repos = pageFinder.Page()

					return repos, manifestMetaDatas, nil
				},
			}

			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageListForDigest(responseContext, manifestDigest,
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 1)
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
			Architecture: "amd64",
			OS:           "linux",
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
