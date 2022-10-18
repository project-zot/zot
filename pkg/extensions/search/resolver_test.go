package search //nolint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		const query = "repo1"
		Convey("RepoDB SearchRepos error", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), repodb.PageInfo{}, ErrTestError
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
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo is successful", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
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

					return repos, manifestMetas, repodb.PageInfo{}, nil
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
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldNotBeEmpty)
			So(len(repos.Results[0].Vendors), ShouldEqual, 2)
		})

		Convey("RepoDB SearchRepo Bad manifest refferenced", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
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

					return repos, manifestMetas, repodb.PageInfo{}, nil
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
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo good manifest refferenced and bad config blob", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
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

					return repos, manifestMetas, repodb.PageInfo{}, nil
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
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldNotBeEmpty)

			query = "repo1:1.0.1"
			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags gives error", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), repodb.PageInfo{}, ErrTestError
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
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags is successful", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
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

					return repos, manifestMetas, repodb.PageInfo{}, nil
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
			repos, images, layers, err := globalSearch(responseContext, query, mockRepoDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldNotBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})
	})
}

func TestRepoListWithNewestImage(t *testing.T) {
	Convey("RepoListWithNewestImage", t, func() {
		Convey("RepoDB SearchRepos error", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), repodb.PageInfo{}, ErrTestError
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
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockRepoDB)
			So(err, ShouldNotBeNil)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo Bad manifest refferenced", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
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

					return repos, manifestMetas, repodb.PageInfo{}, nil
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
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockRepoDB)
			So(err, ShouldBeNil)
			So(repos.Results, ShouldNotBeEmpty)
		})

		Convey("Working SearchRepo function", func() {
			createTime := time.Now()
			createTime2 := createTime.Add(time.Second)
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
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

					repos, _ = pageFinder.Page()

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

					return repos, manifestMetas, repodb.PageInfo{}, nil
				},
			}
			Convey("RepoDB missing requestedPage", func() {
				responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
					graphql.DefaultRecover)
				mockCve := mocks.CveInfoMock{}
				repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), nil, mockRepoDB)
				So(err, ShouldBeNil)
				So(repos.Results, ShouldNotBeEmpty)
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
					log.NewLogger("debug", ""), &pageInput, mockRepoDB)
				So(err, ShouldBeNil)
				So(repos, ShouldNotBeEmpty)
				So(len(repos.Results), ShouldEqual, 2)
				So(*repos.Results[0].Name, ShouldEqual, "repo2")
				So(*repos.Results[0].LastUpdated, ShouldEqual, createTime2)
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

					repos, _ = pageFinder.Page()

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

func TestImageList(t *testing.T) {
	Convey("getImageList", t, func() {
		testLogger := log.NewLogger("debug", "")
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

			_, err := getImageList(responseContext, "test", mockSearchDB, mocks.CveInfoMock{}, nil, testLogger)
			So(err, ShouldNotBeNil)
		})

		Convey("valid repoList returned", func() {
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

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

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

			imageSummaries, err := getImageList(responseContext, "test", mockSearchDB,
				mocks.CveInfoMock{}, &pageInput, testLogger)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 1)

			imageSummaries, err = getImageList(responseContext, "invalid", mockSearchDB,
				mocks.CveInfoMock{}, &pageInput, testLogger)
			So(err, ShouldBeNil)
			So(len(imageSummaries), ShouldEqual, 0)
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

func TestCVEResolvers(t *testing.T) { //nolint:gocyclo
	repoDB, err := repodb.NewBoltDBWrapper(repodb.BoltDBParameters{
		RootDir: t.TempDir(),
	})
	if err != nil {
		panic(err)
	}

	// Create repodb data for scannable image with vulnerabilities
	// Create manifets metadata first
	timeStamp1 := time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC)

	configBlob1, err := json.Marshal(ispec.Image{
		Created: &timeStamp1,
	})
	if err != nil {
		panic(err)
	}

	manifestBlob1, err := json.Marshal(ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Size:      0,
			Digest:    godigest.FromBytes(configBlob1),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Size:      0,
				Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
			},
		},
	})
	if err != nil {
		panic(err)
	}

	repoMeta1 := repodb.ManifestMetadata{
		ManifestBlob: manifestBlob1,
		ConfigBlob:   configBlob1,
	}

	digest1 := godigest.FromBytes(manifestBlob1)

	err = repoDB.SetManifestMeta(digest1, repoMeta1)
	if err != nil {
		panic(err)
	}

	timeStamp2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)

	configBlob2, err := json.Marshal(ispec.Image{
		Created: &timeStamp2,
	})
	if err != nil {
		panic(err)
	}

	manifestBlob2, err := json.Marshal(ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Size:      0,
			Digest:    godigest.FromBytes(configBlob2),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Size:      0,
				Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
			},
		},
	})
	if err != nil {
		panic(err)
	}

	repoMeta2 := repodb.ManifestMetadata{
		ManifestBlob: manifestBlob2,
		ConfigBlob:   configBlob2,
	}

	digest2 := godigest.FromBytes(manifestBlob2)

	err = repoDB.SetManifestMeta(digest2, repoMeta2)
	if err != nil {
		panic(err)
	}

	timeStamp3 := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)

	configBlob3, err := json.Marshal(ispec.Image{
		Created: &timeStamp3,
	})
	if err != nil {
		panic(err)
	}

	manifestBlob3, err := json.Marshal(ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Size:      0,
			Digest:    godigest.FromBytes(configBlob3),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Size:      0,
				Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
			},
		},
	})
	if err != nil {
		panic(err)
	}

	repoMeta3 := repodb.ManifestMetadata{
		ManifestBlob: manifestBlob3,
		ConfigBlob:   configBlob3,
	}

	digest3 := godigest.FromBytes(manifestBlob3)

	err = repoDB.SetManifestMeta(digest3, repoMeta3)
	if err != nil {
		panic(err)
	}

	// Create the repo metadata using previously defined manifests
	tagsMap := map[string]godigest.Digest{}
	tagsMap["repo1:1.0.0"] = digest1
	tagsMap["repo1:1.0.1"] = digest2
	tagsMap["repo1:1.1.0"] = digest3
	tagsMap["repo1:latest"] = digest3
	tagsMap["repo2:2.0.0"] = digest1
	tagsMap["repo2:2.0.1"] = digest2
	tagsMap["repo2:2.1.0"] = digest3
	tagsMap["repo2:latest"] = digest3
	tagsMap["repo3:3.0.1"] = digest2
	tagsMap["repo3:3.1.0"] = digest3
	tagsMap["repo3:latest"] = digest3

	for image, digest := range tagsMap {
		repo, tag := common.GetImageDirAndTag(image)

		err := repoDB.SetRepoTag(repo, tag, digest)
		if err != nil {
			panic(err)
		}
	}

	// Create the repo metadata using previously defined manifests

	// RepoDB loaded with initial data, mock the scanner
	severities := map[string]int{
		"UNKNOWN":  0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	// Setup test CVE data in mock scanner
	scanner := mocks.CveScannerMock{
		ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
			digest, ok := tagsMap[image]
			if !ok {
				return map[string]cvemodel.CVE{}, nil
			}

			if digest.String() == digest1.String() {
				return map[string]cvemodel.CVE{
					"CVE1": {
						ID:          "CVE1",
						Severity:    "HIGH",
						Title:       "Title CVE1",
						Description: "Description CVE1",
					},
					"CVE2": {
						ID:          "CVE2",
						Severity:    "MEDIM",
						Title:       "Title CVE2",
						Description: "Description CVE2",
					},
					"CVE3": {
						ID:          "CVE3",
						Severity:    "LOW",
						Title:       "Title CVE3",
						Description: "Description CVE3",
					},
				}, nil
			}

			if digest.String() == digest2.String() {
				return map[string]cvemodel.CVE{
					"CVE2": {
						ID:          "CVE2",
						Severity:    "MEDIUM",
						Title:       "Title CVE2",
						Description: "Description CVE2",
					},
					"CVE3": {
						ID:          "CVE3",
						Severity:    "LOW",
						Title:       "Title CVE3",
						Description: "Description CVE3",
					},
				}, nil
			}

			if digest.String() == digest3.String() {
				return map[string]cvemodel.CVE{
					"CVE3": {
						ID:          "CVE3",
						Severity:    "LOW",
						Title:       "Title CVE3",
						Description: "Description CVE3",
					},
				}, nil
			}

			// By default the image has no vulnerabilities
			return map[string]cvemodel.CVE{}, nil
		},
		CompareSeveritiesFn: func(severity1, severity2 string) int {
			return severities[severity2] - severities[severity1]
		},
	}

	log := log.NewLogger("debug", "")

	cveInfo := &cveinfo.BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		RepoDB:  repoDB,
	}

	Convey("Get CVE list for image ", t, func() {
		Convey("Unpaginated request to get all CVEs in an image", func() {
			// CVE pagination will be implemented later

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			cveResult, err := getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves := []string{"CVE1", "CVE2", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.1", cveInfo, log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.1")

			expectedCves = []string{"CVE2", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.1.0", cveInfo, log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.1.0")

			expectedCves = []string{"CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}
		})
	})

	Convey("Get a list of images affected by a particular CVE ", t, func() {
		Convey("Unpaginated request", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			images, err := getImageListForCVE(responseContext, "CVE1", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.0",
				"repo2:2.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1",
				"repo2:2.0.0", "repo2:2.0.1",
				"repo3:3.0.1",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
				"repo2:2.0.0", "repo2:2.0.1", "repo2:2.1.0", "repo2:latest",
				"repo3:3.0.1", "repo3:3.1.0", "repo3:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}
		})

		Convey("Paginated requests", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover,
			)

			pageInput := getPageInput(1, 0)

			images, err := getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)

			pageInput = getPageInput(1, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)

			pageInput = getPageInput(2, 0)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0",
				"repo2:2.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0",
				"repo2:2.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)

			pageInput = getPageInput(5, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1",
				"repo2:2.0.0", "repo2:2.0.1",
				"repo3:3.0.1",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 3)

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.1",
				"repo3:3.0.1",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
				"repo2:2.0.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 5)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.1", "repo2:2.1.0", "repo2:latest",
				"repo3:3.0.1", "repo3:3.1.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 10)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo3:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}
		})
	})

	Convey("Get a list of images where a particular CVE is fixed", t, func() {
		Convey("Unpaginated request", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			images, err := getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE3", "repo1", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)
		})

		Convey("Paginated requests", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover,
			)

			pageInput := getPageInput(1, 0)

			images, err := getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.1",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 3)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)

			pageInput = getPageInput(1, 10)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)

			pageInput = getPageInput(2, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(2, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(2, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images), ShouldEqual, len(expectedImages))

			for _, image := range images {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images), ShouldEqual, 0)
		})
	})
}

func getPageInput(limit int, offset int) *gql_generated.PageInput {
	sortCriteria := gql_generated.SortCriteriaAlphabeticAsc

	return &gql_generated.PageInput{
		Limit:  &limit,
		Offset: &offset,
		SortBy: &sortCriteria,
	}
}
