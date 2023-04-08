package search //nolint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
					error,
				) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata),
						map[string]repodb.IndexData{}, repodb.PageInfo{}, ErrTestError
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
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
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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

					return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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

		Convey("RepoDB SearchRepo Bad manifest referenced", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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

					return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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

		Convey("RepoDB SearchRepo good manifest referenced and bad config blob", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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

					return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
					error,
				) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata),
						map[string]repodb.IndexData{}, repodb.PageInfo{}, ErrTestError
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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

					return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
					error,
				) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata),
						map[string]repodb.IndexData{}, repodb.PageInfo{}, ErrTestError
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

		Convey("RepoDB SearchRepo Bad manifest referenced", func() {
			mockRepoDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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

					return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
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
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
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
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
		Convey("no page requested, FilterTagsFn returns error", func() {
			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
					error,
				) {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
						repodb.PageInfo{}, ErrTestError
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {Digest: "digestTag1.0.1", MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
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
						},
					}

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageList, err := getImageListForDigest(responseContext, "test", mockSearchDB, mocks.CveInfoMock{}, nil)
			So(err, ShouldBeNil)
			So(imageList.Results, ShouldBeEmpty)
		})

		Convey("valid imageListForDigest returned for matching manifest digest", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
						},
					}

					configBlob, err := json.Marshal(ispec.ImageConfig{})
					So(err, ShouldBeNil)

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}
					matchedTags := repos[0].Tags
					for tag, manifestDescriptor := range repos[0].Tags {
						if !filter(repos[0], manifestMetaDatas[manifestDescriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestMetaDatas, manifestDescriptor.Digest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
			So(len(imageSummaries.Results), ShouldEqual, 1)

			imageSummaries, err = getImageListForDigest(responseContext, "invalid",
				mockSearchDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 0)
		})

		Convey("valid imageListForDigest returned for matching config digest", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			configDigest := godigest.FromBytes(configBlob)

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
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
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDescriptor := range repos[0].Tags {
						if !filter(repos[0], manifestMetaDatas[manifestDescriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestMetaDatas, manifestDescriptor.Digest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
			So(len(imageSummaries.Results), ShouldEqual, 1)
		})

		Convey("valid imageListForDigest returned for matching layer digest", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			layerDigest := godigest.Digest("validDigest")

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
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
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDescriptor := range repos[0].Tags {
						if !filter(repos[0], manifestMetaDatas[manifestDescriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestMetaDatas, manifestDescriptor.Digest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
			So(len(imageSummaries.Results), ShouldEqual, 1)
		})

		Convey("valid imageListForDigest, multiple matching tags", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
								"1.0.2": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
						},
					}

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					for i, repo := range repos {
						matchedTags := repo.Tags

						for tag, manifestDescriptor := range repo.Tags {
							if !filter(repo, manifestMetaDatas[manifestDescriptor.Digest]) {
								delete(matchedTags, tag)
								delete(manifestMetaDatas, manifestDescriptor.Digest)

								continue
							}
						}

						repos[i].Tags = matchedTags
					}

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
			So(len(imageSummaries.Results), ShouldEqual, 2)
		})

		Convey("valid imageListForDigest, multiple matching tags limited by pageInput", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
					error,
				) {
					pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset,
						requestedPage.SortBy)
					if err != nil {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							repodb.PageInfo{}, err
					}

					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
								"1.0.2": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
						},
					}

					manifestMetaDatas := map[string]repodb.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					for i, repo := range repos {
						matchedTags := repo.Tags

						for tag, manifestDescriptor := range repo.Tags {
							if !filter(repo, manifestMetaDatas[manifestDescriptor.Digest]) {
								delete(matchedTags, tag)
								delete(manifestMetaDatas, manifestDescriptor.Digest)

								continue
							}
						}

						repos[i].Tags = matchedTags

						pageFinder.Add(repodb.DetailedRepoMeta{
							RepoMeta: repo,
						})
					}

					repos, _ = pageFinder.Page()

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
			So(len(imageSummaries.Results), ShouldEqual, 1)
		})
	})
}

func TestGetImageSummary(t *testing.T) {
	Convey("GetImageSummary", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		Convey("Media Type: ImageManifest", func() {
			Convey("repoDB.GetManifestMeta fails", func() {
				var (
					repoDB = mocks.RepoDBMock{
						GetManifestDataFn: func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
							return repodb.ManifestData{}, ErrTestError
						},
						GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
							return repodb.RepoMetadata{
								Tags: map[string]repodb.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, repoDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})

			Convey("0 len return", func() {
				var (
					repoDB = mocks.RepoDBMock{
						GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
							return repodb.RepoMetadata{
								Tags: map[string]repodb.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, repoDB, mocks.CveInfoMock{}, log)
				So(err, ShouldBeNil)
			})

			Convey("digest != nil && *digest != actual image digest", func() {
				var (
					repoDB = mocks.RepoDBMock{
						GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
							return repodb.ManifestMetadata{}, ErrTestError
						},
						GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
							return repodb.RepoMetadata{
								Tags: map[string]repodb.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")

					digest = "wrongDigest"
				)

				_, err := getImageSummary(responseContext, "repo", "tag", &digest, repoDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Media Type: ImageIndex", func() {
			Convey("repoDB.GetIndexData fails", func() {
				var (
					repoDB = mocks.RepoDBMock{
						GetIndexDataFn: func(indexDigest godigest.Digest) (repodb.IndexData, error) {
							return repodb.IndexData{}, ErrTestError
						},
						GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
							return repodb.RepoMetadata{
								Tags: map[string]repodb.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageIndex, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, repoDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})

			Convey("json.Unmarshal(indexData.IndexBlob, &indexContent) fails", func() {
				var (
					repoDB = mocks.RepoDBMock{
						GetIndexDataFn: func(indexDigest godigest.Digest) (repodb.IndexData, error) {
							return repodb.IndexData{
								IndexBlob: []byte("bad json"),
							}, nil
						},
						GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
							return repodb.RepoMetadata{
								Tags: map[string]repodb.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageIndex, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, repoDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})

			Convey("digest != nil", func() {
				index := ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							Digest:    "digest",
							MediaType: ispec.MediaTypeImageManifest,
						},
					},
				}

				indexBlob, err := json.Marshal(index)
				So(err, ShouldBeNil)

				repoDB := mocks.RepoDBMock{
					GetIndexDataFn: func(indexDigest godigest.Digest) (repodb.IndexData, error) {
						return repodb.IndexData{
							IndexBlob: indexBlob,
						}, nil
					},
					GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
						return repodb.RepoMetadata{
							Tags: map[string]repodb.Descriptor{
								"tag": {MediaType: ispec.MediaTypeImageIndex, Digest: "digest"},
							},
						}, nil
					},
				}

				log := log.NewLogger("debug", "")

				goodDigest := "goodDigest"

				Convey("digest not found", func() {
					wrongDigest := "wrongDigest"
					_, err = getImageSummary(responseContext, "repo", "tag", &wrongDigest, repoDB, mocks.CveInfoMock{}, log)
					So(err, ShouldNotBeNil)
				})

				Convey("GetManifestData error", func() {
					repoDB.GetManifestDataFn = func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
						return repodb.ManifestData{}, ErrTestError
					}

					_, err = getImageSummary(responseContext, "repo", "tag", &goodDigest, repoDB, mocks.CveInfoMock{}, log)
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey("Media Type: not supported", func() {
			var (
				repoDB = mocks.RepoDBMock{
					GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
						return repodb.RepoMetadata{
							Tags: map[string]repodb.Descriptor{
								"tag": {MediaType: "unknown", Digest: "digest"},
							},
						}, nil
					},
				}

				log = log.NewLogger("debug", "")
			)

			_, err := getImageSummary(responseContext, "repo", "tag", nil, repoDB, mocks.CveInfoMock{}, log)
			So(err, ShouldBeNil)
		})
	})
}

func TestFilterBaseImagesFn(t *testing.T) {
	Convey("FilterBaseImages", t, func() {
		filterFunc := filterBaseImages(&gql_generated.ImageSummary{})
		ok := filterFunc(
			repodb.RepoMetadata{},
			repodb.ManifestMetadata{
				ManifestBlob: []byte("bad json"),
			},
		)
		So(ok, ShouldBeFalse)
	})
}

func TestImageList(t *testing.T) {
	Convey("getImageList", t, func() {
		testLogger := log.NewLogger("debug", "")
		Convey("no page requested, SearchRepoFn returns error", func() {
			mockSearchDB := mocks.RepoDBMock{
				FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc,
					requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
					error,
				) {
					return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
						map[string]repodb.IndexData{}, repodb.PageInfo{}, ErrTestError
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
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
					repos := []repodb.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]repodb.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]repodb.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []repodb.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []repodb.LayerInfo{}},
									},
								},
							},
							Stars: 100,
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
							Signatures: repodb.ManifestSignatures{
								"cosign": []repodb.SignatureInfo{
									{SignatureManifestDigest: "digestSignature1"},
								},
							},
						},
					}

					return repos, manifestMetaDatas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
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
			So(len(imageSummaries.Results), ShouldEqual, 1)

			imageSummaries, err = getImageList(responseContext, "invalid", mockSearchDB,
				mocks.CveInfoMock{}, &pageInput, testLogger)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 0)
		})
	})
}

func TestGetReferrers(t *testing.T) {
	Convey("getReferrers", t, func() {
		referredDigest := godigest.FromString("t").String()

		Convey("referredDigest is empty", func() {
			testLogger := log.NewLogger("debug", "")

			_, err := getReferrers(mocks.RepoDBMock{}, "test", "", nil, testLogger)
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers returns error", func() {
			testLogger := log.NewLogger("debug", "")
			mockedStore := mocks.RepoDBMock{
				GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest, artifactTypes []string,
				) ([]repodb.ReferrerInfo, error) {
					return nil, ErrTestError
				},
			}

			_, err := getReferrers(mockedStore, "test", referredDigest, nil, testLogger)
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
			mockedStore := mocks.RepoDBMock{
				GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest, artifactTypes []string,
				) ([]repodb.ReferrerInfo, error) {
					return []repodb.ReferrerInfo{
						{
							Digest:       referrerDescriptor.Digest.String(),
							MediaType:    referrerDescriptor.MediaType,
							ArtifactType: referrerDescriptor.ArtifactType,
							Size:         int(referrerDescriptor.Size),
							Annotations:  referrerDescriptor.Annotations,
						},
					}, nil
				},
			}

			referrers, err := getReferrers(mockedStore, "test", referredDigest, nil, testLogger)
			So(err, ShouldBeNil)
			So(*referrers[0].ArtifactType, ShouldEqual, referrerDescriptor.ArtifactType)
			So(*referrers[0].MediaType, ShouldEqual, referrerDescriptor.MediaType)
			So(*referrers[0].Size, ShouldEqual, referrerDescriptor.Size)
			So(*referrers[0].Digest, ShouldEqual, referrerDescriptor.Digest)
			So(*referrers[0].Annotations[0].Value, ShouldEqual, referrerDescriptor.Annotations["key"])
		})
	})
}

func TestQueryResolverErrors(t *testing.T) {
	Convey("Errors", t, func() {
		log := log.NewLogger("debug", "")
		ctx := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		Convey("GlobalSearch error bad requested page", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			resolver := queryResolver{
				resolverConfig,
			}

			limit := -1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			_, err := resolver.GlobalSearch(ctx, "some_string", &gql_generated.Filter{}, &pageInput)
			So(err, ShouldNotBeNil)

			limit = 0
			offset = -1
			pageInput = gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			_, err = resolver.GlobalSearch(ctx, "some_string", &gql_generated.Filter{}, &pageInput)
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForCve error in GetMultipleRepoMeta", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.RepoDBMock{
					GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta repodb.RepoMetadata) bool,
						requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, error) {
						return []repodb.RepoMetadata{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "cve1", &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForCve error in FilterTags", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.RepoDBMock{
					FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
						repodb.PageInfo, error,
					) {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							repodb.PageInfo{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "cve1", &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListWithCVEFixed error in FilterTags", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.RepoDBMock{
					FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
						repodb.PageInfo, error,
					) {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							repodb.PageInfo{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListWithCVEFixed(ctx, "cve1", "image", &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("RepoListWithNewestImage repoListWithNewestImage() errors mocked StoreController", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.RepoDBMock{
					SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter,
						requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
						repodb.PageInfo, error,
					) {
						return nil, nil, nil, repodb.PageInfo{}, ErrTestError
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

		Convey("RepoListWithNewestImage repoListWithNewestImage() errors valid StoreController", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.RepoDBMock{
					SearchReposFn: func(ctx context.Context, searchText string, filter repodb.Filter,
						requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
						repodb.PageInfo, error,
					) {
						return nil, nil, nil, repodb.PageInfo{}, ErrTestError
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
				storage.StoreController{},
				mocks.RepoDBMock{
					FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
						repodb.PageInfo, error,
					) {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							repodb.PageInfo{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageList(ctx, "repo", &gql_generated.PageInput{})
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

			_, err := qr.DerivedImageList(ctx, "repo:tag", nil, &gql_generated.PageInput{})
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

			_, err := qr.BaseImageList(ctx, "repo:tag", nil, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("DerivedImageList and BaseImage List FilterTags() errors", func() {
			configBlob, err := json.Marshal(ispec.Image{
				Config: ispec.ImageConfig{
					Labels: map[string]string{},
				},
			})
			So(err, ShouldBeNil)

			manifest := ispec.Manifest{}

			manifestBlob, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob)

			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.RepoDBMock{
					FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
					) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
						repodb.PageInfo, error,
					) {
						return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
							repodb.PageInfo{}, ErrTestError
					},
					GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
						return repodb.RepoMetadata{
							Name: "repo",
							Tags: map[string]repodb.Descriptor{
								"tag": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
							},
						}, nil
					},
					GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
						return repodb.ManifestMetadata{
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob,
						}, nil
					},
				},
				mocks.CveInfoMock{},
			)

			resolver := queryResolver{
				resolverConfig,
			}

			_, err = resolver.DerivedImageList(ctx, "repo:tag", nil, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)

			_, err = resolver.BaseImageList(ctx, "repo:tag", nil, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers error", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{
						GetReferrersFn: func(repo string, digest godigest.Digest, artifactTypes []string) (ispec.Index, error) {
							return ispec.Index{}, ErrTestError
						},
					},
				},
				mocks.RepoDBMock{},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.Referrers(ctx, "repo", "", nil)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestCVEResolvers(t *testing.T) { //nolint:gocyclo
	params := bolt.DBParameters{
		RootDir: t.TempDir(),
	}

	boltDriver, err := bolt.GetBoltDriver(params)
	if err != nil {
		panic(err)
	}

	log := log.NewLogger("debug", "")

	repoDB, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
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

	repoMeta1 := repodb.ManifestData{
		ManifestBlob: manifestBlob1,
		ConfigBlob:   configBlob1,
	}

	digest1 := godigest.FromBytes(manifestBlob1)

	err = repoDB.SetManifestData(digest1, repoMeta1)
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

	repoMeta2 := repodb.ManifestData{
		ManifestBlob: manifestBlob2,
		ConfigBlob:   configBlob2,
	}

	digest2 := godigest.FromBytes(manifestBlob2)

	err = repoDB.SetManifestData(digest2, repoMeta2)
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

	repoMeta3 := repodb.ManifestData{
		ManifestBlob: manifestBlob3,
		ConfigBlob:   configBlob3,
	}

	digest3 := godigest.FromBytes(manifestBlob3)

	err = repoDB.SetManifestData(digest3, repoMeta3)
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

		err := repoDB.SetRepoReference(repo, tag, digest, ispec.MediaTypeImageManifest)
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
					"CVE34": {
						ID:          "CVE34",
						Severity:    "LOW",
						Title:       "Title for CVE34",
						Description: "Description CVE34",
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

	cveInfo := &cveinfo.BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		RepoDB:  repoDB,
	}

	Convey("Get CVE list for image ", t, func() {
		Convey("Unpaginated request to get all CVEs in an image", func() {
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := &gql_generated.PageInput{
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			dig := godigest.FromString("dig")
			repoWithDigestRef := fmt.Sprintf("repo@%s", dig)

			_, err := getCVEListForImage(responseContext, repoWithDigestRef, cveInfo, pageInput, "", log)
			So(err.Error(), ShouldContainSubstring, "reference by digest not supported")

			cveResult, err := getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves := []string{"CVE1", "CVE2", "CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			// test searching CVE by id in results
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "CVE3", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			// test searching CVE by id in results - no matches
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "CVE100", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")
			So(len(cveResult.CVEList), ShouldEqual, 0)

			// test searching CVE by id in results - partial name
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "VE3", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			// test searching CVE by title in results
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "Title CVE", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE1", "CVE2", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.1", cveInfo, pageInput, "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.1")

			expectedCves = []string{"CVE2", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.1.0", cveInfo, pageInput, "", log)
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
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1",
				"repo2:2.0.0", "repo2:2.0.1",
				"repo3:3.0.1",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
				"repo2:2.0.0", "repo2:2.0.1", "repo2:2.1.0", "repo2:latest",
				"repo3:3.0.1", "repo3:3.1.0", "repo3:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
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
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(1, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(2, 0)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0",
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0",
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(5, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1",
				"repo2:2.0.0", "repo2:2.0.1",
				"repo3:3.0.1",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 3)

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.1",
				"repo3:3.0.1",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.0", "repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 5)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.1", "repo2:2.1.0", "repo2:latest",
				"repo3:3.0.1", "repo3:3.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 10)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo3:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
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
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE3", "repo1", cveInfo, nil, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)
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
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 3)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(1, 10)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(2, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(2, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(2, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, pageInput, repoDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)
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

func TestDerivedImageList(t *testing.T) {
	Convey("RepoDB FilterTags error", t, func() {
		mockSearchDB := mocks.RepoDBMock{
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata),
					make(map[string]repodb.IndexData), repodb.PageInfo{}, ErrTestError
			},
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{}, ErrTestError
			},
			GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
				return repodb.ManifestMetadata{}, ErrTestError
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockSearchDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	//nolint: dupl
	Convey("RepoDB FilterTags no repo available", t, func() {
		configBlob, err := json.Marshal(ispec.Image{
			Config: ispec.ImageConfig{
				Labels: map[string]string{},
			},
		})
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{}

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBlob)

		mockSearchDB := mocks.RepoDBMock{
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
					repodb.PageInfo{}, nil
			},
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Name: "repo1",
					Tags: map[string]repodb.Descriptor{
						"1.0.1": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
				return repodb.ManifestMetadata{
					ManifestBlob: manifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockSearchDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	//nolint: dupl
	Convey("derived image list working", t, func() {
		configBlob, err := json.Marshal(ispec.Image{
			Config: ispec.ImageConfig{
				Labels: map[string]string{},
			},
		})
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
			{13, 14, 15, 11},
		}

		manifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		})
		So(err, ShouldBeNil)

		derivedManifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
			},
		})
		So(err, ShouldBeNil)

		manifestMetas := map[string]repodb.ManifestMetadata{
			"digestTag1.0.1": {
				ManifestBlob:  manifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
			"digestTag1.0.2": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
			"digestTag1.0.3": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
		}
		manifestDigest := godigest.FromBytes(manifestBlob)

		mockSearchDB := mocks.RepoDBMock{
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Name: "repo1",
					Tags: map[string]repodb.Descriptor{
						"1.0.1": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
				return repodb.ManifestData{
					ManifestBlob: manifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
				So(err, ShouldBeNil)

				repos := []repodb.RepoMetadata{
					{
						Name: "repo1",
						Tags: map[string]repodb.Descriptor{
							"1.0.1": {Digest: "digestTag1.0.1", MediaType: ispec.MediaTypeImageManifest},
							"1.0.2": {Digest: "digestTag1.0.2", MediaType: ispec.MediaTypeImageManifest},
							"1.0.3": {Digest: "digestTag1.0.3", MediaType: ispec.MediaTypeImageManifest},
						},
						Stars: 100,
					},
				}

				for i, repo := range repos {
					matchedTags := repo.Tags

					for tag, descriptor := range repo.Tags {
						if !filter(repo, manifestMetas[descriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestMetas, descriptor.Digest)

							continue
						}
					}

					repos[i].Tags = matchedTags

					pageFinder.Add(repodb.DetailedRepoMeta{
						RepoMeta: repo,
					})
				}
				repos, pageInfo := pageFinder.Page()

				return repos, manifestMetas, map[string]repodb.IndexData{}, pageInfo, nil
			},
		}

		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}

		Convey("valid derivedImageList, results not affected by pageInput", func() {
			images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockSearchDB, &gql_generated.PageInput{},
				mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, 2)
		})

		Convey("valid derivedImageList, results affected by pageInput", func() {
			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockSearchDB, &pageInput,
				mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, limit)
		})
	})
}

func TestBaseImageList(t *testing.T) {
	Convey("RepoDB FilterTags error", t, func() {
		mockSearchDB := mocks.RepoDBMock{
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
					repodb.PageInfo{}, ErrTestError
			},
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{}, ErrTestError
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
				return repodb.ManifestData{}, ErrTestError
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockSearchDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	//nolint: dupl
	Convey("RepoDB FilterTags no repo available", t, func() {
		configBlob, err := json.Marshal(ispec.Image{
			Config: ispec.ImageConfig{
				Labels: map[string]string{},
			},
		})
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{}

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBlob)

		mockSearchDB := mocks.RepoDBMock{
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
					repodb.PageInfo{}, nil
			},
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Name: "repo1",
					Tags: map[string]repodb.Descriptor{
						"1.0.2": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
				return repodb.ManifestData{
					ManifestBlob: manifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockSearchDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	//nolint: dupl
	Convey("base image list working", t, func() {
		configBlob, err := json.Marshal(ispec.Image{
			Config: ispec.ImageConfig{
				Labels: map[string]string{},
			},
		})
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
			{13, 14, 15, 11},
		}

		manifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		})
		So(err, ShouldBeNil)

		derivedManifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
			},
		})
		So(err, ShouldBeNil)

		manifestMetas := map[string]repodb.ManifestMetadata{
			"digestTag1.0.1": {
				ManifestBlob:  manifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
			"digestTag1.0.2": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
		}
		derivedManifestDigest := godigest.FromBytes(derivedManifestBlob)

		mockSearchDB := mocks.RepoDBMock{
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Name: "repo1",
					Tags: map[string]repodb.Descriptor{
						"1.0.2": {Digest: derivedManifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
				return repodb.ManifestData{
					ManifestBlob: derivedManifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
				So(err, ShouldBeNil)

				repos := []repodb.RepoMetadata{
					{
						Name: "repo1",
						Tags: map[string]repodb.Descriptor{
							"1.0.1": {Digest: "digestTag1.0.1", MediaType: ispec.MediaTypeImageManifest},
							"1.0.3": {Digest: "digestTag1.0.1", MediaType: ispec.MediaTypeImageManifest},
							"1.0.2": {Digest: "digestTag1.0.2", MediaType: ispec.MediaTypeImageManifest},
						},
						Stars: 100,
					},
				}

				for i, repo := range repos {
					matchedTags := repo.Tags

					for tag, descriptor := range repo.Tags {
						if !filter(repo, manifestMetas[descriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestMetas, descriptor.Digest)

							continue
						}
					}

					repos[i].Tags = matchedTags

					pageFinder.Add(repodb.DetailedRepoMeta{
						RepoMeta: repo,
					})
				}

				repos, pageInfo := pageFinder.Page()

				return repos, manifestMetas, map[string]repodb.IndexData{}, pageInfo, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}

		Convey("valid baseImageList, results not affected by pageInput", func() {
			images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockSearchDB,
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, 2)
			expectedTags := []string{"1.0.1", "1.0.3"}
			So(expectedTags, ShouldContain, *images.Results[0].Tag)
			So(expectedTags, ShouldContain, *images.Results[1].Tag)
		})

		Convey("valid baseImageList, results affected by pageInput", func() {
			limit := 1
			offset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &offset,
				SortBy: &sortCriteria,
			}

			images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockSearchDB,
				&pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, limit)
			So(*images.Results[0].Tag, ShouldEqual, "1.0.1")
		})
	})

	//nolint: dupl
	Convey("filterTags working, no base image list found", t, func() {
		configBlob, err := json.Marshal(ispec.Image{
			Config: ispec.ImageConfig{
				Labels: map[string]string{},
			},
		})
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
			{13, 14, 15, 11},
		}

		manifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		})
		So(err, ShouldBeNil)

		derivedManifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
			},
		})
		So(err, ShouldBeNil)

		manifestMetas := map[string]repodb.ManifestMetadata{
			"digestTag1.0.1": {
				ManifestBlob:  manifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
			"digestTag1.0.2": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(repodb.ManifestSignatures),
			},
		}
		derivedManifestDigest := godigest.FromBytes(derivedManifestBlob)

		mockSearchDB := mocks.RepoDBMock{
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Name: "repo1",
					Tags: map[string]repodb.Descriptor{
						"1.0.2": {Digest: derivedManifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
				return repodb.ManifestData{
					ManifestBlob: derivedManifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
			FilterTagsFn: func(ctx context.Context, filter repodb.FilterFunc, requestedPage repodb.PageInput,
			) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
				repodb.PageInfo, error,
			) {
				pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
				So(err, ShouldBeNil)

				repos := []repodb.RepoMetadata{
					{
						Name: "repo1",
						Tags: map[string]repodb.Descriptor{
							"1.0.1": {Digest: "digestTag1.0.1", MediaType: ispec.MediaTypeImageManifest},
							"1.0.2": {Digest: "digestTag1.0.2", MediaType: ispec.MediaTypeImageManifest},
						},
						Stars: 100,
					},
				}

				for i, repo := range repos {
					matchedTags := repo.Tags

					for tag, descriptor := range repo.Tags {
						if !filter(repo, manifestMetas[descriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestMetas, descriptor.Digest)

							continue
						}
					}

					repos[i].Tags = matchedTags

					pageFinder.Add(repodb.DetailedRepoMeta{
						RepoMeta: repo,
					})
				}

				return repos, manifestMetas, map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockSearchDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(images.Results, ShouldBeEmpty)
	})
}

func TestExpandedRepoInfo(t *testing.T) {
	Convey("ExpandedRepoInfo Errors", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		repoDB := mocks.RepoDBMock{
			GetRepoMetaFn: func(repo string) (repodb.RepoMetadata, error) {
				return repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tagManifest": {
							Digest:    "errorDigest",
							MediaType: ispec.MediaTypeImageManifest,
						},
						"tagIndex": {
							Digest:    "digestIndex",
							MediaType: ispec.MediaTypeImageIndex,
						},
						"tagGoodIndexBadManifests": {
							Digest:    "goodIndexBadManifests",
							MediaType: ispec.MediaTypeImageIndex,
						},
					},
				}, nil
			},
			GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
				switch manifestDigest {
				case "errorDigest":
					return repodb.ManifestMetadata{}, ErrTestError
				default:
					return repodb.ManifestMetadata{
						ManifestBlob: []byte("{}"),
						ConfigBlob:   []byte("{}"),
					}, nil
				}
			},
			GetIndexDataFn: func(indexDigest godigest.Digest) (repodb.IndexData, error) {
				goodIndexBadManifestsBlob, err := json.Marshal(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							Digest:    "errorDigest",
							MediaType: ispec.MediaTypeImageManifest,
						},
					},
				})
				So(err, ShouldBeNil)

				switch indexDigest {
				case "errorIndexDigest":
					return repodb.IndexData{}, ErrTestError
				case "goodIndexBadManifests":
					return repodb.IndexData{
						IndexBlob: goodIndexBadManifestsBlob,
					}, nil
				default:
					return repodb.IndexData{}, nil
				}
			},
		}
		log := log.NewLogger("debug", "")

		_, err := expandedRepoInfo(responseContext, "repo", repoDB, mocks.CveInfoMock{}, log)
		So(err, ShouldBeNil)
	})
}
