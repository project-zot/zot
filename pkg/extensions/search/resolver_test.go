//go:build search

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
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/boltdb"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	reqCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		const query = "repo1"
		Convey("MetaDB SearchRepos error", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					return make([]mTypes.RepoMetadata, 0), make(map[string]mTypes.ManifestMetadata),
						map[string]mTypes.IndexData{}, ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("paginated fail", func() {
			pageInput := &gql_generated.PageInput{
				Limit: ref(-1),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, _, _, err := globalSearch(responseContext, "repo", mocks.MetaDBMock{}, &gql_generated.Filter{},
				pageInput, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)

			_, _, _, err = globalSearch(responseContext, "repo:tag", mocks.MetaDBMock{}, &gql_generated.Filter{},
				pageInput, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
		})

		Convey("MetaDB SearchRepo is successful", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
								"1.0.2": {
									Digest:    "digestTag1.0.2",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
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

					manifestsMeta := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldNotBeEmpty)
			So(len(repos.Results[0].Vendors), ShouldEqual, 2)
		})

		Convey("MetaDB SearchRepo Bad manifest referenced", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
									},
								},
							},
							Stars: 100,
						},
					}

					configBlob, err := json.Marshal(ispec.Image{})
					So(err, ShouldBeNil)

					manifestsMeta := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: []byte("bad manifest blob"),
							ConfigBlob:   configBlob,
						},
					}

					return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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

			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"

			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockMetaDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("MetaDB SearchRepo good manifest referenced and bad config blob", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
									},
								},
							},
							Stars: 100,
						},
					}

					manifestBlob, err := json.Marshal(ispec.Manifest{})
					So(err, ShouldBeNil)

					manifestsMeta := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   []byte("bad config blob"),
						},
					}

					return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldNotBeEmpty)

			query = "repo1:1.0.1"
			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockMetaDB,
				&gql_generated.Filter{}, &pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("MetaDB SearchTags gives error", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					return make([]mTypes.RepoMetadata, 0), make(map[string]mTypes.ManifestMetadata),
						map[string]mTypes.IndexData{}, ErrTestError
				},
			}
			const query = "repo1:1.0.1"
			mockCve := mocks.CveInfoMock{}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("MetaDB SearchTags is successful", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
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

					manifestsMeta := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB,
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
		Convey("MetaDB SearchRepos error", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error,
				) {
					return make([]mTypes.RepoMetadata, 0), make(map[string]mTypes.ManifestMetadata),
						map[string]mTypes.IndexData{}, ErrTestError
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
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockMetaDB)
			So(err, ShouldNotBeNil)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("paginated fail", func() {
			pageInput := &gql_generated.PageInput{
				Limit: ref(-1),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err := repoListWithNewestImage(responseContext, mocks.CveInfoMock{}, log.NewLogger("debug", ""),
				pageInput, mocks.MetaDBMock{})
			So(err, ShouldNotBeNil)
		})

		Convey("MetaDB SearchRepo bad manifest referenced", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
									},
								},
							},
							Stars: 100,
						},
						{
							Name: "repo2",
							Tags: map[string]mTypes.Descriptor{
								"1.0.2": {
									Digest:    "digestTag1.0.2",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
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

					manifestsMeta := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: []byte("bad manifest blob"),
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: []byte("bad manifest blob"),
							ConfigBlob:   configBlob1,
						},
					}

					return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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
			repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), &pageInput, mockMetaDB)
			So(err, ShouldBeNil)
			So(repos.Results, ShouldNotBeEmpty)
		})

		Convey("Working SearchRepo function", func() {
			createTime := time.Now()
			createTime2 := createTime.Add(time.Second)
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "repo1",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
									},
								},
							},
							Stars: 100,
						},
						{
							Name: "repo2",
							Tags: map[string]mTypes.Descriptor{
								"1.0.2": {
									Digest:    "digestTag1.0.2",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
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

					manifestsMeta := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob1,
						},
						"digestTag1.0.2": {
							ManifestBlob: manifestBlob,
							ConfigBlob:   configBlob2,
						},
					}

					return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
				},
			}
			Convey("MetaDB missing requestedPage", func() {
				responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
					graphql.DefaultRecover)
				mockCve := mocks.CveInfoMock{}
				repos, err := repoListWithNewestImage(responseContext, mockCve, log.NewLogger("debug", ""), nil, mockMetaDB)
				So(err, ShouldBeNil)
				So(repos.Results, ShouldNotBeEmpty)
			})

			Convey("MetaDB SearchRepo is successful", func() {
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
					log.NewLogger("debug", ""), &pageInput, mockMetaDB)
				So(err, ShouldBeNil)
				So(repos, ShouldNotBeEmpty)
				So(len(repos.Results), ShouldEqual, 2)
				So(*repos.Results[0].Name, ShouldEqual, "repo2")
				So(*repos.Results[0].LastUpdated, ShouldEqual, createTime2)
			})
		})
	})
}

func TestGetBookmarkedRepos(t *testing.T) {
	Convey("getBookmarkedRepos", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)
		_, err := getBookmarkedRepos(
			responseContext,
			mocks.CveInfoMock{},
			log.NewLogger("debug", ""),
			nil,
			mocks.MetaDBMock{
				GetBookmarkedReposFn: func(ctx context.Context) ([]string, error) {
					return []string{}, ErrTestError
				},
			},
		)
		So(err, ShouldNotBeNil)
	})
}

func TestGetStarredRepos(t *testing.T) {
	Convey("getStarredRepos", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)
		_, err := getStarredRepos(
			responseContext,
			mocks.CveInfoMock{},
			log.NewLogger("debug", ""),
			nil,
			mocks.MetaDBMock{
				GetStarredReposFn: func(ctx context.Context) ([]string, error) {
					return []string{}, ErrTestError
				},
			},
		)
		So(err, ShouldNotBeNil)
	})
}

func TestGetFilteredPaginatedRepos(t *testing.T) {
	Convey("getFilteredPaginatedRepos FilterRepos fails", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)
		_, err := getFilteredPaginatedRepos(
			responseContext,
			mocks.CveInfoMock{},
			func(repoMeta mTypes.RepoMetadata) bool { return true },
			log.NewLogger("debug", ""),
			nil,
			mocks.MetaDBMock{
				FilterReposFn: func(ctx context.Context, filter mTypes.FilterRepoFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						ErrTestError
				},
			},
		)
		So(err, ShouldNotBeNil)
	})

	Convey("Paginated convert fails", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)
		_, err := getFilteredPaginatedRepos(responseContext,
			mocks.CveInfoMock{},
			func(repoMeta mTypes.RepoMetadata) bool { return true },
			log.NewLogger("debug", ""),
			&gql_generated.PageInput{Limit: ref(-1)},
			mocks.MetaDBMock{},
		)
		So(err, ShouldNotBeNil)
	})
}

func TestImageListForDigest(t *testing.T) {
	Convey("getImageList", t, func() {
		Convey("no page requested, FilterTagsFn returns error", func() {
			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			_, err := getImageListForDigest(responseContext, "invalid", mockSearchDB, mocks.CveInfoMock{}, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("Paginated convert fails", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			_, err := getImageListForDigest(responseContext, "invalid", mocks.MetaDBMock{}, mocks.CveInfoMock{},
				&gql_generated.PageInput{Limit: ref(-1)})
			So(err, ShouldNotBeNil)
		})

		Convey("invalid manifest blob", func() {
			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
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

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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

			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
						},
					}

					configBlob, err := json.Marshal(ispec.ImageConfig{})
					So(err, ShouldBeNil)

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}
					matchedTags := repos[0].Tags
					for tag, manifestDescriptor := range repos[0].Tags {
						if !filterFunc(repos[0], manifestsMetaData[manifestDescriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestsMetaData, manifestDescriptor.Digest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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

			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
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

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDescriptor := range repos[0].Tags {
						if !filterFunc(repos[0], manifestsMetaData[manifestDescriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestsMetaData, manifestDescriptor.Digest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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

			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
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

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					matchedTags := repos[0].Tags
					for tag, manifestDescriptor := range repos[0].Tags {
						if !filterFunc(repos[0], manifestsMetaData[manifestDescriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestsMetaData, manifestDescriptor.Digest)

							continue
						}
					}

					repos[0].Tags = matchedTags

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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

			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
								"1.0.2": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
						},
					}

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					for i, repo := range repos {
						matchedTags := repo.Tags

						for tag, manifestDescriptor := range repo.Tags {
							if !filterFunc(repo, manifestsMetaData[manifestDescriptor.Digest]) {
								delete(matchedTags, tag)
								delete(manifestsMetaData, manifestDescriptor.Digest)

								continue
							}
						}

						repos[i].Tags = matchedTags
					}

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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

		Convey("valid imageListForDigest, multiple matching tags limited by pageInput", func() {
			manifestBlob, err := json.Marshal(ispec.Manifest{})
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob).String()

			configBlob, err := json.Marshal(ispec.Image{})
			So(err, ShouldBeNil)

			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
								"1.0.2": {Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
							},
							Stars: 100,
						},
					}

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						manifestDigest: {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
						},
					}

					for i, repo := range repos {
						matchedTags := repo.Tags

						for tag, manifestDescriptor := range repo.Tags {
							if !filterFunc(repo, manifestsMetaData[manifestDescriptor.Digest]) {
								delete(matchedTags, tag)
								delete(manifestsMetaData, manifestDescriptor.Digest)

								continue
							}
						}

						repos[i].Tags = matchedTags

						repos = append(repos, repo)
					}

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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
			Convey("metaDB.GetManifestMeta fails", func() {
				var (
					metaDB = mocks.MetaDBMock{
						GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
							return mTypes.ManifestData{}, ErrTestError
						},
						GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
							return mTypes.RepoMetadata{
								Tags: map[string]mTypes.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")

					skip = convert.SkipQGLField{
						Vulnerabilities: true,
					}
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, skip, metaDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})

			Convey("0 len return", func() {
				var (
					metaDB = mocks.MetaDBMock{
						GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
							return mTypes.RepoMetadata{
								Tags: map[string]mTypes.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")

					skip = convert.SkipQGLField{
						Vulnerabilities: true,
					}
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, skip, metaDB, mocks.CveInfoMock{}, log)
				So(err, ShouldBeNil)
			})

			Convey("digest != nil && *digest != actual image digest", func() {
				var (
					metaDB = mocks.MetaDBMock{
						GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
							return mTypes.ManifestMetadata{}, ErrTestError
						},
						GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
							return mTypes.RepoMetadata{
								Tags: map[string]mTypes.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageManifest, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")

					digest = "wrongDigest"

					skip = convert.SkipQGLField{
						Vulnerabilities: true,
					}
				)

				_, err := getImageSummary(responseContext, "repo", "tag", &digest, skip, metaDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Media Type: ImageIndex", func() {
			Convey("metaDB.GetIndexData fails", func() {
				var (
					metaDB = mocks.MetaDBMock{
						GetIndexDataFn: func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
							return mTypes.IndexData{}, ErrTestError
						},
						GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
							return mTypes.RepoMetadata{
								Tags: map[string]mTypes.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageIndex, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")

					skip = convert.SkipQGLField{
						Vulnerabilities: true,
					}
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, skip, metaDB, mocks.CveInfoMock{}, log)
				So(err, ShouldNotBeNil)
			})

			Convey("json.Unmarshal(indexData.IndexBlob, &indexContent) fails", func() {
				var (
					metaDB = mocks.MetaDBMock{
						GetIndexDataFn: func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
							return mTypes.IndexData{
								IndexBlob: []byte("bad json"),
							}, nil
						},
						GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
							return mTypes.RepoMetadata{
								Tags: map[string]mTypes.Descriptor{
									"tag": {MediaType: ispec.MediaTypeImageIndex, Digest: "digest"},
								},
							}, nil
						},
					}

					log = log.NewLogger("debug", "")

					skip = convert.SkipQGLField{
						Vulnerabilities: true,
					}
				)

				_, err := getImageSummary(responseContext, "repo", "tag", nil, skip, metaDB, mocks.CveInfoMock{}, log)
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

				metaDB := mocks.MetaDBMock{
					GetIndexDataFn: func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
						return mTypes.IndexData{
							IndexBlob: indexBlob,
						}, nil
					},
					GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
						return mTypes.RepoMetadata{
							Tags: map[string]mTypes.Descriptor{
								"tag": {MediaType: ispec.MediaTypeImageIndex, Digest: "digest"},
							},
						}, nil
					},
				}

				log := log.NewLogger("debug", "")

				goodDigest := "goodDigest"

				Convey("digest not found", func() {
					wrongDigest := "wrongDigest"

					skip := convert.SkipQGLField{
						Vulnerabilities: true,
					}

					_, err = getImageSummary(responseContext, "repo", "tag", &wrongDigest, skip, metaDB, mocks.CveInfoMock{}, log)
					So(err, ShouldNotBeNil)
				})

				Convey("GetManifestData error", func() {
					metaDB.GetManifestDataFn = func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
						return mTypes.ManifestData{}, ErrTestError
					}

					skip := convert.SkipQGLField{
						Vulnerabilities: true,
					}

					_, err = getImageSummary(responseContext, "repo", "tag", &goodDigest, skip, metaDB, mocks.CveInfoMock{}, log)
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey("Media Type: not supported", func() {
			var (
				metaDB = mocks.MetaDBMock{
					GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
						return mTypes.RepoMetadata{
							Tags: map[string]mTypes.Descriptor{
								"tag": {MediaType: "unknown", Digest: "digest"},
							},
						}, nil
					},
				}

				log = log.NewLogger("debug", "")

				skip = convert.SkipQGLField{
					Vulnerabilities: true,
				}
			)

			_, err := getImageSummary(responseContext, "repo", "tag", nil, skip, metaDB, mocks.CveInfoMock{}, log)
			So(err, ShouldBeNil)
		})
	})
}

func TestFilterBaseImagesFn(t *testing.T) {
	Convey("FilterBaseImages", t, func() {
		filterFunc := filterBaseImages(&gql_generated.ImageSummary{})
		ok := filterFunc(
			mTypes.RepoMetadata{},
			mTypes.ManifestMetadata{
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
			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{},
						map[string]mTypes.IndexData{}, ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err := getImageList(responseContext, "test", mockSearchDB, mocks.CveInfoMock{}, nil, testLogger)
			So(err, ShouldNotBeNil)
		})

		Convey("Paginated convert fails", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err := getImageList(responseContext, "test", mocks.MetaDBMock{}, mocks.CveInfoMock{},
				&gql_generated.PageInput{Limit: ref(-1)}, log.NewLogger("debug", ""))

			So(err, ShouldNotBeNil)
		})

		Convey("valid repoList returned", func() {
			mockSearchDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterFunc mTypes.FilterFunc,
				) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
					error,
				) {
					repos := []mTypes.RepoMetadata{
						{
							Name: "test",
							Tags: map[string]mTypes.Descriptor{
								"1.0.1": {
									Digest:    "digestTag1.0.1",
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[string]mTypes.ManifestSignatures{
								"digestTag1.0.1": {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
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

					manifestsMetaData := map[string]mTypes.ManifestMetadata{
						"digestTag1.0.1": {
							ManifestBlob:  manifestBlob,
							ConfigBlob:    configBlob,
							DownloadCount: 0,
							Signatures: mTypes.ManifestSignatures{
								"cosign": []mTypes.SignatureInfo{
									{SignatureManifestDigest: "digestSignature1"},
								},
							},
						},
					}

					if !filterFunc(repos[0], manifestsMetaData["digestTag1.0.1"]) {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{},
							map[string]mTypes.IndexData{}, nil
					}

					return repos, manifestsMetaData, map[string]mTypes.IndexData{}, nil
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

			_, err := getReferrers(mocks.MetaDBMock{}, "test", "", nil, testLogger)
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers returns error", func() {
			testLogger := log.NewLogger("debug", "")
			mockedStore := mocks.MetaDBMock{
				GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest, artifactTypes []string,
				) ([]mTypes.ReferrerInfo, error) {
					return nil, ErrTestError
				},
			}

			_, err := getReferrers(mockedStore, "test", referredDigest, nil, testLogger)
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers return index of descriptors", func() {
			testLogger := log.NewLogger("debug", "")
			referrerDescriptor := ispec.Descriptor{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "com.artifact.test",
				Size:         403,
				Digest:       godigest.FromString("test"),
				Annotations: map[string]string{
					"key": "value",
				},
			}
			mockedStore := mocks.MetaDBMock{
				GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest, artifactTypes []string,
				) ([]mTypes.ReferrerInfo, error) {
					return []mTypes.ReferrerInfo{
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
			So(*referrers[0].Digest, ShouldEqual, referrerDescriptor.Digest.String())
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
				mocks.MetaDBMock{},
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
				mocks.MetaDBMock{
					GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta mTypes.RepoMetadata) bool,
					) ([]mTypes.RepoMetadata, error) {
						return []mTypes.RepoMetadata{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "cve1", &gql_generated.Filter{}, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForCve error in FilterTags", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					FilterTagsFn: func(ctx context.Context,
						filterFunc mTypes.FilterFunc,
					) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
						error,
					) {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListForCve(ctx, "cve1", &gql_generated.Filter{}, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListWithCVEFixed error in FilterTags", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					FilterTagsFn: func(ctx context.Context,
						filterFunc mTypes.FilterFunc,
					) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
						error,
					) {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{
				resolverConfig,
			}

			_, err := qr.ImageListWithCVEFixed(ctx, "cve1", "image", &gql_generated.Filter{}, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("RepoListWithNewestImage repoListWithNewestImage() errors mocked StoreController", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					SearchReposFn: func(ctx context.Context, searchText string,
					) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
						error,
					) {
						return nil, nil, nil, ErrTestError
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
				mocks.MetaDBMock{
					SearchReposFn: func(ctx context.Context, searchText string,
					) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
						error,
					) {
						return nil, nil, nil, ErrTestError
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
				mocks.MetaDBMock{
					FilterTagsFn: func(ctx context.Context,
						filterFunc mTypes.FilterFunc,
					) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
						error,
					) {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							ErrTestError
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
				mocks.MetaDBMock{
					GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
						return mTypes.RepoMetadata{}, ErrTestError
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
				mocks.MetaDBMock{
					GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
						return mTypes.RepoMetadata{}, ErrTestError
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
				mocks.MetaDBMock{
					FilterTagsFn: func(ctx context.Context,
						filterFunc mTypes.FilterFunc,
					) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
						error,
					) {
						return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
							ErrTestError
					},
					GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
						return mTypes.RepoMetadata{
							Name: "repo",
							Tags: map[string]mTypes.Descriptor{
								"tag": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
							},
						}, nil
					},
					GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
						return mTypes.ManifestMetadata{
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
				mocks.MetaDBMock{},
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
	params := boltdb.DBParameters{
		RootDir: t.TempDir(),
	}

	LINUX := "linux"
	AMD := "amd"
	ARM := "arm64"

	boltDriver, err := boltdb.GetBoltDriver(params)
	if err != nil {
		panic(err)
	}

	log := log.NewLogger("debug", "")

	metaDB, err := boltdb.New(boltDriver, log)
	if err != nil {
		panic(err)
	}

	// Create metadb data for scannable image with vulnerabilities
	// Create manifest metadata first
	timeStamp1 := time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC)

	configBlob1, err := json.Marshal(ispec.Image{
		Created: &timeStamp1,
		Platform: ispec.Platform{
			Architecture: AMD,
			OS:           LINUX,
		},
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

	repoMeta1 := mTypes.ManifestData{
		ManifestBlob: manifestBlob1,
		ConfigBlob:   configBlob1,
	}

	digest1 := godigest.FromBytes(manifestBlob1)

	err = metaDB.SetManifestData(digest1, repoMeta1)
	if err != nil {
		panic(err)
	}

	timeStamp2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)

	configBlob2, err := json.Marshal(ispec.Image{
		Created: &timeStamp2,
		Platform: ispec.Platform{
			Architecture: AMD,
			OS:           LINUX,
		},
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

	repoMeta2 := mTypes.ManifestData{
		ManifestBlob: manifestBlob2,
		ConfigBlob:   configBlob2,
	}

	digest2 := godigest.FromBytes(manifestBlob2)

	err = metaDB.SetManifestData(digest2, repoMeta2)
	if err != nil {
		panic(err)
	}

	timeStamp3 := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)

	configBlob3, err := json.Marshal(ispec.Image{
		Created: &timeStamp3,
		Platform: ispec.Platform{
			Architecture: ARM,
			OS:           LINUX,
		},
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

	repoMeta3 := mTypes.ManifestData{
		ManifestBlob: manifestBlob3,
		ConfigBlob:   configBlob3,
	}

	digest3 := godigest.FromBytes(manifestBlob3)

	err = metaDB.SetManifestData(digest3, repoMeta3)
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

		err := metaDB.SetRepoReference(repo, tag, digest, ispec.MediaTypeImageManifest)
		if err != nil {
			panic(err)
		}
	}

	// MetaDB loaded with initial data, now mock the scanner
	// Setup test CVE data in mock scanner
	scanner := mocks.CveScannerMock{
		ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
			digest, ok := tagsMap[image]
			if !ok {
				if !strings.Contains(image, "@") {
					return map[string]cvemodel.CVE{}, nil
				}

				_, digestStr := common.GetImageDirAndDigest(image)
				digest = godigest.Digest(digestStr)
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
	}

	cveInfo := &cveinfo.BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		MetaDB:  metaDB,
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
			So(err, ShouldBeNil)

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

		Convey("paginated fail", func() {
			pageInput := &gql_generated.PageInput{
				Limit: ref(-1),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err = getCVEListForImage(responseContext, "repo1:1.1.0", cveInfo, pageInput, "", log)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Get a list of images affected by a particular CVE ", t, func() {
		Convey("Unpaginated request", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			images, err := getImageListForCVE(responseContext, "CVE1", cveInfo, nil, nil, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.0",
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, nil, nil, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, nil, nil, metaDB, log)
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

		Convey("paginated fail", func() {
			pageInput := &gql_generated.PageInput{
				Limit: ref(-1),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err = getImageListForCVE(responseContext, "repo1:1.1.0", cveInfo, &gql_generated.Filter{},
				pageInput, mocks.MetaDBMock{}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Paginated requests", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover,
			)

			pageInput := getPageInput(1, 0)

			images, err := getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(1, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(2, 0)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(5, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, nil, pageInput, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE2", cveInfo, nil, pageInput, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, nil, pageInput, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, nil, pageInput, metaDB, log)
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

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo3:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			amdFilter := &gql_generated.Filter{Arch: []*string{&AMD}}
			pageInput = getPageInput(5, 0)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, amdFilter, pageInput, metaDB, log)
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

			pageInput = getPageInput(2, 2)

			images, err = getImageListForCVE(responseContext, "CVE3", cveInfo, amdFilter, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0", "repo2:2.0.1",
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

			images, err := getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, nil, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, nil, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE3", "repo1", cveInfo, nil, nil, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)
		})

		Convey("paginated fail", func() {
			pageInput := &gql_generated.PageInput{
				Limit: ref(-1),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err = getImageListWithCVEFixed(responseContext, "cve", "repo1:1.1.0", cveInfo, &gql_generated.Filter{},
				pageInput, mocks.MetaDBMock{
					GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
						return mTypes.RepoMetadata{
							Tags: map[string]mTypes.Descriptor{
								"1.1.0": {
									Digest:    godigest.FromString("str").String(),
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
						}, nil
					},
				}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Paginated requests", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover,
			)

			pageInput := getPageInput(1, 0)

			images, err := getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.1",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 3)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(1, 10)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getPageInput(2, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(2, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(2, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(5, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			amdFilter := &gql_generated.Filter{Arch: []*string{&AMD}}
			armFilter := &gql_generated.Filter{Arch: []*string{&ARM}}

			pageInput = getPageInput(3, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, amdFilter, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{"repo1:1.0.1"}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, armFilter, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{"repo1:1.1.0", "repo1:latest"}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getPageInput(1, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, armFilter, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{"repo1:latest"}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}
		})
	})

	Convey("Errors for cve resolvers", t, func() {
		_, err := getImageListForCVE(
			context.Background(),
			"id",
			mocks.CveInfoMock{
				GetImageListForCVEFn: func(repo, cveID string) ([]cvemodel.TagInfo, error) {
					return []cvemodel.TagInfo{}, ErrTestError
				},
			},
			nil,
			nil,
			mocks.MetaDBMock{
				GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta mTypes.RepoMetadata) bool,
				) ([]mTypes.RepoMetadata, error) {
					return []mTypes.RepoMetadata{{}}, nil
				},
			},
			log,
		)
		So(err, ShouldNotBeNil)
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
	Convey("MetaDB FilterTags error", t, func() {
		mockSearchDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				return make([]mTypes.RepoMetadata, 0), make(map[string]mTypes.ManifestMetadata),
					make(map[string]mTypes.IndexData), ErrTestError
			},
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{}, ErrTestError
			},
			GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
				return mTypes.ManifestMetadata{}, ErrTestError
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

	Convey("paginated fail", t, func() {
		pageInput := &gql_generated.PageInput{
			Limit: ref(-1),
		}

		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		_, err := derivedImageList(responseContext, "repo1:1.0.1", nil,
			mocks.MetaDBMock{
				GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
					return mTypes.RepoMetadata{
						Tags: map[string]mTypes.Descriptor{
							"1.0.1": {
								Digest:    godigest.FromString("str").String(),
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					}, nil
				},
			},
			pageInput,
			mocks.CveInfoMock{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})

	//nolint: dupl
	Convey("MetaDB FilterTags no repo available", t, func() {
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

		mockSearchDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
					nil
			},
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"1.0.1": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestMetaFn: func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
				return mTypes.ManifestMetadata{
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

		manifestsMeta := map[string]mTypes.ManifestMetadata{
			"digestTag1.0.1": {
				ManifestBlob:  manifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
			"digestTag1.0.2": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
			"digestTag1.0.3": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
		}
		manifestDigest := godigest.FromBytes(manifestBlob)

		mockSearchDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"1.0.1": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{
					ManifestBlob: manifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				repos := []mTypes.RepoMetadata{
					{
						Name: "repo1",
						Tags: map[string]mTypes.Descriptor{
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
						if !filterFunc(repo, manifestsMeta[descriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestsMeta, descriptor.Digest)

							continue
						}
					}

					repos[i].Tags = matchedTags
				}

				return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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
	Convey("MetaDB FilterTags error", t, func() {
		mockSearchDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
					ErrTestError
			},
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{}, ErrTestError
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{}, ErrTestError
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

	Convey("paginated fail", t, func() {
		pageInput := &gql_generated.PageInput{
			Limit: ref(-1),
		}

		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)
		_, err := baseImageList(responseContext, "repo1:1.0.2", nil,
			mocks.MetaDBMock{
				GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
					return mTypes.RepoMetadata{
						Tags: map[string]mTypes.Descriptor{
							"1.0.2": {
								Digest:    godigest.FromString("str").String(),
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					}, nil
				},
			},
			pageInput, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})

	//nolint: dupl
	Convey("MetaDB FilterTags no repo available", t, func() {
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

		mockSearchDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
					nil
			},
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"1.0.2": {Digest: manifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{
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

		manifestsMeta := map[string]mTypes.ManifestMetadata{
			"digestTag1.0.1": {
				ManifestBlob:  manifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
			"digestTag1.0.2": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
		}
		derivedManifestDigest := godigest.FromBytes(derivedManifestBlob)

		mockSearchDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"1.0.2": {Digest: derivedManifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{
					ManifestBlob: derivedManifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				repos := []mTypes.RepoMetadata{
					{
						Name: "repo1",
						Tags: map[string]mTypes.Descriptor{
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
						if !filterFunc(repo, manifestsMeta[descriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestsMeta, descriptor.Digest)

							continue
						}
					}

					repos[i].Tags = matchedTags
				}

				return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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

		manifestsMeta := map[string]mTypes.ManifestMetadata{
			"digestTag1.0.1": {
				ManifestBlob:  manifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
			"digestTag1.0.2": {
				ManifestBlob:  derivedManifestBlob,
				ConfigBlob:    configBlob,
				DownloadCount: 100,
				Signatures:    make(mTypes.ManifestSignatures),
			},
		}
		derivedManifestDigest := godigest.FromBytes(derivedManifestBlob)

		mockSearchDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"1.0.2": {Digest: derivedManifestDigest.String(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{
					ManifestBlob: derivedManifestBlob,
					ConfigBlob:   configBlob,
				}, nil
			},
			FilterTagsFn: func(ctx context.Context,
				filterFunc mTypes.FilterFunc,
			) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
				error,
			) {
				repos := []mTypes.RepoMetadata{
					{
						Name: "repo1",
						Tags: map[string]mTypes.Descriptor{
							"1.0.1": {Digest: "digestTag1.0.1", MediaType: ispec.MediaTypeImageManifest},
							"1.0.2": {Digest: "digestTag1.0.2", MediaType: ispec.MediaTypeImageManifest},
						},
						Stars: 100,
					},
				}

				for i, repo := range repos {
					matchedTags := repo.Tags

					for tag, descriptor := range repo.Tags {
						if !filterFunc(repo, manifestsMeta[descriptor.Digest]) {
							delete(matchedTags, tag)
							delete(manifestsMeta, descriptor.Digest)

							continue
						}
					}

					repos[i].Tags = matchedTags
				}

				return repos, manifestsMeta, map[string]mTypes.IndexData{}, nil
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
	log := log.NewLogger("debug", "")

	Convey("ExpandedRepoInfo Errors", t, func() {
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		metaDB := mocks.MetaDBMock{
			GetUserRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMetadata, error) {
				return mTypes.RepoMetadata{
					Tags: map[string]mTypes.Descriptor{
						"tagManifest": {
							Digest:    "errorDigest",
							MediaType: ispec.MediaTypeImageManifest,
						},
						"tagIndex": {
							Digest:    "digestIndex",
							MediaType: ispec.MediaTypeImageIndex,
						},
						"tagGetIndexError": {
							Digest:    "errorIndexDigest",
							MediaType: ispec.MediaTypeImageIndex,
						},
						"tagGoodIndexBadManifests": {
							Digest:    "goodIndexBadManifests",
							MediaType: ispec.MediaTypeImageIndex,
						},
						"tagGoodIndex1GoodManifest": {
							Digest:    "goodIndexGoodManifest",
							MediaType: ispec.MediaTypeImageIndex,
						},
						"tagGoodIndex2GoodManifest": {
							Digest:    "goodIndexGoodManifest",
							MediaType: ispec.MediaTypeImageIndex,
						},
					},
				}, nil
			},
			GetManifestDataFn: func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				switch manifestDigest {
				case "errorDigest":
					return mTypes.ManifestData{}, ErrTestError
				default:
					return mTypes.ManifestData{
						ManifestBlob: []byte("{}"),
						ConfigBlob:   []byte("{}"),
					}, nil
				}
			},
			GetIndexDataFn: func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				goodIndexBadManifestsBlob, err := json.Marshal(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							Digest:    "errorDigest",
							MediaType: ispec.MediaTypeImageManifest,
						},
					},
				})
				So(err, ShouldBeNil)

				goodIndexGoodManifestBlob, err := json.Marshal(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							Digest:    "goodManifest",
							MediaType: ispec.MediaTypeImageManifest,
						},
					},
				})
				So(err, ShouldBeNil)

				switch indexDigest {
				case "errorIndexDigest":
					return mTypes.IndexData{}, ErrTestError
				case "goodIndexBadManifests":
					return mTypes.IndexData{
						IndexBlob: goodIndexBadManifestsBlob,
					}, nil
				case "goodIndexGoodManifest":
					return mTypes.IndexData{
						IndexBlob: goodIndexGoodManifestBlob,
					}, nil
				default:
					return mTypes.IndexData{}, nil
				}
			},
		}

		_, err := expandedRepoInfo(responseContext, "repo", metaDB, mocks.CveInfoMock{}, log)
		So(err, ShouldBeNil)
	})

	Convey("Access error", t, func() {
		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("user")
		userAc.SetGlobPatterns("read", map[string]bool{
			"repo": false,
		})

		ctx := userAc.DeriveContext(context.Background())

		responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		_, err := expandedRepoInfo(responseContext, "repo", mocks.MetaDBMock{}, mocks.CveInfoMock{}, log)
		So(err, ShouldBeNil)
	})
}

func TestFilterFunctions(t *testing.T) {
	Convey("Filter Functions", t, func() {
		Convey("FilterByDigest bad manifest blob", func() {
			filterFunc := FilterByDigest("digest")
			ok := filterFunc(
				mTypes.RepoMetadata{},
				mTypes.ManifestMetadata{
					ManifestBlob: []byte("bad blob"),
				},
			)
			So(ok, ShouldBeFalse)
		})

		Convey("filterDerivedImages bad manifest blob", func() {
			filterFunc := filterDerivedImages(&gql_generated.ImageSummary{})
			ok := filterFunc(
				mTypes.RepoMetadata{},
				mTypes.ManifestMetadata{
					ManifestBlob: []byte("bad blob"),
				},
			)
			So(ok, ShouldBeFalse)
		})

		Convey("FilterByTagInfo", func() {
			fFunc := FilterByTagInfo([]cvemodel.TagInfo{
				{
					Descriptor: cvemodel.Descriptor{
						MediaType: ispec.MediaTypeImageIndex,
					},
					Manifests: []cvemodel.DescriptorInfo{
						{
							Descriptor: cvemodel.Descriptor{
								Digest: godigest.FromString("{}"),
							},
						},
					},
				},
			})

			ok := fFunc(mTypes.RepoMetadata{}, mTypes.ManifestMetadata{ManifestBlob: []byte("{}")})
			So(ok, ShouldBeTrue)
		})
	})
}

func ref[T any](val T) *T {
	ref := val

	return &ref
}
