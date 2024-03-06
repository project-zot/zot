//go:build search

package search //nolint

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.dev/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	mConvert "zotregistry.dev/zot/pkg/meta/convert"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
	"zotregistry.dev/zot/pkg/storage"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
)

var ErrTestError = errors.New("TestError")

func TestResolverGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		const query = "repo1"
		Convey("MetaDB SearchRepos error", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string,
				) ([]mTypes.RepoMeta, error) {
					return []mTypes.RepoMeta{}, ErrTestError
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

		Convey("MetaDB SearchTags gives error", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string) ([]mTypes.FullImageMeta, error) {
					return []mTypes.FullImageMeta{}, ErrTestError
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

		Convey("Searching by digest", func() {
			ctx := context.Background()
			query := "sha256:aabb12341baf2"
			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
					filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					return []mTypes.FullImageMeta{}, ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter, graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("Searching by digest with bad pagination", func() {
			ctx := context.Background()
			query := "sha256:aabb12341baf2"

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter, graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mocks.MetaDBMock{}, &gql_generated.Filter{},
				&gql_generated.PageInput{Limit: ref(-10)}, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("Searching by tag returns a filter error", func() {
			ctx := context.Background()
			query := ":test"
			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
					filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					return []mTypes.FullImageMeta{}, ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter, graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockMetaDB, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("Searching by tag returns a pagination error", func() {
			ctx := context.Background()
			query := ":test"

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter, graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mocks.MetaDBMock{}, &gql_generated.Filter{},
				&gql_generated.PageInput{Limit: ref(-10)}, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})

		Convey("Searching with a bad query", func() {
			ctx := context.Background()
			query := ":"

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter, graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mocks.MetaDBMock{}, &gql_generated.Filter{},
				&gql_generated.PageInput{}, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos.Results, ShouldBeEmpty)
		})
	})
}

func TestRepoListWithNewestImage(t *testing.T) {
	Convey("RepoListWithNewestImage", t, func() {
		Convey("MetaDB SearchRepos error", func() {
			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string) ([]mTypes.RepoMeta, error) {
					return []mTypes.RepoMeta{}, ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			mockCve := mocks.CveInfoMock{}

			pageInput := gql_generated.PageInput{
				Limit:  ref(1),
				Offset: ref(0),
				SortBy: ref(gql_generated.SortCriteriaUpdateTime),
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

		Convey("Working SearchRepo function", func() {
			createTime := time.Now()
			createTime2 := createTime.Add(time.Second)
			img1 := CreateImageWith().DefaultLayers().
				ImageConfig(ispec.Image{
					Config: ispec.ImageConfig{
						Labels: map[string]string{},
					},
					Created: &createTime,
				}).Build()

			img2 := CreateImageWith().DefaultLayers().
				ImageConfig(ispec.Image{
					Config: ispec.ImageConfig{
						Labels: map[string]string{},
					},
					Created: &createTime2,
				}).Build()

			mockMetaDB := mocks.MetaDBMock{
				SearchReposFn: func(ctx context.Context, searchText string) ([]mTypes.RepoMeta, error) {
					repos := []mTypes.RepoMeta{
						{
							Name: "repo1",
							Tags: map[mTypes.Tag]mTypes.Descriptor{
								"1.0.1": {
									Digest:    img1.DigestStr(),
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[mTypes.ImageDigest]mTypes.ManifestSignatures{
								img1.DigestStr(): {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
									},
								},
							},
							StarCount: 100,
							LastUpdatedImage: &mTypes.LastUpdatedImage{
								Descriptor: mTypes.Descriptor{
									Digest:    img1.DigestStr(),
									MediaType: ispec.MediaTypeImageManifest,
								},
								Tag:         "1.0.1",
								LastUpdated: &createTime,
							},
						},
						{
							Name: "repo2",
							Tags: map[mTypes.Tag]mTypes.Descriptor{
								"1.0.2": {
									Digest:    img2.DigestStr(),
									MediaType: ispec.MediaTypeImageManifest,
								},
							},
							Signatures: map[mTypes.ImageDigest]mTypes.ManifestSignatures{
								img1.DigestStr(): {
									"cosign": []mTypes.SignatureInfo{
										{SignatureManifestDigest: "testSignature", LayersInfo: []mTypes.LayerInfo{}},
									},
								},
							},
							StarCount: 100,
							LastUpdatedImage: &mTypes.LastUpdatedImage{
								Descriptor: mTypes.Descriptor{
									Digest:    img2.DigestStr(),
									MediaType: ispec.MediaTypeImageManifest,
								},
								Tag:         "1.0.2",
								LastUpdated: &createTime2,
							},
						},
					}

					return repos, nil
				},
				FilterImageMetaFn: func(ctx context.Context, digests []string,
				) (map[string]mTypes.ImageMeta, error) {
					return map[string]mTypes.ImageMeta{
						img1.DigestStr(): mConvert.GetImageManifestMeta(img1.Manifest, img1.Config,
							img1.ManifestDescriptor.Size, img1.ManifestDescriptor.Digest),
						img2.DigestStr(): mConvert.GetImageManifestMeta(img2.Manifest, img2.Config,
							img2.ManifestDescriptor.Size, img2.ManifestDescriptor.Digest),
					}, nil
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
				pageInput := gql_generated.PageInput{
					Limit:  ref(2),
					Offset: ref(0),
					SortBy: ref(gql_generated.SortCriteriaUpdateTime),
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

func TestGetFilteredPaginatedRepos(t *testing.T) {
	ctx := context.Background()
	log := log.NewLogger("debug", "")

	Convey("getFilteredPaginatedRepos", t, func() {
		metaDB := mocks.MetaDBMock{}

		Convey("FilterRepos", func() {
			metaDB.FilterReposFn = func(ctx context.Context, rankName mTypes.FilterRepoNameFunc,
				filterFunc mTypes.FilterFullRepoFunc,
			) ([]mTypes.RepoMeta, error) {
				return nil, ErrTestError
			}
			_, err := getFilteredPaginatedRepos(ctx, nil, func(repo string) bool { return true }, log,
				&gql_generated.PageInput{}, metaDB)
			So(err, ShouldNotBeNil)
		})
		Convey("FilterImageMeta", func() {
			metaDB.FilterImageMetaFn = func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return nil, ErrTestError
			}
			_, err := getFilteredPaginatedRepos(ctx, nil, func(repo string) bool { return true }, log,
				&gql_generated.PageInput{}, metaDB)
			So(err, ShouldNotBeNil)
		})
		Convey("PaginatedRepoMeta2RepoSummaries", func() {
			_, err := getFilteredPaginatedRepos(ctx, nil, func(repo string) bool { return true }, log,
				&gql_generated.PageInput{Limit: ref(-10)}, metaDB)
			So(err, ShouldNotBeNil)
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

func getTestRepoMetaWithImages(repo string, images []Image) mTypes.RepoMeta {
	tags := map[mTypes.Tag]mTypes.Descriptor{"": {}}
	statistics := map[mTypes.Tag]mTypes.DescriptorStatistics{"": {}}
	signatures := map[mTypes.ImageDigest]mTypes.ManifestSignatures{"": {}}
	referrers := map[string][]mTypes.ReferrerInfo{"": {}}

	for i := range images {
		tags[images[i].DigestStr()] = mTypes.Descriptor{}
		statistics[images[i].DigestStr()] = mTypes.DescriptorStatistics{}
		signatures[images[i].DigestStr()] = mTypes.ManifestSignatures{}
		referrers[images[i].DigestStr()] = []mTypes.ReferrerInfo{}
	}

	return mTypes.RepoMeta{
		Name:       repo,
		Tags:       tags,
		Statistics: statistics,
		Signatures: signatures,
		Referrers:  referrers,
	}
}

func TestImageListForDigest(t *testing.T) {
	Convey("getImageList", t, func() {
		Convey("no page requested, FilterTagsFn returns error", func() {
			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
					filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					return []mTypes.FullImageMeta{}, ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			_, err := getImageListForDigest(responseContext, "invalid", mockMetaDB, mocks.CveInfoMock{}, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("Paginated convert fails", func() {
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			_, err := getImageListForDigest(responseContext, "invalid", mocks.MetaDBMock{}, mocks.CveInfoMock{},
				&gql_generated.PageInput{Limit: ref(-1)})
			So(err, ShouldNotBeNil)
		})

		Convey("valid imageListForDigest returned for matching manifest digest", func() {
			img1, img2 := CreateRandomImage(), CreateRandomImage()
			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
					filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					fullImageMetaList := []mTypes.ImageMeta{img1.AsImageMeta(), img2.AsImageMeta()}
					repoMeta := getTestRepoMetaWithImages("repo", []Image{img1, img2})
					tags := []string{"tag1", "tag2"}

					acceptedImages := []mTypes.FullImageMeta{}

					for i := range fullImageMetaList {
						if filterFunc(repoMeta, fullImageMetaList[i]) {
							acceptedImages = append(acceptedImages,
								convert.GetFullImageMeta(tags[i], repoMeta, fullImageMetaList[i]))

							continue
						}
					}

					return acceptedImages, nil
				},
			}

			pageInput := gql_generated.PageInput{
				Limit:  ref(1),
				Offset: ref(0),
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			imageSummaries, err := getImageListForDigest(responseContext, img1.DigestStr(),
				mockMetaDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 1)

			imageSummaries, err = getImageListForDigest(responseContext, "invalid",
				mockMetaDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 0)

			imageSummaries, err = getImageListForDigest(responseContext, img1.Manifest.Config.Digest.String(),
				mockMetaDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 1)

			imageSummaries, err = getImageListForDigest(responseContext, img1.Manifest.Layers[0].Digest.String(),
				mockMetaDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 1)
		})

		Convey("valid imageListForDigest, multiple matching tags", func() {
			img1 := CreateRandomImage()

			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
					filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					fullImageMetaList := []mTypes.ImageMeta{img1.AsImageMeta()}
					repoMeta := getTestRepoMetaWithImages("repo", []Image{img1, img1})
					tags := []string{"tag1", "tag2"}

					acceptedImages := []mTypes.FullImageMeta{}

					for i := range fullImageMetaList {
						if filterFunc(repoMeta, fullImageMetaList[i]) {
							acceptedImages = append(acceptedImages,
								convert.GetFullImageMeta(tags[i], repoMeta, fullImageMetaList[i]))

							continue
						}
					}

					return acceptedImages, nil
				},
			}

			pageInput := gql_generated.PageInput{
				Limit:  ref(1),
				Offset: ref(0),
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageListForDigest(responseContext, img1.DigestStr(),
				mockMetaDB, mocks.CveInfoMock{}, &pageInput)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 1)
		})
	})
}

func TestGetImageSummaryError(t *testing.T) {
	Convey("getImageSummary", t, func() {
		metaDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{Tags: map[mTypes.Tag]mTypes.Descriptor{"tag": {}}}, nil
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return nil, ErrTestError
			},
		}
		log := log.NewLogger("debug", "")

		_, err := getImageSummary(context.Background(), "repo", "tag", nil, convert.SkipQGLField{},
			metaDB, nil, log)
		So(err, ShouldNotBeNil)
	})
}

func TestImageListError(t *testing.T) {
	Convey("getImageList", t, func() {
		testLogger := log.NewLogger("debug", "/dev/null")
		Convey("no page requested, SearchRepoFn returns error", func() {
			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					return []mTypes.FullImageMeta{}, ErrTestError
				},
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err := getImageList(responseContext, "test", mockMetaDB, mocks.CveInfoMock{}, nil, testLogger)
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
			mockMetaDB := mocks.MetaDBMock{
				FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
				) ([]mTypes.FullImageMeta, error) {
					repoName := "correct-repo"

					if !filterRepoTag(repoName, "tag") {
						return []mTypes.FullImageMeta{}, nil
					}

					image := CreateDefaultImage()
					repoMeta := mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{image.DigestStr(): {
							Digest:    image.DigestStr(),
							MediaType: ispec.MediaTypeImageManifest,
						}},
					}

					return []mTypes.FullImageMeta{convert.GetFullImageMeta("tag", repoMeta, image.AsImageMeta())}, nil
				},
			}

			pageInput := gql_generated.PageInput{
				Limit:  ref(1),
				Offset: ref(0),
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			imageSummaries, err := getImageList(responseContext, "correct-repo", mockMetaDB,
				mocks.CveInfoMock{}, &pageInput, testLogger)
			So(err, ShouldBeNil)
			So(len(imageSummaries.Results), ShouldEqual, 1)

			imageSummaries, err = getImageList(responseContext, "invalid", mockMetaDB,
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
			resolverConfig := NewResolver(log, storage.StoreController{}, mocks.MetaDBMock{}, mocks.CveInfoMock{})
			resolver := queryResolver{resolverConfig}
			pageInput := gql_generated.PageInput{
				Limit:  ref(-1),
				Offset: ref(0),
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			_, err := resolver.GlobalSearch(ctx, "some_string", &gql_generated.Filter{}, &pageInput)
			So(err, ShouldNotBeNil)

			pageInput = gql_generated.PageInput{
				Limit:  ref(0),
				Offset: ref(-1),
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			_, err = resolver.GlobalSearch(ctx, "some_string", &gql_generated.Filter{}, &pageInput)
			So(err, ShouldNotBeNil)
		})

		Convey("GlobalSearch error filte image meta", func() {
			resolverConfig := NewResolver(log, storage.StoreController{}, mocks.MetaDBMock{
				FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
					return nil, ErrTestError
				},
			}, mocks.CveInfoMock{})
			resolver := queryResolver{resolverConfig}

			_, err := resolver.GlobalSearch(ctx, "some_string", &gql_generated.Filter{}, getGQLPageInput(1, 1))
			So(err, ShouldNotBeNil)
		})

		Convey("CVEDiffListForImages nill cveinfo", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
					) ([]mTypes.RepoMeta, error) {
						return []mTypes.RepoMeta{}, ErrTestError
					},
				},
				nil,
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.CVEDiffListForImages(ctx, gql_generated.ImageInput{}, gql_generated.ImageInput{},
				&gql_generated.PageInput{}, nil, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("CVEDiffListForImages error", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
					) ([]mTypes.RepoMeta, error) {
						return []mTypes.RepoMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.CVEDiffListForImages(ctx, gql_generated.ImageInput{}, gql_generated.ImageInput{},
				&gql_generated.PageInput{}, nil, nil)
			So(err, ShouldNotBeNil)
		})

		Convey("ImageListForCve error in GetMultipleRepoMeta", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
					) ([]mTypes.RepoMeta, error) {
						return []mTypes.RepoMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

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
					FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
					) ([]mTypes.FullImageMeta, error) {
						return []mTypes.FullImageMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

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
					FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
					) ([]mTypes.FullImageMeta, error) {
						return []mTypes.FullImageMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.ImageListWithCVEFixed(ctx, "cve1", "image", &gql_generated.Filter{}, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("RepoListWithNewestImage repoListWithNewestImage() filter image meta error", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{
					DefaultStore: mocks.MockedImageStore{},
				},
				mocks.MetaDBMock{
					SearchReposFn: func(ctx context.Context, searchText string,
					) ([]mTypes.RepoMeta, error) {
						return []mTypes.RepoMeta{}, nil
					},
					FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
						return nil, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.RepoListWithNewestImage(ctx, &gql_generated.PageInput{})
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
					) ([]mTypes.RepoMeta, error) {
						return nil, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.RepoListWithNewestImage(ctx, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("RepoListWithNewestImage repoListWithNewestImage() errors valid StoreController", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.MetaDBMock{
					SearchReposFn: func(ctx context.Context, searchText string,
					) ([]mTypes.RepoMeta, error) {
						return nil, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.RepoListWithNewestImage(ctx, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("ImageList getImageList() errors", func() {
			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.MetaDBMock{
					FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
					) ([]mTypes.FullImageMeta, error) {
						return []mTypes.FullImageMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

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
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

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
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{}, ErrTestError
					},
				},
				mocks.CveInfoMock{},
			)

			qr := queryResolver{resolverConfig}

			_, err := qr.BaseImageList(ctx, "repo:tag", nil, &gql_generated.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("DerivedImageList and BaseImage List FilterTags() errors", func() {
			image := CreateDefaultImage()

			resolverConfig := NewResolver(
				log,
				storage.StoreController{},
				mocks.MetaDBMock{
					FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
					) ([]mTypes.FullImageMeta, error) {
						return []mTypes.FullImageMeta{}, ErrTestError
					},
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{
							Name: "repo",
							Tags: map[mTypes.Tag]mTypes.Descriptor{
								"tag": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
							},
						}, nil
					},
					GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
						return image.AsImageMeta(), nil
					},
				},
				mocks.CveInfoMock{},
			)

			resolver := queryResolver{resolverConfig}

			_, err := resolver.DerivedImageList(ctx, "repo:tag", nil, &gql_generated.PageInput{})
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

			qr := queryResolver{resolverConfig}

			_, err := qr.Referrers(ctx, "repo", "", nil)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestCVEResolvers(t *testing.T) { //nolint:gocyclo
	ctx := context.Background()
	log := log.NewLogger("debug", "")
	LINUX := "linux"
	AMD := "amd"
	ARM := "arm64"

	boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: t.TempDir()})
	if err != nil {
		panic(err)
	}

	metaDB, err := boltdb.New(boltDriver, log)
	if err != nil {
		panic(err)
	}

	image1 := CreateImageWith().RandomLayers(5, 2).ImageConfig(ispec.Image{
		Created: DateRef(2008, 1, 1, 12, 0, 0, 0, time.UTC),
		Platform: ispec.Platform{
			Architecture: AMD,
			OS:           LINUX,
		},
	}).Build()
	digest1 := image1.Digest()

	image2 := CreateImageWith().RandomLayers(5, 2).ImageConfig(ispec.Image{
		Created: DateRef(2009, 1, 1, 12, 0, 0, 0, time.UTC),
		Platform: ispec.Platform{
			Architecture: AMD,
			OS:           LINUX,
		},
	}).Build()
	digest2 := image2.Digest()

	image3 := CreateImageWith().RandomLayers(5, 2).ImageConfig(ispec.Image{
		Created: DateRef(2010, 1, 1, 12, 0, 0, 0, time.UTC),
		Platform: ispec.Platform{
			Architecture: ARM,
			OS:           LINUX,
		},
	}).Build()
	digest3 := image3.Digest()

	ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB,
		ociutils.Repo{
			Name: "repo1", Images: []ociutils.RepoImage{
				{Image: image1, Reference: "1.0.0"},
				{Image: image2, Reference: "1.0.1"},
				{Image: image3, Reference: "1.1.0"},
				{Image: image3, Reference: "latest"},
			},
		},
		ociutils.Repo{
			Name: "repo2", Images: []ociutils.RepoImage{
				{Image: image1, Reference: "2.0.0"},
				{Image: image2, Reference: "2.0.1"},
				{Image: image3, Reference: "2.1.0"},
				{Image: image3, Reference: "latest"},
			},
		},
		ociutils.Repo{
			Name: "repo3", Images: []ociutils.RepoImage{
				{Image: image2, Reference: "3.0.1"},
				{Image: image3, Reference: "3.1.0"},
				{Image: image3, Reference: "latest"},
			},
		},
	)
	if err != nil {
		panic(err)
	}

	getCveResults := func(digestStr string) map[string]cvemodel.CVE {
		if digestStr == digest1.String() {
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
			}
		}

		if digestStr == digest2.String() {
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
			}
		}

		if digestStr == digest3.String() {
			return map[string]cvemodel.CVE{
				"CVE3": {
					ID:          "CVE3",
					Severity:    "LOW",
					Title:       "Title CVE3",
					Description: "Description CVE3",
				},
			}
		}

		// By default the image has no vulnerabilities
		return map[string]cvemodel.CVE{}
	}

	// MetaDB loaded with initial data, now mock the scanner
	// Setup test CVE data in mock scanner
	scanner := mocks.CveScannerMock{
		ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
			repo, ref, _, _ := common.GetRepoReference(image)

			if common.IsDigest(ref) {
				return getCveResults(ref), nil
			}

			repoMeta, _ := metaDB.GetRepoMeta(ctx, repo)

			if _, ok := repoMeta.Tags[ref]; !ok {
				panic("unexpected tag '" + ref + "', test might be wrong")
			}

			return getCveResults(repoMeta.Tags[ref].Digest), nil
		},
		GetCachedResultFn: func(digestStr string) map[string]cvemodel.CVE {
			return getCveResults(digestStr)
		},
		IsResultCachedFn: func(digestStr string) bool {
			return true
		},
	}

	cveInfo := &cveinfo.BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		MetaDB:  metaDB,
	}

	Convey("Get CVE list for image ", t, func() {
		Convey("Unpaginated request to get all CVEs in an image", func() {
			pageInput := &gql_generated.PageInput{
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			dig := godigest.FromString("dig")
			repoWithDigestRef := fmt.Sprintf("repo@%s", dig)

			_, err := getCVEListForImage(responseContext, repoWithDigestRef, cveInfo, pageInput, "", "", "", log)
			So(err, ShouldBeNil)

			cveResult, err := getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves := []string{"CVE1", "CVE2", "CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			// test searching CVE by id in results
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "CVE3", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			// test searching CVE by id in results - no matches
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "CVE100", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")
			So(len(cveResult.CVEList), ShouldEqual, 0)

			// test searching CVE by id in results - partial name
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "VE3", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			// test searching CVE by title in results
			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "Title CVE", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE1", "CVE2", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.1", cveInfo, pageInput, "", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.1")

			expectedCves = []string{"CVE2", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.1.0", cveInfo, pageInput, "", "", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.1.0")

			expectedCves = []string{"CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}
		})

		Convey("Unpaginated request to get all CVEs in an image excluding some", func() {
			pageInput := &gql_generated.PageInput{
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			cveResult, err := getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "Title CVE",
				"Title CVE2", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves := []string{"CVE1", "CVE3"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "Description",
				"Description CVE2", "", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE1", "CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}
		})

		Convey("Unpaginated request to get all CVEs in an image filtered by severity", func() {
			pageInput := &gql_generated.PageInput{
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			cveResult, err := getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "",
				"", "HIGH", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves := []string{"CVE1"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}

			cveResult, err = getCVEListForImage(responseContext, "repo1:1.0.0", cveInfo, pageInput, "Description",
				"Description CVE2", "LOW", log)
			So(err, ShouldBeNil)
			So(*cveResult.Tag, ShouldEqual, "1.0.0")

			expectedCves = []string{"CVE3", "CVE34"}
			So(len(cveResult.CVEList), ShouldEqual, len(expectedCves))

			for _, cve := range cveResult.CVEList {
				So(expectedCves, ShouldContain, *cve.ID)
			}
		})

		Convey("paginated fail", func() {
			pageInput := &gql_generated.PageInput{
				Limit: ref(-1),
			}

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err = getCVEListForImage(responseContext, "repo1:1.1.0", cveInfo, pageInput, "", "", "", log)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Get a list of images affected by a particular CVE ", t, func() {
		Convey("Unpaginated request", func() {
			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
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

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err = getImageListForCVE(responseContext, "repo1:1.1.0", cveInfo, &gql_generated.Filter{},
				pageInput, mocks.MetaDBMock{}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("context done", func() {
			pageInput := getGQLPageInput(1, 0)

			ctx, cancel := context.WithCancel(ctx)
			cancel()

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			canceledScanner := scanner

			canceledScanner.ScanImageFn = func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				return nil, ctx.Err()
			}

			cveInfo.Scanner = canceledScanner

			defer func() {
				cveInfo.Scanner = scanner
			}()

			_, err = getImageListForCVE(responseContext, "repo1:1.1.0", cveInfo, &gql_generated.Filter{},
				pageInput, metaDB, log)
			So(err, ShouldEqual, ctx.Err())
		})

		Convey("Paginated requests", func() {
			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover,
			)

			pageInput := getGQLPageInput(1, 0)

			images, err := getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(1, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(1, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getGQLPageInput(1, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getGQLPageInput(2, 0)

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

			pageInput = getGQLPageInput(5, 0)

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

			pageInput = getGQLPageInput(5, 1)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo2:2.0.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(5, 2)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getGQLPageInput(5, 5)

			images, err = getImageListForCVE(responseContext, "CVE1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getGQLPageInput(5, 0)

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

			pageInput = getGQLPageInput(5, 3)

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

			pageInput = getGQLPageInput(5, 0)

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

			pageInput = getGQLPageInput(5, 5)

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

			pageInput = getGQLPageInput(5, 10)

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
			pageInput = getGQLPageInput(5, 0)

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

			pageInput = getGQLPageInput(2, 2)

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
			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
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

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err = getImageListWithCVEFixed(responseContext, "cve", "repo1:1.1.0", cveInfo, &gql_generated.Filter{},
				pageInput, mocks.MetaDBMock{
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{
							Tags: map[mTypes.Tag]mTypes.Descriptor{
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

		Convey("context done", func() {
			ctx, cancel := context.WithCancel(ctx)
			cancel()

			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			_, err := getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, nil, metaDB, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Paginated requests", func() {
			responseContext := graphql.WithResponseContext(ctx, graphql.DefaultErrorPresenter,
				graphql.DefaultRecover,
			)

			pageInput := getGQLPageInput(1, 0)

			images, err := getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages := []string{
				"repo1:1.0.1",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(1, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(1, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(1, 3)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getGQLPageInput(1, 10)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			pageInput = getGQLPageInput(2, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(2, 1)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(2, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE1", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.0.1", "repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(5, 0)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)

			expectedImages = []string{
				"repo1:1.1.0", "repo1:latest",
			}
			So(len(images.Results), ShouldEqual, len(expectedImages))

			for _, image := range images.Results {
				So(fmt.Sprintf("%s:%s", *image.RepoName, *image.Tag), ShouldBeIn, expectedImages)
			}

			pageInput = getGQLPageInput(5, 2)

			images, err = getImageListWithCVEFixed(responseContext, "CVE2", "repo1", cveInfo, nil, pageInput, metaDB, log)
			So(err, ShouldBeNil)
			So(len(images.Results), ShouldEqual, 0)

			amdFilter := &gql_generated.Filter{Arch: []*string{&AMD}}
			armFilter := &gql_generated.Filter{Arch: []*string{&ARM}}

			pageInput = getGQLPageInput(3, 0)

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

			pageInput = getGQLPageInput(1, 1)

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
			ctx,
			"id",
			mocks.CveInfoMock{
				GetImageListForCVEFn: func(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error) {
					return []cvemodel.TagInfo{}, ErrTestError
				},
			},
			nil,
			nil,
			mocks.MetaDBMock{
				GetMultipleRepoMetaFn: func(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
				) ([]mTypes.RepoMeta, error) {
					return []mTypes.RepoMeta{{}}, nil
				},
			},
			log,
		)
		So(err, ShouldNotBeNil)
	})

	Convey("CVE Diff between images", t, func() {
		// image := "image:tag"
		// baseImage := "base:basetag"
		ctx := context.Background()
		pageInput := &gql_generated.PageInput{
			SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
		}

		boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: t.TempDir()})
		if err != nil {
			panic(err)
		}

		metaDB, err := boltdb.New(boltDriver, log)
		if err != nil {
			panic(err)
		}

		layer1 := []byte{10, 20, 30}
		layer2 := []byte{11, 21, 31}
		layer3 := []byte{12, 22, 23}

		otherImage := CreateImageWith().LayerBlobs([][]byte{
			layer1,
		}).DefaultConfig().Build()

		baseImage := CreateImageWith().LayerBlobs([][]byte{
			layer1,
			layer2,
		}).PlatformConfig("testArch", "testOs").Build()

		image := CreateImageWith().LayerBlobs([][]byte{
			layer1,
			layer2,
			layer3,
		}).PlatformConfig("testArch", "testOs").Build()

		multiArchBase := CreateMultiarchWith().Images([]Image{baseImage, CreateRandomImage(), CreateRandomImage()}).
			Build()
		multiArchImage := CreateMultiarchWith().Images([]Image{image, CreateRandomImage(), CreateRandomImage()}).
			Build()

		getCveResults := func(digestStr string) map[string]cvemodel.CVE {
			switch digestStr {
			case image.DigestStr():
				return map[string]cvemodel.CVE{
					"CVE1": {
						ID:          "CVE1",
						Severity:    "HIGH",
						Title:       "Title CVE1",
						Description: "Description CVE1",
						PackageList: []cvemodel.Package{{}},
					},
					"CVE2": {
						ID:          "CVE2",
						Severity:    "MEDIUM",
						Title:       "Title CVE2",
						Description: "Description CVE2",
						PackageList: []cvemodel.Package{{}},
					},
					"CVE3": {
						ID:          "CVE3",
						Severity:    "LOW",
						Title:       "Title CVE3",
						Description: "Description CVE3",
						PackageList: []cvemodel.Package{{}},
					},
				}
			case baseImage.DigestStr():
				return map[string]cvemodel.CVE{
					"CVE1": {
						ID:          "CVE1",
						Severity:    "HIGH",
						Title:       "Title CVE1",
						Description: "Description CVE1",
						PackageList: []cvemodel.Package{{}},
					},
					"CVE2": {
						ID:          "CVE2",
						Severity:    "MEDIUM",
						Title:       "Title CVE2",
						Description: "Description CVE2",
						PackageList: []cvemodel.Package{{}},
					},
				}
			case otherImage.DigestStr():
				return map[string]cvemodel.CVE{
					"CVE1": {
						ID:          "CVE1",
						Severity:    "HIGH",
						Title:       "Title CVE1",
						Description: "Description CVE1",
						PackageList: []cvemodel.Package{{}},
					},
				}
			}

			// By default the image has no vulnerabilities
			return map[string]cvemodel.CVE{}
		}

		// MetaDB loaded with initial data, now mock the scanner
		// Setup test CVE data in mock scanner
		scanner := mocks.CveScannerMock{
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				repo, ref, _, _ := common.GetRepoReference(image)

				if common.IsDigest(ref) {
					return getCveResults(ref), nil
				}

				repoMeta, _ := metaDB.GetRepoMeta(ctx, repo)

				if _, ok := repoMeta.Tags[ref]; !ok {
					panic("unexpected tag '" + ref + "', test might be wrong")
				}

				return getCveResults(repoMeta.Tags[ref].Digest), nil
			},
			GetCachedResultFn: func(digestStr string) map[string]cvemodel.CVE {
				return getCveResults(digestStr)
			},
			IsResultCachedFn: func(digestStr string) bool {
				return true
			},
		}

		cveInfo := &cveinfo.BaseCveInfo{
			Log:     log,
			Scanner: scanner,
			MetaDB:  metaDB,
		}

		ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB,
			ociutils.Repo{
				Name: "repo",
				Images: []ociutils.RepoImage{
					{Image: otherImage, Reference: "other-image"},
					{Image: baseImage, Reference: "base-image"},
					{Image: image, Reference: "image"},
				},
			},
			ociutils.Repo{
				Name: "repo-multi",
				MultiArchImages: []ociutils.RepoMultiArchImage{
					{MultiarchImage: CreateRandomMultiarch(), Reference: "multi-rand"},
					{MultiarchImage: multiArchBase, Reference: "multi-base"},
					{MultiarchImage: multiArchImage, Reference: "multi-img"},
				},
			},
		)
		So(err, ShouldBeNil)

		minuend := gql_generated.ImageInput{Repo: "repo", Tag: "image"}
		subtrahend := gql_generated.ImageInput{Repo: "repo", Tag: "image"}
		diffResult, err := getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldBeNil)
		So(len(diffResult.CVEList), ShouldEqual, 0)

		minuend = gql_generated.ImageInput{Repo: "repo", Tag: "image"}
		subtrahend = gql_generated.ImageInput{}
		diffResult, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldBeNil)
		So(len(diffResult.CVEList), ShouldEqual, 1)

		minuend = gql_generated.ImageInput{Repo: "repo", Tag: "base-image"}
		subtrahend = gql_generated.ImageInput{Repo: "repo", Tag: "image"}
		diffResult, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldBeNil)
		So(len(diffResult.CVEList), ShouldEqual, 0)

		minuend = gql_generated.ImageInput{Repo: "repo-multi", Tag: "multi-img", Platform: &gql_generated.PlatformInput{}}
		subtrahend = gql_generated.ImageInput{}
		_, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldNotBeNil)

		minuend = gql_generated.ImageInput{Repo: "repo-multi", Tag: "multi-img", Platform: &gql_generated.PlatformInput{
			Os:   ref("testOs"),
			Arch: ref("testArch"),
		}}
		subtrahend = gql_generated.ImageInput{}
		diffResult, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldBeNil)
		So(len(diffResult.CVEList), ShouldEqual, 1)
		So(diffResult.Subtrahend.Repo, ShouldEqual, "repo-multi")
		So(diffResult.Subtrahend.Tag, ShouldEqual, "multi-base")
		So(dderef(diffResult.Subtrahend.Platform.Os), ShouldResemble, "testOs")
		So(dderef(diffResult.Subtrahend.Platform.Arch), ShouldResemble, "testArch")

		minuend = gql_generated.ImageInput{Repo: "repo-multi", Tag: "multi-img", Platform: &gql_generated.PlatformInput{
			Os:   ref("testOs"),
			Arch: ref("testArch"),
		}}
		subtrahend = gql_generated.ImageInput{Repo: "repo-multi", Tag: "multi-base", Platform: &gql_generated.PlatformInput{
			Os:   ref("testOs"),
			Arch: ref("testArch"),
		}}
		diffResult, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldBeNil)
		So(len(diffResult.CVEList), ShouldEqual, 1)

		minuend = gql_generated.ImageInput{Repo: "repo-multi", Tag: "multi-img", Platform: &gql_generated.PlatformInput{
			Os:   ref("testOs"),
			Arch: ref("testArch"),
		}}
		subtrahend = gql_generated.ImageInput{Repo: "repo-multi", Tag: "multi-base", Platform: &gql_generated.PlatformInput{}}
		_, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, pageInput, "", "", log)
		So(err, ShouldNotBeNil)
	})

	Convey("CVE Diff Errors", t, func() {
		ctx := context.Background()
		metaDB := mocks.MetaDBMock{}
		cveInfo := mocks.CveInfoMock{}
		emptyImage := gql_generated.ImageInput{}

		Convey("minuend is empty", func() {
			_, err := getCVEDiffListForImages(ctx, emptyImage, emptyImage, metaDB, cveInfo, getGQLPageInput(0, 0), "", "", log)
			So(err, ShouldNotBeNil)
		})

		Convey("no ", func() {
			minuend := gql_generated.ImageInput{Repo: "repo", Tag: "bad-tag"}
			_, err := getCVEDiffListForImages(ctx, minuend, emptyImage, metaDB, cveInfo, getGQLPageInput(0, 0), "", "", log)
			So(err, ShouldNotBeNil)
		})

		Convey("getImageSummary for subtrahend errors", func() {
			metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{}, ErrTestError
			}
			minuend := gql_generated.ImageInput{Repo: "test", Tag: "img"}
			_, err := getCVEDiffListForImages(ctx, minuend, emptyImage, metaDB, cveInfo, getGQLPageInput(0, 0), "", "", log)
			So(err, ShouldNotBeNil)

			metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{}, zerr.ErrRepoMetaNotFound
			}
			minuend = gql_generated.ImageInput{Repo: "test", Tag: "img"}
			_, err = getCVEDiffListForImages(ctx, minuend, emptyImage, metaDB, cveInfo, getGQLPageInput(0, 0), "", "", log)
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags for subtrahend errors", func() {
			metaDB.FilterTagsFn = func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				return nil, ErrTestError
			}
			minuend := gql_generated.ImageInput{Repo: "test", Tag: "img"}
			_, err = getCVEDiffListForImages(ctx, minuend, emptyImage, metaDB, cveInfo, getGQLPageInput(0, 0), "", "", log)
			So(err, ShouldNotBeNil)
		})

		Convey("GetCVEDiffListForImages errors", func() {
			cveInfo.GetCVEDiffListForImagesFn = func(ctx context.Context, minuend, subtrahend, searchedCVE, excluded string,
				pageInput cvemodel.PageInput,
			) ([]cvemodel.CVE, cvemodel.ImageCVESummary, common.PageInfo, error) {
				return nil, cvemodel.ImageCVESummary{}, common.PageInfo{}, ErrTestError
			}
			minuend := gql_generated.ImageInput{Repo: "test", Tag: "img"}
			subtrahend := gql_generated.ImageInput{Repo: "sub", Tag: "img"}
			_, err = getCVEDiffListForImages(ctx, minuend, subtrahend, metaDB, cveInfo, getGQLPageInput(0, 0), "", "", log)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestMockedDerivedImageList(t *testing.T) {
	Convey("MetaDB FilterTags error", t, func() {
		log := log.NewLogger("debug", "/dev/null")

		image := CreateRandomImage()
		mockMetaDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				return []mTypes.FullImageMeta{}, ErrTestError
			},
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{}, ErrTestError
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return map[string]mTypes.ImageMeta{image.DigestStr(): image.AsImageMeta()}, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockMetaDB, &gql_generated.PageInput{},
			mockCve, log)
		So(err, ShouldNotBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	Convey("paginated fail", t, func() {
		log := log.NewLogger("debug", "/dev/null")
		image := CreateRandomImage()
		pageInput := &gql_generated.PageInput{
			Limit: ref(-1),
		}

		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		_, err := derivedImageList(responseContext, "repo1:1.0.1", nil,
			mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"1.0.1": {
								Digest:    image.DigestStr(),
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					}, nil
				},
				FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
					return map[string]mTypes.ImageMeta{image.DigestStr(): image.AsImageMeta()}, nil
				},
			},
			pageInput,
			mocks.CveInfoMock{}, log)
		So(err, ShouldNotBeNil)
	})

	//nolint: dupl
	Convey("MetaDB FilterTags no repo available", t, func() {
		log := log.NewLogger("debug", "/dev/null")
		image := CreateDefaultImage()

		mockMetaDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				return []mTypes.FullImageMeta{}, nil
			},
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.1": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return map[string]mTypes.ImageMeta{
					digests[0]: image.AsImageMeta(),
				}, nil
			},
			GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
				return image.AsImageMeta(), nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockMetaDB, &gql_generated.PageInput{},
			mockCve, log)
		So(err, ShouldBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	//nolint: dupl
	Convey("derived image list working", t, func() {
		log := log.NewLogger("debug", "/dev/null")
		layer1 := []byte{10, 11, 10, 11}
		layer2 := []byte{11, 11, 11, 11}
		layer3 := []byte{10, 10, 10, 11}
		layer4 := []byte{13, 14, 15, 11}

		image := CreateImageWith().
			LayerBlobs([][]byte{
				layer1,
				layer2,
				layer3,
			}).DefaultConfig().Build()

		derivedImage := CreateImageWith().
			LayerBlobs([][]byte{
				layer1,
				layer2,
				layer3,
				layer4,
			}).DefaultConfig().Build()

		imageMetaMap := map[string]mTypes.ImageMeta{
			image.DigestStr():        image.AsImageMeta(),
			derivedImage.DigestStr(): derivedImage.AsImageMeta(),
		}

		mockMetaDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.1": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
				return imageMetaMap[digest.String()], nil
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				result := map[string]mTypes.ImageMeta{}

				for _, digest := range digests {
					result[digest] = imageMetaMap[digest]
				}

				return result, nil
			},
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				fullImageMetaList := []mTypes.FullImageMeta{}
				repos := []mTypes.RepoMeta{{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.1": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
						"1.0.2": {Digest: derivedImage.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
						"1.0.3": {Digest: derivedImage.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}}

				for _, repo := range repos {
					for tag, descriptor := range repo.Tags {
						if filterFunc(repo, imageMetaMap[descriptor.Digest]) {
							fullImageMetaList = append(fullImageMetaList,
								convert.GetFullImageMeta(tag, repo, imageMetaMap[descriptor.Digest]))
						}
					}
				}

				return fullImageMetaList, nil
			},
		}

		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}

		Convey("valid derivedImageList, results not affected by pageInput", func() {
			images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockMetaDB, &gql_generated.PageInput{},
				mockCve, log)
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, 2)
		})

		Convey("valid derivedImageList, results affected by pageInput", func() {
			pageInput := gql_generated.PageInput{
				Limit:  ref(1),
				Offset: ref(0),
				SortBy: ref(gql_generated.SortCriteriaAlphabeticAsc),
			}

			images, err := derivedImageList(responseContext, "repo1:1.0.1", nil, mockMetaDB, &pageInput,
				mockCve, log)
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, 1)
		})
	})
}

func TestMockedBaseImageList(t *testing.T) {
	Convey("MetaDB FilterTags error", t, func() {
		mockMetaDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				return []mTypes.FullImageMeta{}, ErrTestError
			},
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{}, ErrTestError
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return map[string]mTypes.ImageMeta{}, ErrTestError
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockMetaDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	Convey("paginated fail", t, func() {
		image := CreateDefaultImage()
		pageInput := &gql_generated.PageInput{Limit: ref(-1)}

		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)
		_, err := baseImageList(responseContext, "repo1:1.0.2", nil,
			mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"1.0.2": {
								Digest:    image.DigestStr(),
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					}, nil
				},
				FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
					return map[string]mTypes.ImageMeta{image.DigestStr(): image.AsImageMeta()}, nil
				},
			},
			pageInput, mocks.CveInfoMock{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})

	//nolint: dupl
	Convey("MetaDB FilterTags no repo available", t, func() {
		image := CreateDefaultImage()

		mockMetaDB := mocks.MetaDBMock{
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				return []mTypes.FullImageMeta{}, nil
			},
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.2": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return map[string]mTypes.ImageMeta{image.DigestStr(): image.AsImageMeta()}, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockMetaDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(images.Results, ShouldBeEmpty)
	})

	//nolint: dupl
	Convey("base image list working", t, func() {
		layer1 := []byte{10, 11, 10, 11}
		layer2 := []byte{11, 11, 11, 11}
		layer3 := []byte{10, 10, 10, 11}
		layer4 := []byte{13, 14, 15, 11}

		image := CreateImageWith().
			LayerBlobs([][]byte{
				layer1,
				layer2,
				layer3,
			}).DefaultConfig().Build()

		derivedImage := CreateImageWith().
			LayerBlobs([][]byte{
				layer1,
				layer2,
				layer3,
				layer4,
			}).DefaultConfig().Build()

		imageMetaMap := map[string]mTypes.ImageMeta{
			image.DigestStr():        image.AsImageMeta(),
			derivedImage.DigestStr(): derivedImage.AsImageMeta(),
		}

		mockMetaDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.2": {Digest: derivedImage.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return imageMetaMap, nil
			},
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				fullImageMetaList := []mTypes.FullImageMeta{}
				repos := []mTypes.RepoMeta{{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.1": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
						"1.0.3": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
						"1.0.2": {Digest: derivedImage.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}}

				for _, repo := range repos {
					for tag, descriptor := range repo.Tags {
						if filterFunc(repo, imageMetaMap[descriptor.Digest]) {
							fullImageMetaList = append(fullImageMetaList,
								convert.GetFullImageMeta(tag, repo, imageMetaMap[descriptor.Digest]))
						}
					}
				}

				return fullImageMetaList, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}

		Convey("valid baseImageList, results not affected by pageInput", func() {
			images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockMetaDB,
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

			images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockMetaDB,
				&pageInput, mockCve, log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images.Results, ShouldNotBeEmpty)
			So(len(images.Results), ShouldEqual, limit)
			So(*images.Results[0].Tag, ShouldEqual, "1.0.1")
		})
	})

	//nolint: dupl
	Convey("filterTags working, no base image list found", t, func() {
		layer1 := []byte{10, 11, 10, 11}
		layer2 := []byte{11, 11, 11, 11}
		layer3 := []byte{10, 10, 10, 11}
		layer4 := []byte{13, 14, 15, 11}

		image := CreateImageWith().
			LayerBlobs([][]byte{
				layer1,
				layer2,
				layer3,
			}).DefaultConfig().Build()

		derivedImage := CreateImageWith().
			LayerBlobs([][]byte{
				layer4,
			}).DefaultConfig().Build()

		imageMetaMap := map[string]mTypes.ImageMeta{
			image.DigestStr():        image.AsImageMeta(),
			derivedImage.DigestStr(): derivedImage.AsImageMeta(),
		}

		mockMetaDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.2": {Digest: derivedImage.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}, nil
			},
			FilterImageMetaFn: func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error) {
				return imageMetaMap, nil
			},
			FilterTagsFn: func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc, filterFunc mTypes.FilterFunc,
			) ([]mTypes.FullImageMeta, error) {
				fullImageMetaList := []mTypes.FullImageMeta{}
				repos := []mTypes.RepoMeta{{
					Name: "repo1",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"1.0.1": {Digest: image.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
						"1.0.2": {Digest: derivedImage.DigestStr(), MediaType: ispec.MediaTypeImageManifest},
					},
				}}

				for _, repo := range repos {
					for tag, descriptor := range repo.Tags {
						if filterFunc(repo, imageMetaMap[descriptor.Digest]) {
							fullImageMetaList = append(fullImageMetaList,
								convert.GetFullImageMeta(tag, repo, imageMetaMap[descriptor.Digest]))
						}
					}
				}

				return fullImageMetaList, nil
			},
		}
		responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
			graphql.DefaultRecover)

		mockCve := mocks.CveInfoMock{}
		images, err := baseImageList(responseContext, "repo1:1.0.2", nil, mockMetaDB, &gql_generated.PageInput{},
			mockCve, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(images.Results, ShouldBeEmpty)
	})
}

func TestExpandedRepoInfoErrors(t *testing.T) {
	log := log.NewLogger("debug", "")

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

func TestUtils(t *testing.T) {
	Convey("utils", t, func() {
		Convey("", func() {
			So(isMatchingPlatform(ispec.Platform{OS: "test"}, gql_generated.PlatformInput{Os: ref("t")}), ShouldBeFalse)
			So(getArch(ispec.Platform{OS: "t", Architecture: "e", Variant: "st"}), ShouldResemble, "e/st")
		})

		Convey("checkImageInput", func() {
			_, err := resolveImageData(context.Background(), gql_generated.ImageInput{Repo: "test"}, mocks.MetaDBMock{})
			So(err, ShouldNotBeNil)
		})

		Convey("checkImageInput can't find index data", func() {
			_, err := resolveImageData(context.Background(), gql_generated.ImageInput{
				Repo: "test", Tag: "test", Digest: ref("dig"),
			},
				mocks.MetaDBMock{
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{Tags: map[string]mTypes.Descriptor{
							"test": {MediaType: ispec.MediaTypeImageIndex},
						}}, nil
					},
					GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
						return mTypes.ImageMeta{}, ErrTestError
					},
				})
			So(err, ShouldNotBeNil)
		})
		Convey("checkImageInput image meta not found", func() {
			_, err := resolveImageData(context.Background(), gql_generated.ImageInput{
				Repo: "test", Tag: "test", Digest: ref("dig"),
			},
				mocks.MetaDBMock{
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{Tags: map[string]mTypes.Descriptor{
							"test": {MediaType: ispec.MediaTypeImageIndex},
						}}, nil
					},
					GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
						return mTypes.ImageMeta{}, nil
					},
				})
			So(err, ShouldNotBeNil)
		})
		Convey("checkImageInput image meta bad media type", func() {
			_, err := resolveImageData(context.Background(), gql_generated.ImageInput{
				Repo: "test", Tag: "test", Digest: ref("dig"),
			},
				mocks.MetaDBMock{
					GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
						return mTypes.RepoMeta{Tags: map[string]mTypes.Descriptor{
							"test": {MediaType: "bad-type"},
						}}, nil
					},
					GetImageMetaFn: func(digest godigest.Digest) (mTypes.ImageMeta, error) {
						return mTypes.ImageMeta{}, nil
					},
				})
			So(err, ShouldBeNil)
		})
	})
}

func getGQLPageInput(limit int, offset int) *gql_generated.PageInput {
	sortCriteria := gql_generated.SortCriteriaAlphabeticAsc

	return &gql_generated.PageInput{
		Limit:  &limit,
		Offset: &offset,
		SortBy: &sortCriteria,
	}
}
