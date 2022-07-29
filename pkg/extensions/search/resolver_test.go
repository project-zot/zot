package search //nolint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/repodb"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestGlobalSearch(t *testing.T) {
	Convey("globalSearch", t, func() {
		const query = "repo1"
		Convey("RepoDB SearchRepos error", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &gql_generated.PageInput{},
				log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo is successful", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, requestedPage repodb.PageInput,
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
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &pageInput,
				log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)
			So(len(repos[0].Vendors), ShouldEqual, 2)
		})

		Convey("RepoDB SearchRepo Bad manifest refferenced", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, requestedPage repodb.PageInput,
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
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)

			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &pageInput,
				log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"

			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockSearchDB, &pageInput,
				log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchRepo good manifest refferenced and bad config blob", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchReposFn: func(ctx context.Context, searchText string, requestedPage repodb.PageInput,
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
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &pageInput,
				log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldNotBeEmpty)

			query = "repo1:1.0.1"
			responseContext = graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err = globalSearch(responseContext, query, mockSearchDB, &pageInput,
				log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags gives error", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, requestedPage repodb.PageInput,
				) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
					return make([]repodb.RepoMetadata, 0), make(map[string]repodb.ManifestMetadata), ErrTestError
				},
			}
			const query = "repo1:1.0.1"

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &gql_generated.PageInput{},
				log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
			So(images, ShouldBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
		})

		Convey("RepoDB SearchTags is successful", func() {
			mockSearchDB := mocks.RepoDBMock{
				SearchTagsFn: func(ctx context.Context, searchText string, requestedPage repodb.PageInput,
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
			ofset := 0
			sortCriteria := gql_generated.SortCriteriaAlphabeticAsc
			pageInput := gql_generated.PageInput{
				Limit:  &limit,
				Offset: &ofset,
				SortBy: &sortCriteria,
			}

			responseContext := graphql.WithResponseContext(context.Background(), graphql.DefaultErrorPresenter,
				graphql.DefaultRecover)
			repos, images, layers, err := globalSearch(responseContext, query, mockSearchDB, &pageInput,
				log.NewLogger("debug", ""))
			So(err, ShouldBeNil)
			So(images, ShouldNotBeEmpty)
			So(layers, ShouldBeEmpty)
			So(repos, ShouldBeEmpty)
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
		score := calculateImageMatchingScore("alpine", strings.Index("alpine", query))
		So(score, ShouldEqual, 0)
	})

	Convey("Partial Matching", t, func() {
		query := pine
		score := calculateImageMatchingScore("alpine", strings.Index("alpine", query))
		So(score, ShouldEqual, 2)
	})

	Convey("Complex Partial Matching", t, func() {
		query := pine
		score := calculateImageMatchingScore("repo/test/alpine", strings.Index("alpine", query))
		So(score, ShouldEqual, 2)

		query = pine
		score = calculateImageMatchingScore("repo/alpine/test", strings.Index("alpine", query))
		So(score, ShouldEqual, 2)

		query = pine
		score = calculateImageMatchingScore("alpine/repo/test", strings.Index("alpine", query))
		So(score, ShouldEqual, 2)
	})
}
