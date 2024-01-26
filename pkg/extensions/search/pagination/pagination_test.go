//go:build search

package pagination_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/pkg/extensions/search/pagination"
)

func TestImgSumPagination(t *testing.T) {
	Convey("NewImgSumPageFinder errors", t, func() {
		_, err := pagination.NewImgSumPageFinder(-1, 0, pagination.AlphabeticAsc)
		So(err, ShouldNotBeNil)

		_, err = pagination.NewImgSumPageFinder(0, -1, pagination.AlphabeticAsc)
		So(err, ShouldNotBeNil)

		_, err = pagination.NewImgSumPageFinder(0, 0, "unknown")
		So(err, ShouldNotBeNil)
	})

	Convey("Sort Functions", t, func() {
		Convey("ImgSortByAlphabeticAsc", func() {
			// Case: repo1 is < repo2
			pageBuff := []*gql_generated.ImageSummary{
				{RepoName: ref("repo1:1")},
				{RepoName: ref("repo2:2")},
			}

			sortFunc := pagination.ImgSortByAlphabeticAsc(pageBuff)
			So(sortFunc(0, 1), ShouldBeTrue)
		})

		Convey("ImgSortByAlphabeticDsc", func() {
			// Case: repo1 is < repo2
			pageBuff := []*gql_generated.ImageSummary{
				{RepoName: ref("repo1:1")},
				{RepoName: ref("repo2:2")},
			}

			sortFunc := pagination.ImgSortByAlphabeticDsc(pageBuff)
			So(sortFunc(0, 1), ShouldBeFalse)
		})

		Convey("ImgSortByRelevance", func() {
			// Case: repo1 is < repo2
			pageBuff := []*gql_generated.ImageSummary{
				{RepoName: ref("repo1:1")},
				{RepoName: ref("repo2:2")},
			}

			sortFunc := pagination.ImgSortByRelevance(pageBuff)
			So(sortFunc(0, 1), ShouldBeTrue)
		})
	})
}

func TestRepoSumPagination(t *testing.T) {
	Convey("NewRepoSumPageFinder errors", t, func() {
		_, err := pagination.NewRepoSumPageFinder(-1, 0, pagination.AlphabeticAsc)
		So(err, ShouldNotBeNil)

		_, err = pagination.NewRepoSumPageFinder(0, -1, pagination.AlphabeticAsc)
		So(err, ShouldNotBeNil)

		_, err = pagination.NewRepoSumPageFinder(0, 0, "unknown")
		So(err, ShouldNotBeNil)
	})
}

func ref[T any](input T) *T {
	obj := input

	return &obj
}

func TestPagination(t *testing.T) {
	Convey("Image Pagination", t, func() {
		Convey("Sort functions", func() {
			imgSum1 := gql_generated.ImageSummary{
				RepoName:      ref("1"),
				Tag:           ref("1"),
				LastUpdated:   ref(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(33),
			}

			imgSum2 := gql_generated.ImageSummary{
				RepoName:      ref("1"),
				Tag:           ref("latest"),
				LastUpdated:   ref(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(11),
			}

			imgSum3 := gql_generated.ImageSummary{
				RepoName:      ref("3"),
				Tag:           ref("1"),
				LastUpdated:   ref(time.Date(2011, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(22),
			}

			imgSum4 := gql_generated.ImageSummary{
				RepoName:      ref("4"),
				Tag:           ref("latest"),
				LastUpdated:   ref(time.Date(2012, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(44),
			}

			// ImgSortByAlphabeticAsc
			imagePageFinder, err := pagination.NewImgSumPageFinder(4, 0, pagination.AlphabeticAsc)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)
			page, _ := imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.ImageSummary{
				&imgSum1, &imgSum2, &imgSum3, &imgSum4,
			})

			// ImgSortByAlphabeticDsc
			imagePageFinder, err = pagination.NewImgSumPageFinder(4, 0, pagination.AlphabeticDsc)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.ImageSummary{
				&imgSum4, &imgSum3, &imgSum2, &imgSum1,
			})

			// ImgSortByRelevance
			imagePageFinder, err = pagination.NewImgSumPageFinder(4, 0, pagination.Relevance)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.ImageSummary{
				&imgSum1, &imgSum2, &imgSum3, &imgSum4,
			})

			// ImgSortByUpdateTime
			imagePageFinder, err = pagination.NewImgSumPageFinder(4, 0, pagination.UpdateTime)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.ImageSummary{
				&imgSum2, &imgSum1, &imgSum4, &imgSum3,
			})

			// ImgSortByDownloads
			imagePageFinder, err = pagination.NewImgSumPageFinder(4, 0, pagination.Downloads)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.ImageSummary{
				&imgSum4, &imgSum1, &imgSum3, &imgSum2,
			})
		})

		Convey("Errors", func() {
			imagePageFinder, err := pagination.NewImgSumPageFinder(2, 0, "")
			So(err, ShouldBeNil)
			So(imagePageFinder, ShouldNotBeNil)

			_, err = pagination.NewImgSumPageFinder(-1, 0, "")
			So(err, ShouldNotBeNil)

			_, err = pagination.NewImgSumPageFinder(1, -1, "")
			So(err, ShouldNotBeNil)

			_, err = pagination.NewImgSumPageFinder(1, -1, "bad sort func")
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Repos Pagination", t, func() {
		Convey("Sort functions", func() {
			repoSum1 := gql_generated.RepoSummary{
				Name:          ref("1"),
				LastUpdated:   ref(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(33),
				Rank:          ref(1),
			}

			repoSum2 := gql_generated.RepoSummary{
				Name:          ref("2"),
				LastUpdated:   ref(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(11),
				Rank:          ref(2),
			}

			repoSum3 := gql_generated.RepoSummary{
				Name:          ref("3"),
				LastUpdated:   ref(time.Date(2011, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(22),
				Rank:          ref(3),
			}

			repoSum4 := gql_generated.RepoSummary{
				Name:          ref("4"),
				LastUpdated:   ref(time.Date(2012, 1, 1, 1, 1, 1, 1, time.UTC)),
				DownloadCount: ref(44),
				Rank:          ref(4),
			}

			// ImgSortByAlphabeticAsc
			imagePageFinder, err := pagination.NewRepoSumPageFinder(4, 0, pagination.AlphabeticAsc)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&repoSum1)
			imagePageFinder.Add(&repoSum2)
			imagePageFinder.Add(&repoSum3)
			imagePageFinder.Add(&repoSum4)
			page, _ := imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.RepoSummary{
				&repoSum1, &repoSum2, &repoSum3, &repoSum4,
			})

			// ImgSortByAlphabeticDsc
			imagePageFinder, err = pagination.NewRepoSumPageFinder(4, 0, pagination.AlphabeticDsc)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&repoSum1)
			imagePageFinder.Add(&repoSum2)
			imagePageFinder.Add(&repoSum3)
			imagePageFinder.Add(&repoSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.RepoSummary{
				&repoSum4, &repoSum3, &repoSum2, &repoSum1,
			})

			// ImgSortByRelevance
			imagePageFinder, err = pagination.NewRepoSumPageFinder(4, 0, pagination.Relevance)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&repoSum1)
			imagePageFinder.Add(&repoSum2)
			imagePageFinder.Add(&repoSum3)
			imagePageFinder.Add(&repoSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.RepoSummary{
				&repoSum1, &repoSum2, &repoSum3, &repoSum4,
			})

			// ImgSortByUpdateTime
			imagePageFinder, err = pagination.NewRepoSumPageFinder(4, 0, pagination.UpdateTime)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&repoSum1)
			imagePageFinder.Add(&repoSum2)
			imagePageFinder.Add(&repoSum3)
			imagePageFinder.Add(&repoSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.RepoSummary{
				&repoSum2, &repoSum4, &repoSum3, &repoSum1,
			})

			// ImgSortByDownloads
			imagePageFinder, err = pagination.NewRepoSumPageFinder(4, 0, pagination.Downloads)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&repoSum1)
			imagePageFinder.Add(&repoSum2)
			imagePageFinder.Add(&repoSum3)
			imagePageFinder.Add(&repoSum4)
			page, _ = imagePageFinder.Page()
			So(page, ShouldEqual, []*gql_generated.RepoSummary{
				&repoSum4, &repoSum1, &repoSum3, &repoSum2,
			})
		})

		Convey("Errors", func() {
			repoPageFinder, err := pagination.NewRepoSumPageFinder(2, 0, "")
			So(err, ShouldBeNil)
			So(repoPageFinder, ShouldNotBeNil)

			_, err = pagination.NewRepoSumPageFinder(-1, 0, "")
			So(err, ShouldNotBeNil)

			_, err = pagination.NewRepoSumPageFinder(1, -1, "")
			So(err, ShouldNotBeNil)

			_, err = pagination.NewRepoSumPageFinder(1, -1, "bad sort func")
			So(err, ShouldNotBeNil)
		})
	})
}
