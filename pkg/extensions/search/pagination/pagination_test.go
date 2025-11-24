//go:build search

package pagination_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/v2/pkg/extensions/search/pagination"
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
			image1 := &gql_generated.ImageSummary{RepoName: ref("repo1:1")}
			image2 := &gql_generated.ImageSummary{RepoName: ref("repo2:2")}

			So(pagination.ImgSortByAlphabeticAsc(image1, image2), ShouldEqual, -1)
		})

		Convey("ImgSortByAlphabeticDsc", func() {
			// Case: repo1 is < repo2
			image1 := &gql_generated.ImageSummary{RepoName: ref("repo1:1")}
			image2 := &gql_generated.ImageSummary{RepoName: ref("repo2:2")}

			So(pagination.ImgSortByAlphabeticDsc(image1, image2), ShouldEqual, 1)
		})

		Convey("ImgSortByRelevance", func() {
			// Case: repo1 is < repo2
			image1 := &gql_generated.ImageSummary{RepoName: ref("repo1:1")}
			image2 := &gql_generated.ImageSummary{RepoName: ref("repo2:2")}

			So(pagination.ImgSortByRelevance(image1, image2), ShouldEqual, -1)
		})

		Convey("ImgSortByUpdateTime with nil and zero LastUpdated", func() {
			time1 := time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)
			time2 := time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)
			zeroTime := time.Time{}

			// Both nil - should be equal
			image1 := &gql_generated.ImageSummary{RepoName: ref("repo1"), Tag: ref("tag1"), LastUpdated: nil}
			image2 := &gql_generated.ImageSummary{RepoName: ref("repo2"), Tag: ref("tag2"), LastUpdated: nil}
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 0)

			// Both zero time - should be equal (treated same as nil)
			image1.LastUpdated = &zeroTime
			image2.LastUpdated = &zeroTime
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 0)

			// a is nil, b is zero - should be equal (both treated as oldest)
			image1.LastUpdated = nil
			image2.LastUpdated = &zeroTime
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 0)

			// a is nil, b is not - a should come after b (return 1)
			image1.LastUpdated = nil
			image2.LastUpdated = &time1
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 1)

			// a is zero, b is not - a should come after b (return 1)
			image1.LastUpdated = &zeroTime
			image2.LastUpdated = &time1
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 1)

			// b is nil, a is not - a should come before b (return -1)
			image1.LastUpdated = &time1
			image2.LastUpdated = nil
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, -1)

			// b is zero, a is not - a should come before b (return -1)
			image1.LastUpdated = &time1
			image2.LastUpdated = &zeroTime
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, -1)

			// Both non-nil - normal comparison (a is newer, should come first in descending sort)
			image1.LastUpdated = &time1
			image2.LastUpdated = &time2
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, -1)

			// Both non-nil - normal comparison (b is newer, should come first in descending sort)
			image1.LastUpdated = &time2
			image2.LastUpdated = &time1
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 1)

			// Both non-nil and equal
			image1.LastUpdated = &time1
			image2.LastUpdated = &time1
			So(pagination.ImgSortByUpdateTime(image1, image2), ShouldEqual, 0)
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
		// Verify it's the specific error for unsupported sort criteria
		So(err.Error(), ShouldContainSubstring, "sorting repos by 'unknown' is not supported")
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

			// ImgSortByUpdateTime (sorts by image LastUpdated descending)
			imagePageFinder, err = pagination.NewImgSumPageFinder(4, 0, pagination.UpdateTime)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)
			page, _ = imagePageFinder.Page()
			// Expected order: imgSum2 (2020), imgSum4 (2012), imgSum3 (2011), imgSum1 (2010)
			So(page, ShouldEqual, []*gql_generated.ImageSummary{
				&imgSum2, &imgSum4, &imgSum3, &imgSum1,
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

		Convey("ImgSortByUpdateTime with nil LastUpdated in pagination", func() {
			// Test pagination with images that have nil LastUpdated
			imgSumWithTime := gql_generated.ImageSummary{
				RepoName:    ref("repo1"),
				Tag:         ref("tag1"),
				LastUpdated: ref(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)),
			}
			imgSumNil1 := gql_generated.ImageSummary{
				RepoName:    ref("repo2"),
				Tag:         ref("tag2"),
				LastUpdated: nil,
			}
			imgSumNil2 := gql_generated.ImageSummary{
				RepoName:    ref("repo3"),
				Tag:         ref("tag3"),
				LastUpdated: nil,
			}
			imgSumOlder := gql_generated.ImageSummary{
				RepoName:    ref("repo4"),
				Tag:         ref("tag4"),
				LastUpdated: ref(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)),
			}

			imagePageFinder, err := pagination.NewImgSumPageFinder(4, 0, pagination.UpdateTime)
			So(err, ShouldBeNil)
			imagePageFinder.Add(&imgSumNil1)
			imagePageFinder.Add(&imgSumWithTime)
			imagePageFinder.Add(&imgSumNil2)
			imagePageFinder.Add(&imgSumOlder)
			page, _ := imagePageFinder.Page()

			// Expected order: imgSumWithTime (2020), imgSumOlder (2010), then nil values (imgSumNil1, imgSumNil2)
			So(len(page), ShouldEqual, 4)
			So(*page[0].RepoName, ShouldEqual, "repo1") // 2020 - newest
			So(*page[1].RepoName, ShouldEqual, "repo4") // 2010 - older
			// Nil values should come last
			So(page[2].LastUpdated == nil || page[3].LastUpdated == nil, ShouldBeTrue)
		})

		Convey("Tie-breaking when values match", func() {
			// Test tie-breaking for AlphabeticAsc - when RepoName and Tag are equal
			imagePageFinder, err := pagination.NewImgSumPageFinder(10, 0, pagination.AlphabeticAsc)
			So(err, ShouldBeNil)

			// Add images with same RepoName and Tag but different LastUpdated to verify stable sort
			imgSum1 := gql_generated.ImageSummary{
				RepoName:    ref("repo1"),
				Tag:         ref("tag1"),
				LastUpdated: ref(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)),
			}
			imgSum2 := gql_generated.ImageSummary{
				RepoName:    ref("repo1"),
				Tag:         ref("tag1"),
				LastUpdated: ref(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)),
			}
			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)

			page, _ := imagePageFinder.Page()
			// When RepoName and Tag are equal, sort is stable - first added stays first
			So(len(page), ShouldEqual, 2)
			So(*page[0].RepoName, ShouldEqual, "repo1")
			So(*page[0].Tag, ShouldEqual, "tag1")
			So(page[0].LastUpdated.Equal(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)), ShouldBeTrue) // First added
			So(*page[1].RepoName, ShouldEqual, "repo1")
			So(*page[1].Tag, ShouldEqual, "tag1")
			So(page[1].LastUpdated.Equal(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)), ShouldBeTrue) // Second added

			// Test tie-breaking for AlphabeticDsc
			imagePageFinder, err = pagination.NewImgSumPageFinder(10, 0, pagination.AlphabeticDsc)
			So(err, ShouldBeNil)

			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)

			page, _ = imagePageFinder.Page()
			// When RepoName and Tag are equal, sort is stable - first added stays first
			So(len(page), ShouldEqual, 2)
			So(page[0].LastUpdated.Equal(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)), ShouldBeTrue) // First added
			So(page[1].LastUpdated.Equal(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)), ShouldBeTrue) // Second added

			// Test tie-breaking for Relevance
			imagePageFinder, err = pagination.NewImgSumPageFinder(10, 0, pagination.Relevance)
			So(err, ShouldBeNil)

			imagePageFinder.Add(&imgSum1)
			imagePageFinder.Add(&imgSum2)

			page, _ = imagePageFinder.Page()
			// When RepoName and Tag are equal, sort is stable - first added stays first
			So(len(page), ShouldEqual, 2)
			So(page[0].LastUpdated.Equal(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)), ShouldBeTrue) // First added
			So(page[1].LastUpdated.Equal(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)), ShouldBeTrue) // Second added

			// Test tie-breaking for UpdateTime - when LastUpdated times are equal
			imagePageFinder, err = pagination.NewImgSumPageFinder(10, 0, pagination.UpdateTime)
			So(err, ShouldBeNil)

			sameTime := time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)
			imgSum3 := gql_generated.ImageSummary{
				RepoName:    ref("repo1"),
				Tag:         ref("tag1"),
				LastUpdated: ref(sameTime),
			}
			imgSum4 := gql_generated.ImageSummary{
				RepoName:    ref("repo2"),
				Tag:         ref("tag2"),
				LastUpdated: ref(sameTime),
			}
			imagePageFinder.Add(&imgSum3)
			imagePageFinder.Add(&imgSum4)

			page, _ = imagePageFinder.Page()
			// When LastUpdated times are equal, sort is stable - first added stays first
			So(len(page), ShouldEqual, 2)
			So(*page[0].RepoName, ShouldEqual, "repo1") // First added
			So(*page[1].RepoName, ShouldEqual, "repo2") // Second added

			// Test tie-breaking for Downloads - when DownloadCount values are equal
			imagePageFinder, err = pagination.NewImgSumPageFinder(10, 0, pagination.Downloads)
			So(err, ShouldBeNil)

			imgSum5 := gql_generated.ImageSummary{
				RepoName:      ref("repo1"),
				Tag:           ref("tag1"),
				DownloadCount: ref(100),
			}
			imgSum6 := gql_generated.ImageSummary{
				RepoName:      ref("repo2"),
				Tag:           ref("tag2"),
				DownloadCount: ref(100),
			}
			imagePageFinder.Add(&imgSum5)
			imagePageFinder.Add(&imgSum6)

			page, _ = imagePageFinder.Page()
			// When DownloadCount values are equal, sort is stable - first added stays first
			So(len(page), ShouldEqual, 2)
			So(*page[0].RepoName, ShouldEqual, "repo1") // First added
			So(*page[1].RepoName, ShouldEqual, "repo2") // Second added
		})

		Convey("Errors", func() {
			imagePageFinder, err := pagination.NewImgSumPageFinder(2, 0, "")
			So(err, ShouldBeNil)
			So(imagePageFinder, ShouldNotBeNil)

			_, err = pagination.NewImgSumPageFinder(-1, 0, "")
			So(err, ShouldNotBeNil)

			_, err = pagination.NewImgSumPageFinder(1, -1, "")
			So(err, ShouldNotBeNil)

			// Test invalid sortBy with valid limit and offset to ensure it reaches the sortBy validation
			_, err = pagination.NewImgSumPageFinder(1, 0, "bad sort func")
			So(err, ShouldNotBeNil)
			// Verify it's the specific error for unsupported sort criteria
			So(err.Error(), ShouldContainSubstring, "sorting repos by 'bad sort func' is not supported")
		})
	})

	Convey("Repos Pagination", t, func() {
		Convey("Sort Functions unit tests", func() {
			Convey("RepoSortByAlphabeticAsc", func() {
				// Case: repo1 is < repo2
				repo1 := &gql_generated.RepoSummary{Name: ref("repo1")}
				repo2 := &gql_generated.RepoSummary{Name: ref("repo2")}

				So(pagination.RepoSortByAlphabeticAsc(repo1, repo2), ShouldEqual, -1)
				So(pagination.RepoSortByAlphabeticAsc(repo2, repo1), ShouldEqual, 1)
				So(pagination.RepoSortByAlphabeticAsc(repo1, repo1), ShouldEqual, 0)
			})

			Convey("RepoSortByAlphabeticDsc", func() {
				// Case: repo1 is < repo2, so descending should return 1
				repo1 := &gql_generated.RepoSummary{Name: ref("repo1")}
				repo2 := &gql_generated.RepoSummary{Name: ref("repo2")}

				So(pagination.RepoSortByAlphabeticDsc(repo1, repo2), ShouldEqual, 1)
				So(pagination.RepoSortByAlphabeticDsc(repo2, repo1), ShouldEqual, -1)
				So(pagination.RepoSortByAlphabeticDsc(repo1, repo1), ShouldEqual, 0)
			})

			Convey("RepoSortByDownloads", func() {
				// Case: repo1 has more downloads than repo2, so should return -1 (descending)
				repo1 := &gql_generated.RepoSummary{DownloadCount: ref(100)}
				repo2 := &gql_generated.RepoSummary{DownloadCount: ref(50)}

				So(pagination.RepoSortByDownloads(repo1, repo2), ShouldEqual, -1)
				So(pagination.RepoSortByDownloads(repo2, repo1), ShouldEqual, 1)
				So(pagination.RepoSortByDownloads(repo1, repo1), ShouldEqual, 0)
			})

			Convey("RepoSortByUpdateTime with nil and zero LastUpdated", func() {
				time1 := time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)
				time2 := time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)
				zeroTime := time.Time{}

				// Both nil - should be equal
				repo1 := &gql_generated.RepoSummary{Name: ref("repo1"), LastUpdated: nil}
				repo2 := &gql_generated.RepoSummary{Name: ref("repo2"), LastUpdated: nil}
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 0)

				// Both zero time - should be equal (treated same as nil)
				repo1.LastUpdated = &zeroTime
				repo2.LastUpdated = &zeroTime
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 0)

				// a is nil, b is zero - should be equal (both treated as oldest)
				repo1.LastUpdated = nil
				repo2.LastUpdated = &zeroTime
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 0)

				// a is nil, b is not - a should come after b (return 1)
				repo1.LastUpdated = nil
				repo2.LastUpdated = &time1
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 1)

				// a is zero, b is not - a should come after b (return 1)
				repo1.LastUpdated = &zeroTime
				repo2.LastUpdated = &time1
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 1)

				// b is nil, a is not - a should come before b (return -1)
				repo1.LastUpdated = &time1
				repo2.LastUpdated = nil
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, -1)

				// b is zero, a is not - a should come before b (return -1)
				repo1.LastUpdated = &time1
				repo2.LastUpdated = &zeroTime
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, -1)

				// Both non-nil - normal comparison (a is newer, should come first in descending sort)
				repo1.LastUpdated = &time1
				repo2.LastUpdated = &time2
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, -1)

				// Both non-nil - normal comparison (b is newer, should come first in descending sort)
				repo1.LastUpdated = &time2
				repo2.LastUpdated = &time1
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 1)

				// Both non-nil and equal
				repo1.LastUpdated = &time1
				repo2.LastUpdated = &time1
				So(pagination.RepoSortByUpdateTime(repo1, repo2), ShouldEqual, 0)
			})
		})

		Convey("Repo page finder tests", func() {
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

		Convey("RepoSortByUpdateTime with nil LastUpdated in pagination", func() {
			// Test pagination with repos that have nil LastUpdated
			repoSumWithTime := gql_generated.RepoSummary{
				Name:        ref("repo1"),
				LastUpdated: ref(time.Date(2020, 1, 1, 1, 1, 1, 1, time.UTC)),
			}
			repoSumNil1 := gql_generated.RepoSummary{
				Name:        ref("repo2"),
				LastUpdated: nil,
			}
			repoSumNil2 := gql_generated.RepoSummary{
				Name:        ref("repo3"),
				LastUpdated: nil,
			}
			repoSumOlder := gql_generated.RepoSummary{
				Name:        ref("repo4"),
				LastUpdated: ref(time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC)),
			}

			repoPageFinder, err := pagination.NewRepoSumPageFinder(4, 0, pagination.UpdateTime)
			So(err, ShouldBeNil)
			repoPageFinder.Add(&repoSumNil1)
			repoPageFinder.Add(&repoSumWithTime)
			repoPageFinder.Add(&repoSumNil2)
			repoPageFinder.Add(&repoSumOlder)
			page, _ := repoPageFinder.Page()

			// Expected order: repoSumWithTime (2020), repoSumOlder (2010), then nil values (repoSumNil1, repoSumNil2)
			So(len(page), ShouldEqual, 4)
			So(*page[0].Name, ShouldEqual, "repo1") // 2020 - newest
			So(*page[1].Name, ShouldEqual, "repo4") // 2010 - older
			// Nil values should come last
			So(page[2].LastUpdated == nil || page[3].LastUpdated == nil, ShouldBeTrue)
		})

		Convey("Repo page finder error tests", func() {
			repoPageFinder, err := pagination.NewRepoSumPageFinder(2, 0, "")
			So(err, ShouldBeNil)
			So(repoPageFinder, ShouldNotBeNil)

			_, err = pagination.NewRepoSumPageFinder(-1, 0, "")
			So(err, ShouldNotBeNil)

			_, err = pagination.NewRepoSumPageFinder(1, -1, "")
			So(err, ShouldNotBeNil)

			// Test invalid sortBy with valid limit and offset to ensure it reaches the sortBy validation
			_, err = pagination.NewRepoSumPageFinder(1, 0, "bad sort func")
			So(err, ShouldNotBeNil)
			// Verify it's the specific error for unsupported sort criteria
			So(err.Error(), ShouldContainSubstring, "sorting repos by 'bad sort func' is not supported")
		})
	})
}
