package repodb_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/meta/repodb"
)

func TestPagination(t *testing.T) {
	Convey("Repo Pagination", t, func() {
		Convey("reset", func() {
			pageFinder, err := repodb.NewBaseRepoPageFinder(1, 0, repodb.AlphabeticAsc)
			So(err, ShouldBeNil)
			So(pageFinder, ShouldNotBeNil)

			pageFinder.Add(repodb.DetailedRepoMeta{})
			pageFinder.Add(repodb.DetailedRepoMeta{})
			pageFinder.Add(repodb.DetailedRepoMeta{})

			pageFinder.Reset()

			So(pageFinder.Page(), ShouldBeEmpty)
		})
	})

	Convey("Image Pagination", t, func() {
		Convey("create new pageFinder errors", func() {
			pageFinder, err := repodb.NewBaseImagePageFinder(-1, 10, repodb.AlphabeticAsc)
			So(pageFinder, ShouldBeNil)
			So(err, ShouldNotBeNil)

			pageFinder, err = repodb.NewBaseImagePageFinder(2, -1, repodb.AlphabeticAsc)
			So(pageFinder, ShouldBeNil)
			So(err, ShouldNotBeNil)

			pageFinder, err = repodb.NewBaseImagePageFinder(2, 1, "wrong sorting criteria")
			So(pageFinder, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})

		Convey("Reset", func() {
			pageFinder, err := repodb.NewBaseImagePageFinder(1, 0, repodb.AlphabeticAsc)
			So(err, ShouldBeNil)
			So(pageFinder, ShouldNotBeNil)

			pageFinder.Add(repodb.DetailedRepoMeta{})
			pageFinder.Add(repodb.DetailedRepoMeta{})
			pageFinder.Add(repodb.DetailedRepoMeta{})

			pageFinder.Reset()

			So(pageFinder.Page(), ShouldBeEmpty)
		})

		Convey("Page", func() {
			Convey("limit < len(tags)", func() {
				pageFinder, err := repodb.NewBaseImagePageFinder(5, 2, repodb.AlphabeticAsc)
				So(err, ShouldBeNil)
				So(pageFinder, ShouldNotBeNil)

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo1",
						Tags: map[string]string{
							"tag1": "dig1",
						},
					},
				})

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo2",
						Tags: map[string]string{
							"Tag1": "dig1",
							"Tag2": "dig2",
							"Tag3": "dig3",
							"Tag4": "dig4",
						},
					},
				})
				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo3",
						Tags: map[string]string{
							"Tag11": "dig11",
							"Tag12": "dig12",
							"Tag13": "dig13",
							"Tag14": "dig14",
						},
					},
				})

				result := pageFinder.Page()
				So(result[0].Tags, ShouldContainKey, "Tag2")
				So(result[0].Tags, ShouldContainKey, "Tag3")
				So(result[0].Tags, ShouldContainKey, "Tag4")
				So(result[1].Tags, ShouldContainKey, "Tag11")
				So(result[1].Tags, ShouldContainKey, "Tag12")
			})

			Convey("limit > len(tags)", func() {
				pageFinder, err := repodb.NewBaseImagePageFinder(3, 0, repodb.AlphabeticAsc)
				So(err, ShouldBeNil)
				So(pageFinder, ShouldNotBeNil)

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo1",
						Tags: map[string]string{
							"tag1": "dig1",
						},
					},
				})

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo2",
						Tags: map[string]string{
							"Tag1": "dig1",
						},
					},
				})
				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo3",
						Tags: map[string]string{
							"Tag11": "dig11",
						},
					},
				})

				result := pageFinder.Page()
				So(result[0].Tags, ShouldContainKey, "tag1")
				So(result[1].Tags, ShouldContainKey, "Tag1")
				So(result[2].Tags, ShouldContainKey, "Tag11")
			})
		})
	})
}
