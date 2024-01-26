//go:build search
// +build search

package client_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	. "zotregistry.dev/zot/pkg/cli/client"
	gql_gen "zotregistry.dev/zot/pkg/extensions/search/gql_generated"
)

func TestSortFlagsMapping(t *testing.T) {
	// We do this to not import the whole gql_gen in the CLI
	Convey("Make sure the sort-by values map correctly to the gql enum type", t, func() {
		So(Flag2SortCriteria(SortByRelevance), ShouldResemble, string(gql_gen.SortCriteriaRelevance))
		So(Flag2SortCriteria(SortByUpdateTime), ShouldResemble, string(gql_gen.SortCriteriaUpdateTime))
		So(Flag2SortCriteria(SortByAlphabeticAsc), ShouldResemble, string(gql_gen.SortCriteriaAlphabeticAsc))
		So(Flag2SortCriteria(SortByAlphabeticDsc), ShouldResemble, string(gql_gen.SortCriteriaAlphabeticDsc))
		So(Flag2SortCriteria(SortBySeverity), ShouldResemble, string(gql_gen.SortCriteriaSeverity))
	})
}

func TestSortFlags(t *testing.T) {
	Convey("Flags", t, func() {
		cveSortFlag := CVEListSortFlag("")
		err := cveSortFlag.Set("bad-flag")
		So(err, ShouldNotBeNil)

		imageListSortFlag := ImageListSortFlag("")
		err = imageListSortFlag.Set("bad-flag")
		So(err, ShouldNotBeNil)

		imageSearchSortFlag := ImageSearchSortFlag("")
		err = imageSearchSortFlag.Set("bad-flag")
		So(err, ShouldNotBeNil)

		repoListSearchFlag := RepoListSortFlag("")
		err = repoListSearchFlag.Set("bad-flag")
		So(err, ShouldNotBeNil)
	})

	Convey("Flag2SortCriteria", t, func() {
		So(Flag2SortCriteria("bad-flag"), ShouldResemble, "BAD_SORT_CRITERIA")
	})
}
