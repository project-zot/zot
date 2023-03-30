package common_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/meta/common"
	"zotregistry.io/zot/pkg/meta/repodb"
)

func TestUtils(t *testing.T) {
	Convey("GetReferredSubject", t, func() {
		_, err := common.GetReferredSubject([]byte("bad json"))
		So(err, ShouldNotBeNil)
	})

	Convey("MatchesArtifactTypes", t, func() {
		res := common.MatchesArtifactTypes("", nil)
		So(res, ShouldBeTrue)

		res = common.MatchesArtifactTypes("type", []string{"someOtherType"})
		So(res, ShouldBeFalse)
	})

	Convey("CheckImageLastUpdated", t, func() {
		Convey("No image checked, it doesn't have time", func() {
			repoLastUpdated := time.Time{}
			isSigned := false
			noImageChecked := true
			manifestFilterData := repodb.FilterData{
				DownloadCount: 10,
				LastUpdated:   time.Time{},
				IsSigned:      true,
			}

			repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned, noImageChecked,
				manifestFilterData)
			So(repoLastUpdated, ShouldResemble, manifestFilterData.LastUpdated)
			So(isSigned, ShouldEqual, manifestFilterData.IsSigned)
			So(noImageChecked, ShouldEqual, false)
		})

		Convey("First image checked, it has time", func() {
			repoLastUpdated := time.Time{}
			isSigned := false
			noImageChecked := true
			manifestFilterData := repodb.FilterData{
				DownloadCount: 10,
				LastUpdated:   time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC),
				IsSigned:      true,
			}

			repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned, noImageChecked,
				manifestFilterData)
			So(repoLastUpdated, ShouldResemble, manifestFilterData.LastUpdated)
			So(isSigned, ShouldEqual, manifestFilterData.IsSigned)
			So(noImageChecked, ShouldEqual, false)
		})

		Convey("Not first image checked, current image is newer", func() {
			repoLastUpdated := time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC)
			isSigned := true
			noImageChecked := false
			manifestFilterData := repodb.FilterData{
				DownloadCount: 10,
				LastUpdated:   time.Date(2023, 1, 1, 1, 1, 1, 1, time.UTC),
				IsSigned:      false,
			}

			repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned,
				noImageChecked, manifestFilterData)
			So(repoLastUpdated, ShouldResemble, manifestFilterData.LastUpdated)
			So(isSigned, ShouldEqual, manifestFilterData.IsSigned)
			So(noImageChecked, ShouldEqual, false)
		})

		Convey("Not first image checked, current image is older", func() {
			repoLastUpdated := time.Date(2024, 1, 1, 1, 1, 1, 1, time.UTC)
			isSigned := false
			noImageChecked := false
			manifestFilterData := repodb.FilterData{
				DownloadCount: 10,
				LastUpdated:   time.Date(2022, 1, 1, 1, 1, 1, 1, time.UTC),
				IsSigned:      true,
			}

			updatedRepoLastUpdated, noImageChecked, isSigned := common.CheckImageLastUpdated(repoLastUpdated, isSigned,
				noImageChecked,
				manifestFilterData)
			So(updatedRepoLastUpdated, ShouldResemble, repoLastUpdated)
			So(isSigned, ShouldEqual, false)
			So(noImageChecked, ShouldEqual, false)
		})
	})
}
