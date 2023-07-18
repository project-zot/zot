package common_test

import (
	"errors"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/meta/common"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("test error")

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
			manifestFilterData := mTypes.FilterData{
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
			manifestFilterData := mTypes.FilterData{
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
			manifestFilterData := mTypes.FilterData{
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
			manifestFilterData := mTypes.FilterData{
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

	Convey("SignatureAlreadyExists", t, func() {
		res := common.SignatureAlreadyExists(
			[]mTypes.SignatureInfo{{SignatureManifestDigest: "digest"}},
			mTypes.SignatureMetadata{SignatureDigest: "digest"},
		)

		So(res, ShouldEqual, true)

		res = common.SignatureAlreadyExists(
			[]mTypes.SignatureInfo{{SignatureManifestDigest: "digest"}},
			mTypes.SignatureMetadata{SignatureDigest: "digest2"},
		)

		So(res, ShouldEqual, false)
	})

	Convey("FilterDataByRepo", t, func() {
		Convey("Errors", func() {
			// Unmarshal index data error
			_, _, err := common.FilterDataByRepo(
				[]mTypes.RepoMetadata{{
					Tags: map[string]mTypes.Descriptor{
						"tag": {
							Digest:    "indexDigest",
							MediaType: ispec.MediaTypeImageIndex,
						},
					},
				}},
				map[string]mTypes.ManifestMetadata{},
				map[string]mTypes.IndexData{
					"indexDigest": {
						IndexBlob: []byte("bad blob"),
					},
				},
			)

			So(err, ShouldNotBeNil)
		})
	})

	Convey("FetchDataForRepos", t, func() {
		Convey("Errors", func() {
			// Unmarshal index data error
			_, _, err := common.FetchDataForRepos(
				mocks.MetaDBMock{
					GetIndexDataFn: func(indexDigest digest.Digest) (mTypes.IndexData, error) {
						return mTypes.IndexData{
							IndexBlob: []byte("bad blob"),
						}, nil
					},
				},
				[]mTypes.RepoMetadata{{
					Tags: map[string]mTypes.Descriptor{
						"tag": {
							Digest:    "indexDigest",
							MediaType: ispec.MediaTypeImageIndex,
						},
					},
				}},
			)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestFetchDataForRepos(t *testing.T) {
	Convey("GetReferredSubject", t, func() {
		mockMetaDB := mocks.MetaDBMock{}

		Convey("GetManifestData errors", func() {
			mockMetaDB.GetManifestDataFn = func(manifestDigest digest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{}, ErrTestError
			}

			_, _, err := common.FetchDataForRepos(mockMetaDB, []mTypes.RepoMetadata{
				{
					Tags: map[string]mTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("GetIndexData errors", func() {
			mockMetaDB.GetIndexDataFn = func(indexDigest digest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{}, ErrTestError
			}

			_, _, err := common.FetchDataForRepos(mockMetaDB, []mTypes.RepoMetadata{
				{
					Tags: map[string]mTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageIndex},
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("GetIndexData ok, GetManifestData errors", func() {
			mockMetaDB.GetIndexDataFn = func(indexDigest digest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{
					IndexBlob: []byte(`{
						"manifests": [
							{"digest": "dig1"}
						]
					}`),
				}, nil
			}
			mockMetaDB.GetManifestDataFn = func(manifestDigest digest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{}, ErrTestError
			}

			_, _, err := common.FetchDataForRepos(mockMetaDB, []mTypes.RepoMetadata{
				{
					Tags: map[string]mTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageIndex},
					},
				},
			})
			So(err, ShouldNotBeNil)
		})
	})
}
