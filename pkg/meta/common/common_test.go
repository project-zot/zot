package common_test

import (
	"errors"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/protobuf/types/known/timestamppb"

	"zotregistry.dev/zot/v2/pkg/meta/common"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

var ErrTestError = errors.New("test error")

func TestUtils(t *testing.T) {
	Convey("GetPartialImageMeta", t, func() {
		So(func() { common.GetPartialImageMeta(mTypes.ImageMeta{}, mTypes.ImageMeta{}) }, ShouldNotPanic)
	})

	Convey("MatchesArtifactTypes", t, func() {
		res := common.MatchesArtifactTypes("", nil)
		So(res, ShouldBeTrue)

		res = common.MatchesArtifactTypes("type", []string{"someOtherType"})
		So(res, ShouldBeFalse)
	})

	Convey("GetProtoPlatform", t, func() {
		platform := common.GetProtoPlatform(nil)
		So(platform, ShouldBeNil)
	})

	Convey("ValidateRepoReferenceInput", t, func() {
		err := common.ValidateRepoReferenceInput("", "tag", "digest")
		So(err, ShouldNotBeNil)
		err = common.ValidateRepoReferenceInput("repo", "", "digest")
		So(err, ShouldNotBeNil)
		err = common.ValidateRepoReferenceInput("repo", "tag", "")
		So(err, ShouldNotBeNil)
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

	Convey("RemoveImageFromRepoMeta", t, func() {
		Convey("should handle nil blob info for descriptor digest", func() {
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag1": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:missing",
					},
				},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{
					// Intentionally missing "sha256:missing" to trigger nil check
				},
			}

			// Should not panic when blob info is nil
			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)
			So(resultMeta.LastUpdatedImage, ShouldBeNil)
		})

		Convey("should handle nil blob info in queue traversal", func() {
			now := time.Now()
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag1": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:manifest1",
					},
				},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{
					"sha256:manifest1": {
						Size:        1000,
						LastUpdated: timestamppb.New(now),
						SubBlobs:    []string{"sha256:layer1", "sha256:missing-layer"},
					},
					"sha256:layer1": {
						Size: 500,
					},
					// Intentionally missing "sha256:missing-layer" to trigger nil check in queue traversal
				},
			}

			// Should not panic when a sub-blob is nil
			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)
			// Should only include non-nil blobs
			So(len(resultBlobs.Blobs), ShouldEqual, 2)
			So(resultBlobs.Blobs["sha256:manifest1"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer1"], ShouldNotBeNil)
		})

		Convey("should work correctly with valid blob info", func() {
			now := time.Now()
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag1": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:manifest1",
					},
					"tag2": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:manifest2",
					},
				},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{
					"sha256:manifest1": {
						Size:        1000,
						LastUpdated: timestamppb.New(now),
						SubBlobs:    []string{"sha256:layer1"},
						Vendors:     []string{"vendor1"},
						Platforms:   []*proto_go.Platform{{OS: "linux", Architecture: "amd64"}},
					},
					"sha256:layer1": {
						Size: 500,
					},
					"sha256:manifest2": {
						Size:        2000,
						LastUpdated: timestamppb.New(now.Add(time.Hour)),
						SubBlobs:    []string{"sha256:layer2"},
					},
					"sha256:layer2": {
						Size: 800,
					},
				},
			}

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Should include all blobs from all tags
			So(len(resultBlobs.Blobs), ShouldEqual, 4)
			So(resultBlobs.Blobs["sha256:manifest1"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:manifest2"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer1"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer2"], ShouldNotBeNil)

			// Should calculate total size correctly
			expectedSize := int64(1000 + 500 + 2000 + 800)
			So(resultMeta.Size, ShouldEqual, expectedSize)

			// Should have updated last image
			So(resultMeta.LastUpdatedImage, ShouldNotBeNil)
		})

		Convey("should handle empty tags", func() {
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{},
			}

			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)
			So(resultMeta.Size, ShouldEqual, 0)
			So(len(resultBlobs.Blobs), ShouldEqual, 0)
		})

		Convey("should skip tags with empty digest", func() {
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag1": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "", // Empty digest
					},
				},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{},
			}

			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)
			So(resultMeta.Size, ShouldEqual, 0)
		})
	})
}
