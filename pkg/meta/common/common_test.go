package common_test

import (
	"errors"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
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
		Convey("should handle nil blob info for descriptor digest and continue with other tags", func() {
			now := time.Now()
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag1": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:manifest1",
					},
					"tag-missing": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:missing",
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
					},
					"sha256:layer1": {
						Size: 500,
					},
					// Intentionally missing "sha256:missing" for tag-missing to test nil check
					// The function should skip tag-missing and continue processing tag2
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

			// Remove tag1 (simulating actual usage pattern)
			delete(repoMeta.Tags, "tag1")

			// Should not panic when tag-missing has nil blob info
			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// tag-missing remains in metadata but has no blobs (inconsistent state, acceptable in GC scenarios)
			So(resultMeta.Tags["tag-missing"], ShouldNotBeNil)

			// Should include blobs from tag2 (which has valid blob info)
			So(len(resultBlobs.Blobs), ShouldEqual, 2)
			So(resultBlobs.Blobs["sha256:manifest2"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer2"], ShouldNotBeNil)

			// Should have correct size from tag2 only
			expectedSize := int64(2000 + 800)
			So(resultMeta.Size, ShouldEqual, expectedSize)

			// Should have updated last image from tag2
			So(resultMeta.LastUpdatedImage, ShouldNotBeNil)
			So(resultMeta.LastUpdatedImage.Digest, ShouldEqual, "sha256:manifest2")
		})

		Convey("should handle nil blob info in queue traversal and continue processing", func() {
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
						// Mix of valid and missing sub-blobs to test that processing continues
						SubBlobs: []string{"sha256:layer1", "sha256:missing-layer", "sha256:layer2"},
					},
					"sha256:layer1": {
						Size: 500,
					},
					// Intentionally missing "sha256:missing-layer" to trigger nil check in queue traversal
					// The function should skip it and continue processing layer2
					"sha256:layer2": {
						Size:     300,
						SubBlobs: []string{"sha256:layer3"},
					},
					"sha256:layer3": {
						Size: 200,
					},
				},
			}

			// Remove the tag before calling RemoveImageFromRepoMeta (as done in actual usage)
			delete(repoMeta.Tags, "tag1")

			// Should not panic when a sub-blob is nil
			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Verify tag1 was removed
			So(resultMeta.Tags["tag1"], ShouldBeNil)

			// After removing tag1, no blobs should remain
			So(len(resultBlobs.Blobs), ShouldEqual, 0)
		})

		Convey("should handle multiple nil blobs in deeply nested structure", func() {
			now := time.Now()
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag-valid": {
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
						// Multiple missing sub-blobs interspersed with valid ones
						SubBlobs: []string{
							"sha256:missing1",
							"sha256:layer1",
							"sha256:missing2",
							"sha256:layer2",
							"sha256:missing3",
						},
					},
					"sha256:layer1": {
						Size:     500,
						SubBlobs: []string{"sha256:missing4", "sha256:nested-layer"},
					},
					"sha256:layer2": {
						Size: 300,
					},
					"sha256:nested-layer": {
						Size: 100,
					},
					// Intentionally missing: missing1, missing2, missing3, missing4
				},
			}

			// Should not panic with multiple missing blobs at various levels
			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "nonexistent")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "nonexistent")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Should only include the valid blobs that were successfully traversed
			So(len(resultBlobs.Blobs), ShouldEqual, 4) // manifest1, layer1, layer2, nested-layer
			So(resultBlobs.Blobs["sha256:manifest1"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer1"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer2"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:nested-layer"], ShouldNotBeNil)

			// Verify correct size calculation (only valid blobs)
			expectedSize := int64(1000 + 500 + 300 + 100)
			So(resultMeta.Size, ShouldEqual, expectedSize)
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

			// Remove the tag before calling RemoveImageFromRepoMeta (as done in actual usage)
			delete(repoMeta.Tags, "tag1")

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag1")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Verify tag1 was removed
			So(resultMeta.Tags["tag1"], ShouldBeNil)

			// Should only include blobs from remaining tag2 (manifest2 and layer2)
			So(len(resultBlobs.Blobs), ShouldEqual, 2)
			So(resultBlobs.Blobs["sha256:manifest2"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer2"], ShouldNotBeNil)

			// Should calculate total size correctly (only tag2 blobs)
			expectedSize := int64(2000 + 800)
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

		Convey("should skip tags with empty digest and continue processing", func() {
			now := time.Now()
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag-empty": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "", // Empty digest - should be skipped
					},
					"tag-valid": {
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
						SubBlobs:    []string{"sha256:layer1"},
					},
					"sha256:layer1": {
						Size: 500,
					},
				},
			}

			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag-empty")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "tag-empty")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Should skip tag-empty and process tag-valid
			So(len(resultBlobs.Blobs), ShouldEqual, 2)
			So(resultBlobs.Blobs["sha256:manifest1"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:layer1"], ShouldNotBeNil)

			expectedSize := int64(1000 + 500)
			So(resultMeta.Size, ShouldEqual, expectedSize)
		})

		Convey("should handle combined edge cases - empty digest, nil descriptor blob, and nil queue blob", func() {
			now := time.Now()
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{
					"tag-empty": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "", // Empty digest
					},
					"tag-nil-descriptor": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:missing-descriptor",
					},
					"tag-nil-in-queue": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:manifest-with-missing-blobs",
					},
					"tag-valid": {
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Digest:    "sha256:valid-manifest",
					},
				},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{
					// Missing "sha256:missing-descriptor" to trigger descriptor nil check
					"sha256:manifest-with-missing-blobs": {
						Size:        1000,
						LastUpdated: timestamppb.New(now),
						SubBlobs:    []string{"sha256:missing-in-queue", "sha256:valid-layer1"},
					},
					// Missing "sha256:missing-in-queue" to trigger queue nil check
					"sha256:valid-layer1": {
						Size: 300,
					},
					"sha256:valid-manifest": {
						Size:        2000,
						LastUpdated: timestamppb.New(now.Add(2 * time.Hour)),
						SubBlobs:    []string{"sha256:valid-layer2"},
					},
					"sha256:valid-layer2": {
						Size: 800,
					},
				},
			}

			// Should not panic with multiple types of issues
			So(func() {
				common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "nonexistent")
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.RemoveImageFromRepoMeta(repoMeta, repoBlobs, "nonexistent")
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Should include only valid blobs:
			// - tag-valid's blobs (valid-manifest + valid-layer2)
			// - tag-nil-in-queue's valid blobs (manifest-with-missing-blobs + valid-layer1)
			So(len(resultBlobs.Blobs), ShouldEqual, 4)
			So(resultBlobs.Blobs["sha256:valid-manifest"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:valid-layer2"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:manifest-with-missing-blobs"], ShouldNotBeNil)
			So(resultBlobs.Blobs["sha256:valid-layer1"], ShouldNotBeNil)

			// Verify correct size (all valid blobs)
			expectedSize := int64(2000 + 800 + 1000 + 300)
			So(resultMeta.Size, ShouldEqual, expectedSize)

			// Last updated should be from the most recent valid blob
			So(resultMeta.LastUpdatedImage, ShouldNotBeNil)
		})
	})

	Convey("AddImageMetaToRepoMeta", t, func() {
		Convey("should handle ImageManifest with empty Manifests slice", func() {
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{},
			}

			testDigest := godigest.FromString("sha256:testdigest")
			imageMeta := mTypes.ImageMeta{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    testDigest,
				Size:      1000,
				Manifests: []mTypes.ManifestMeta{}, // Empty Manifests slice
			}

			// Should not panic
			So(func() {
				common.AddImageMetaToRepoMeta(repoMeta, repoBlobs, "tag1", imageMeta)
			}, ShouldNotPanic)

			resultMeta, resultBlobs := common.AddImageMetaToRepoMeta(repoMeta, repoBlobs, "tag1", imageMeta)
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Should add basic blob info with just Size
			digestStr := testDigest.String()
			So(resultBlobs.Blobs[digestStr], ShouldNotBeNil)
			So(resultBlobs.Blobs[digestStr].Size, ShouldEqual, 1000)
			// Should not have SubBlobs, Vendors, Platforms, or LastUpdated since Manifests is empty
			So(resultBlobs.Blobs[digestStr].SubBlobs, ShouldBeNil)
			So(resultBlobs.Blobs[digestStr].Vendors, ShouldBeNil)
			So(resultBlobs.Blobs[digestStr].Platforms, ShouldBeNil)
			So(resultBlobs.Blobs[digestStr].LastUpdated, ShouldBeNil)
		})

		Convey("should handle ImageManifest with valid Manifests", func() {
			repoMeta := &proto_go.RepoMeta{
				Name: "test-repo",
				Tags: map[string]*proto_go.TagDescriptor{},
			}

			repoBlobs := &proto_go.RepoBlobs{
				Blobs: map[string]*proto_go.BlobInfo{},
			}

			testDigest := godigest.FromString("sha256:testdigest")
			configDigest := godigest.FromString("sha256:configdigest")
			layerDigest := godigest.FromString("sha256:layerdigest")

			imageMeta := mTypes.ImageMeta{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    testDigest,
				Size:      1000,
				Manifests: []mTypes.ManifestMeta{
					{
						Digest: testDigest,
						Size:   1000,
						Manifest: ispec.Manifest{
							Config: ispec.Descriptor{
								Digest: configDigest,
								Size:   500,
							},
							Layers: []ispec.Descriptor{
								{
									Digest: layerDigest,
									Size:   300,
								},
							},
						},
						Config: ispec.Image{},
					},
				},
			}

			resultMeta, resultBlobs := common.AddImageMetaToRepoMeta(repoMeta, repoBlobs, "tag1", imageMeta)
			So(resultMeta, ShouldNotBeNil)
			So(resultBlobs, ShouldNotBeNil)

			// Should add full blob info including SubBlobs
			digestStr := testDigest.String()
			So(resultBlobs.Blobs[digestStr], ShouldNotBeNil)
			So(resultBlobs.Blobs[digestStr].Size, ShouldEqual, 1000)
			So(len(resultBlobs.Blobs[digestStr].SubBlobs), ShouldEqual, 2) // config + layer
			So(resultBlobs.Blobs[configDigest.String()], ShouldNotBeNil)
			So(resultBlobs.Blobs[layerDigest.String()], ShouldNotBeNil)
		})
	})
}
