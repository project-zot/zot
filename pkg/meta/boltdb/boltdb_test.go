package boltdb_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

type imgTrustStore struct{}

func (its imgTrustStore) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta,
	repo string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	return "", time.Time{}, false, nil
}

var errImageMetaBucketNotFound = errors.New("ImageMeta bucket not found")

func TestWrapperErrors(t *testing.T) {
	image := CreateDefaultImage()
	imageMeta := image.AsImageMeta()
	multiarchImageMeta := CreateMultiarchWith().Images([]Image{image}).Build().AsImageMeta()

	badProtoBlob := []byte("bad-repo-meta")

	goodRepoMetaBlob, err := proto.Marshal(&proto_go.RepoMeta{Name: "repo"})
	if err != nil {
		t.FailNow()
	}

	Convey("Errors", t, func() {
		tmpDir := t.TempDir()
		boltDBParams := boltdb.DBParameters{RootDir: tmpDir}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewTestLogger()

		boltdbWrapper, err := boltdb.New(boltDriver, log)
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		boltdbWrapper.SetImageTrustStore(imgTrustStore{})

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("test")

		ctx := userAc.DeriveContext(context.Background())

		Convey("RemoveRepoReference", func() {
			Convey("getProtoRepoMeta errors", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})

			Convey("getProtoImageMeta errors", func() {
				err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    imageMeta.Digest.String(),
						},
					},
				})
				So(err, ShouldBeNil)

				err = setImageMeta(imageMeta.Digest, badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoBlobs errors", func() {
				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = setRepoBlobInfo("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("UpdateSignaturesValidity", func() {
			boltdbWrapper.SetImageTrustStore(imgTrustStore{})

			digest := image.Digest()

			ctx := context.Background()

			Convey("image meta blob not found", func() {
				err := boltdbWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldBeNil)
			})

			Convey("image meta unmarshal fail", func() {
				err := setImageMeta(digest, badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta blob not found", func() {
				err := boltdbWrapper.SetImageMeta(digest, imageMeta)
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta unmarshal fail", func() {
				err := boltdbWrapper.SetImageMeta(digest, imageMeta)
				So(err, ShouldBeNil)

				err = setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetRepoLastUpdated", func() {
			Convey("bad blob in db", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBlobsBuck := tx.Bucket([]byte(boltdb.RepoBlobsBuck))
					lastUpdatedBuck := repoBlobsBuck.Bucket([]byte(boltdb.RepoLastUpdatedBuck))

					return lastUpdatedBuck.Put([]byte("repo"), []byte("bad-blob"))
				})
				So(err, ShouldBeNil)

				lastUpdated := boltdbWrapper.GetRepoLastUpdated("repo")
				So(lastUpdated, ShouldEqual, time.Time{})
			})
		})

		Convey("UpdateStatsOnDownload", func() {
			Convey("repo meta not found", func() {
				err = boltdbWrapper.UpdateStatsOnDownload("repo", "ref")
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateStatsOnDownload("repo", "ref")
				So(err, ShouldNotBeNil)
			})

			Convey("ref is tag and tag is not found", func() {
				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateStatsOnDownload("repo", "not-found-tag")
				So(err, ShouldNotBeNil)
			})

			Convey("digest not found in statistics", func() {
				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateStatsOnDownload("repo", godigest.FromString("not-found").String())
				So(err, ShouldNotBeNil)
			})

			Convey("statistics entry missing but digest exists in tags - should create and increment", func() {
				// Set repo reference to create tag
				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				// Manually remove Statistics entry to simulate missing Statistics
				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoMetaBuck := tx.Bucket([]byte(boltdb.RepoMetaBuck))
					repoMetaBlob := repoMetaBuck.Get([]byte("repo"))

					if len(repoMetaBlob) == 0 {
						return zerr.ErrRepoMetaNotFound
					}

					var protoRepoMeta proto_go.RepoMeta

					err := proto.Unmarshal(repoMetaBlob, &protoRepoMeta)
					if err != nil {
						return err
					}

					// Remove Statistics entry for the digest
					delete(protoRepoMeta.Statistics, imageMeta.Digest.String())

					repoMetaBlob, err = proto.Marshal(&protoRepoMeta)
					if err != nil {
						return err
					}

					return repoMetaBuck.Put([]byte("repo"), repoMetaBlob)
				})
				So(err, ShouldBeNil)

				// Verify Statistics entry doesn't exist
				repoMeta, err := boltdbWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				_, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeFalse)

				// Update stats - should create Statistics entry and increment
				err = boltdbWrapper.UpdateStatsOnDownload("repo", "tag")
				So(err, ShouldBeNil)

				// Verify Statistics entry was created and incremented
				repoMeta, err = boltdbWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 1)

				// Update stats again - should increment existing entry
				err = boltdbWrapper.UpdateStatsOnDownload("repo", "tag")
				So(err, ShouldBeNil)

				repoMeta, err = boltdbWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists = repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 2)
			})

			Convey("statistics entry missing but digest exists in tags - using digest reference", func() {
				// Set repo reference to create tag
				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				// Manually remove Statistics entry
				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoMetaBuck := tx.Bucket([]byte(boltdb.RepoMetaBuck))
					repoMetaBlob := repoMetaBuck.Get([]byte("repo"))

					if len(repoMetaBlob) == 0 {
						return zerr.ErrRepoMetaNotFound
					}

					var protoRepoMeta proto_go.RepoMeta

					err := proto.Unmarshal(repoMetaBlob, &protoRepoMeta)
					if err != nil {
						return err
					}

					delete(protoRepoMeta.Statistics, imageMeta.Digest.String())

					repoMetaBlob, err = proto.Marshal(&protoRepoMeta)
					if err != nil {
						return err
					}

					return repoMetaBuck.Put([]byte("repo"), repoMetaBlob)
				})
				So(err, ShouldBeNil)

				// Update stats using digest directly
				err = boltdbWrapper.UpdateStatsOnDownload("repo", imageMeta.Digest.String())
				So(err, ShouldBeNil)

				// Verify Statistics entry was created
				repoMeta, err := boltdbWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 1)
			})
		})

		Convey("GetReferrersInfo", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.GetReferrersInfo("repo", "refDig", []string{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("ResetRepoReferences", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.ResetRepoReferences("repo", nil)
				So(err, ShouldNotBeNil)
			})

			Convey("preserve tags in tagsToKeep", func() {
				ctx := context.Background()

				// Create repo with multiple tags
				image1 := CreateRandomImage()
				image2 := CreateRandomImage()

				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag1", image1.AsImageMeta())
				So(err, ShouldBeNil)

				// Wait a bit to ensure different timestamps
				time.Sleep(10 * time.Millisecond)

				err = boltdbWrapper.SetRepoReference(ctx, "repo", "tag2", image2.AsImageMeta())
				So(err, ShouldBeNil)

				// Get repo meta to capture TaggedTimestamp
				repoMeta, err := boltdbWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldContainKey, "tag2")

				tag1Timestamp := repoMeta.Tags["tag1"].TaggedTimestamp

				// Reset with only tag1 in tagsToKeep
				tagsToKeep := map[string]bool{"tag1": true}
				err = boltdbWrapper.ResetRepoReferences("repo", tagsToKeep)
				So(err, ShouldBeNil)

				// Verify tag1 is preserved with its timestamp
				repoMeta, err = boltdbWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldNotContainKey, "tag2")
				So(repoMeta.Tags["tag1"].TaggedTimestamp, ShouldEqual, tag1Timestamp)
			})
		})

		Convey("DecrementRepoStars", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.DecrementRepoStars("repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("IncrementRepoStars", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.IncrementRepoStars("repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("DeleteSignature", func() {
			Convey("repo meta not found", func() {
				err = boltdbWrapper.DeleteSignature("repo", godigest.FromString("dig"), mTypes.SignatureMetadata{})
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.DeleteSignature("repo", godigest.FromString("dig"), mTypes.SignatureMetadata{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("AddManifestSignature", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.AddManifestSignature("repo", godigest.FromString("dig"), mTypes.SignatureMetadata{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetMultipleRepoMeta", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetFullImageMeta", func() {
			Convey("repo meta not found", func() {
				_, err := boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("tag not found", func() {
				err := setRepoMeta("repo", goodRepoMetaBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag-not-found")
				So(err, ShouldNotBeNil)
			})

			Convey("getProtoImageMeta fails", func() {
				err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromString("not-found").String(),
						},
					},
				})
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("image is index, missing manifests are skipped gracefully", func() {
				err := boltdbWrapper.SetRepoReference(ctx, "repo", "tag", multiarchImageMeta)
				So(err, ShouldBeNil)

				// Missing manifests are skipped gracefully, so GetFullImageMeta succeeds
				// but returns an index with no manifests
				fullImageMeta, err := boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldBeNil)
				So(len(fullImageMeta.Manifests), ShouldEqual, 0)
			})

			Convey("image is index, corrupted manifest data returns error", func() {
				// Create a multiarch image with multiple manifests
				multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
				multiarchImageMeta := multiarchImage.AsImageMeta()
				err := boltdbWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				// Store the first manifest normally
				firstManifest := multiarchImage.Images[0]
				firstManifestMeta := firstManifest.AsImageMeta()
				err = boltdbWrapper.SetImageMeta(firstManifestMeta.Digest, firstManifestMeta)
				So(err, ShouldBeNil)

				// Store the second manifest normally first, then corrupt it
				secondManifest := multiarchImage.Images[1]
				secondManifestMeta := secondManifest.AsImageMeta()
				err = boltdbWrapper.SetImageMeta(secondManifestMeta.Digest, secondManifestMeta)
				So(err, ShouldBeNil)

				secondManifestDigest := secondManifest.ManifestDescriptor.Digest

				// Corrupt the data for the second manifest by storing invalid protobuf data
				// This will cause getProtoImageMeta to return an unmarshaling error
				// which is not ErrImageMetaNotFound, so it will propagate through getAllContainedMeta
				corruptedData := []byte("invalid protobuf data")

				// Access BoltDB directly to corrupt the data
				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					imageBuck := tx.Bucket([]byte(boltdb.ImageMetaBuck))
					if imageBuck == nil {
						return errImageMetaBucketNotFound
					}
					// Store corrupted protobuf data
					return imageBuck.Put([]byte(secondManifestDigest.String()), corruptedData)
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetRepoReference(ctx, "repo", "tag", multiarchImageMeta)
				So(err, ShouldBeNil)

				// GetFullImageMeta should return an error due to corrupted manifest data
				// The error from getAllContainedMeta should propagate
				fullImageMeta, err := boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
				// Should still return a FullImageMeta object (even with error)
				So(fullImageMeta, ShouldNotBeNil)
			})
		})

		Convey("FilterRepos", func() {
			err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.FilterRepos(ctx, mTypes.AcceptAllRepoNames, mTypes.AcceptAllRepoMeta)
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags", func() {
			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = boltdbWrapper.SearchTags(ctx, "repo:")
				So(err, ShouldNotBeNil)
			})

			Convey("found repo meta", func() {
				Convey("bad image manifest", func() {
					badImageDigest := godigest.FromString("bad-image-manifest")
					err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-manifest": {
								MediaType: ispec.MediaTypeImageManifest,
								Digest:    badImageDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badImageDigest, badProtoBlob, boltdbWrapper.DB)
					So(err, ShouldBeNil)

					_, err = boltdbWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("bad image index", func() {
					badIndexDigest := godigest.FromString("bad-image-manifest")
					err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-index": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    badIndexDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badIndexDigest, badProtoBlob, boltdbWrapper.DB)
					So(err, ShouldBeNil)

					_, err = boltdbWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("good image index, bad inside manifest", func() {
					goodIndexBadManifestDigest := godigest.FromString("good-index-bad-manifests")
					err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"good-index-bad-manifests": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    goodIndexBadManifestDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = boltdbWrapper.SetImageMeta(goodIndexBadManifestDigest, multiarchImageMeta)
					So(err, ShouldBeNil)

					err = setImageMeta(image.Digest(), badProtoBlob, boltdbWrapper.DB)
					So(err, ShouldBeNil)

					_, err = boltdbWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("bad media type", func() {
					err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"mad-media-type": {
								MediaType: "bad media type",
								Digest:    godigest.FromString("dig").String(),
							},
						},
					})
					So(err, ShouldBeNil)

					_, err = boltdbWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldBeNil)
				})
			})
		})

		Convey("FilterTags", func() {
			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldNotBeNil)
			})

			Convey("bad media Type fails", func() {
				err := boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"bad-repo-meta": {
							MediaType: "bad media type",
							Digest:    godigest.FromString("dig").String(),
						},
					},
				})
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldBeNil)
			})

			Convey("getAllContainedMeta error for index is joined and processing continues", func() {
				// Create a multiarch image with multiple manifests
				multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
				multiarchImageMeta := multiarchImage.AsImageMeta()
				err := boltdbWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				// Store the first manifest normally
				firstManifest := multiarchImage.Images[0]
				firstManifestMeta := firstManifest.AsImageMeta()
				err = boltdbWrapper.SetImageMeta(firstManifestMeta.Digest, firstManifestMeta)
				So(err, ShouldBeNil)

				// Store the second manifest normally first, then corrupt it
				secondManifest := multiarchImage.Images[1]
				secondManifestMeta := secondManifest.AsImageMeta()
				err = boltdbWrapper.SetImageMeta(secondManifestMeta.Digest, secondManifestMeta)
				So(err, ShouldBeNil)

				secondManifestDigest := secondManifest.ManifestDescriptor.Digest

				// Corrupt the data for the second manifest by storing invalid protobuf data
				// This will cause getProtoImageMeta to return an unmarshaling error
				// which is not ErrImageMetaNotFound, so it will propagate through getAllContainedMeta
				corruptedData := []byte("invalid protobuf data")

				// Access BoltDB directly to corrupt the data
				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					imageBuck := tx.Bucket([]byte(boltdb.ImageMetaBuck))
					if imageBuck == nil {
						return errImageMetaBucketNotFound
					}
					// Store corrupted protobuf data
					return imageBuck.Put([]byte(secondManifestDigest.String()), corruptedData)
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetRepoReference(ctx, "repo", "tag", multiarchImageMeta)
				So(err, ShouldBeNil)

				// FilterTags should return an error due to corrupted manifest data
				// The error from getAllContainedMeta should be joined with viewError
				images, err := boltdbWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldNotBeNil)
				// Should still return some images (the first valid manifest might be processed)
				So(images, ShouldNotBeNil)
			})
		})

		Convey("SearchRepos", func() {
			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = boltdbWrapper.SearchRepos(ctx, "repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("FilterImageMeta", func() {
			Convey("MediaType ImageIndex, getProtoImageMeta fails", func() {
				err := boltdbWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				err = setImageMeta(image.Digest(), badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = boltdbWrapper.FilterImageMeta(ctx, []string{multiarchImageMeta.Digest.String()})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetImageMeta", func() {
			Convey("image is index, getAllContainedMeta error returns error", func() {
				// Create a multiarch image with multiple manifests
				multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
				multiarchImageMeta := multiarchImage.AsImageMeta()
				err := boltdbWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				// Store the first manifest normally
				firstManifest := multiarchImage.Images[0]
				firstManifestMeta := firstManifest.AsImageMeta()
				err = boltdbWrapper.SetImageMeta(firstManifestMeta.Digest, firstManifestMeta)
				So(err, ShouldBeNil)

				// Store the second manifest normally first, then corrupt it
				secondManifest := multiarchImage.Images[1]
				secondManifestMeta := secondManifest.AsImageMeta()
				err = boltdbWrapper.SetImageMeta(secondManifestMeta.Digest, secondManifestMeta)
				So(err, ShouldBeNil)

				secondManifestDigest := secondManifest.ManifestDescriptor.Digest

				// Corrupt the data for the second manifest by storing invalid protobuf data
				// This will cause getProtoImageMeta to return an unmarshaling error
				// which is not ErrImageMetaNotFound, so it will propagate through getAllContainedMeta
				corruptedData := []byte("invalid protobuf data")

				// Access BoltDB directly to corrupt the data
				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					imageBuck := tx.Bucket([]byte(boltdb.ImageMetaBuck))
					if imageBuck == nil {
						return errImageMetaBucketNotFound
					}
					// Store corrupted protobuf data
					return imageBuck.Put([]byte(secondManifestDigest.String()), corruptedData)
				})
				So(err, ShouldBeNil)

				// GetImageMeta should return an error due to corrupted manifest data
				// The error from getAllContainedMeta should propagate
				imageMeta, err := boltdbWrapper.GetImageMeta(multiarchImageMeta.Digest)
				So(err, ShouldNotBeNil)
				// Should still return an ImageMeta object (even with error)
				So(imageMeta, ShouldNotBeNil)
			})
		})

		Convey("SetRepoReference", func() {
			Convey("getProtoRepoMeta errors", func() {
				err := setRepoMeta("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoBlobs errors", func() {
				err := setRepoMeta("repo", goodRepoMetaBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = setRepoBlobInfo("repo", badProtoBlob, boltdbWrapper.DB)
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("AddUserAPIKey", func() {
			Convey("no userid found", func() {
				userAc := reqCtx.NewUserAccessControl()
				ctx := userAc.DeriveContext(context.Background())

				err = boltdbWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
				So(err, ShouldNotBeNil)
			})

			err = boltdbWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserDataBucket))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddUserAPIKey(ctx, "test", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserAPIKeysBucket))
			})

			So(err, ShouldBeNil)

			err = boltdbWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldEqual, zerr.ErrBucketDoesNotExist)
		})

		Convey("UpdateUserAPIKey", func() {
			err = boltdbWrapper.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = boltdbWrapper.UpdateUserAPIKeyLastUsed(ctx, "") //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey", func() {
			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddUserAPIKey(ctx, "hashedKey", &mTypes.APIKeyDetails{})
			So(err, ShouldBeNil)

			Convey("no such bucket", func() {
				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					return tx.DeleteBucket([]byte(boltdb.UserAPIKeysBucket))
				})
				So(err, ShouldBeNil)

				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				err = boltdbWrapper.DeleteUserAPIKey(ctx, "")
				So(err, ShouldEqual, zerr.ErrBucketDoesNotExist)
			})

			Convey("userdata not found", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				err := boltdbWrapper.DeleteUserData(ctx)
				So(err, ShouldBeNil)

				err = boltdbWrapper.DeleteUserAPIKey(ctx, "")
				So(err, ShouldNotBeNil)
			})

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = boltdbWrapper.DeleteUserAPIKey(ctx, "test") //nolint: contextcheck
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserDataBucket))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserAPIKey(ctx, "") //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo", func() {
			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserAPIKeysBucket))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetUserAPIKeyInfo("")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData", func() {
			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				buck := tx.Bucket([]byte(boltdb.UserDataBucket))
				So(buck, ShouldNotBeNil)

				return buck.Put([]byte("test"), []byte("dsa8"))
			})

			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserAPIKeysBucket))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData", func() {
			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)

			buff := make([]byte, int(math.Ceil(float64(1000000)/float64(1.33333333333))))
			_, err := rand.Read(buff)
			So(err, ShouldBeNil)

			longString := base64.RawURLEncoding.EncodeToString(buff)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername(longString)
			ctx = userAc.DeriveContext(context.Background())

			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserDataBucket))
			})
			So(err, ShouldBeNil)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("test")
			ctx = userAc.DeriveContext(context.Background())

			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData", func() {
			userAc = reqCtx.NewUserAccessControl()
			ctx = userAc.DeriveContext(context.Background()) //nolint:fatcontext // test code

			err = boltdbWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserDataBucket))
			})
			So(err, ShouldBeNil)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("test")
			ctx = userAc.DeriveContext(context.Background())

			err = boltdbWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserGroups and SetUserGroups", func() {
			userAc = reqCtx.NewUserAccessControl()
			ctx = userAc.DeriveContext(context.Background()) //nolint:fatcontext // test code

			_, err := boltdbWrapper.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, no repoMeta found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetaBuck))

				err := repoBuck.Put([]byte("repo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, bad repoMeta found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := boltdbWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := boltdbWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := boltdbWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserGroups bad context errors", func() {
			_, err := boltdbWrapper.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)

			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err = boltdbWrapper.GetUserGroups(ctx) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserGroups bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := boltdbWrapper.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := boltdbWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := boltdbWrapper.DeleteUserAPIKey(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := boltdbWrapper.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := boltdbWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetStarredRepos bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := boltdbWrapper.GetStarredRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetBookmarkedRepos bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := boltdbWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta unmarshal error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetaBuck))

				err := repoBuck.Put([]byte("repo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err := boltdbWrapper.GetRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})
	})
}

func setRepoMeta(repo string, blob []byte, db *bbolt.DB) error { //nolint: unparam
	err := db.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(boltdb.RepoMetaBuck))

		return buck.Put([]byte(repo), blob)
	})

	return err
}

func setImageMeta(digest godigest.Digest, blob []byte, db *bbolt.DB) error {
	err := db.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(boltdb.ImageMetaBuck))

		return buck.Put([]byte(digest.String()), blob)
	})

	return err
}

func setRepoBlobInfo(repo string, blob []byte, db *bbolt.DB) error {
	err := db.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(boltdb.RepoBlobsBuck))

		return buck.Put([]byte(repo), blob)
	})

	return err
}
