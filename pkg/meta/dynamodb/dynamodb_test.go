package dynamodb_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/imagetrust"
	"zotregistry.dev/zot/v2/pkg/log"
	mdynamodb "zotregistry.dev/zot/v2/pkg/meta/dynamodb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

const badTablename = "bad tablename"

func TestIterator(t *testing.T) {
	tskip.SkipDynamo(t)

	const region = "us-east-2"

	endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	imageMetaTablename := "ImageMeta" + uuid.String()
	repoBlobsTablename := "RepoBlobs" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()

	log := log.NewTestLogger()

	Convey("TestIterator", t, func() {
		params := mdynamodb.DBDriverParameters{
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			VersionTablename:       versionTablename,
			APIKeyTablename:        apiKeyTablename,
			UserDataTablename:      userDataTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := mdynamodb.New(client, params, log)
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetTable(dynamoWrapper.ImageMetaTablename), ShouldBeNil)
		So(dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename), ShouldBeNil)

		err = dynamoWrapper.SetRepoReference(context.Background(), "repo1", "tag1", CreateRandomImage().AsImageMeta())
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference(context.Background(), "repo2", "tag2", CreateRandomImage().AsImageMeta())
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference(context.Background(), "repo3", "tag3", CreateRandomImage().AsImageMeta())
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := mdynamodb.NewBaseDynamoAttributesIterator(
			dynamoWrapper.Client,
			dynamoWrapper.RepoMetaTablename,
			"RepoMeta",
			1,
			log,
		)

		attribute, err := repoMetaAttributeIterator.First(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldBeNil)
	})
}

func TestIteratorErrors(t *testing.T) {
	Convey("errors", t, func() {
		badEndpoint := "endpoint"
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("region"))
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := mdynamodb.NewBaseDynamoAttributesIterator(
			dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(badEndpoint)
			}),
			"RepoMetadataTable",
			"RepoMeta",
			1,
			log.NewTestLogger(),
		)

		_, err = repoMetaAttributeIterator.First(context.Background())
		So(err, ShouldNotBeNil)
	})
}

func TestWrapperErrors(t *testing.T) {
	tskip.SkipDynamo(t)

	const region = "us-east-2"

	endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	wrongTableName := "WRONG Tables"
	imageMetaTablename := "ImageMeta" + uuid.String()
	repoBlobsTablename := "RepoBlobs" + uuid.String()

	log := log.NewTestLogger()
	testDigest := godigest.FromString("str")
	image := CreateDefaultImage()
	multi := CreateMultiarchWith().Images([]Image{image}).Build()
	imageMeta := image.AsImageMeta()
	multiarchImageMeta := multi.AsImageMeta()

	badProtoBlob := []byte("bad-repo-meta")
	// goodRepoMetaBlob, err := proto.Marshal(&proto_go.RepoMeta{Name: "repo"})
	// if err != nil {
	// 	t.FailNow()
	// }

	//nolint: contextcheck
	Convey("Errors", t, func() {
		params := mdynamodb.DBDriverParameters{ //nolint:contextcheck,staticcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       versionTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params) //nolint:contextcheck
		So(err, ShouldBeNil)

		imgTrustStore, err := imagetrust.NewAWSImageTrustStore(params.Region, params.Endpoint)
		So(err, ShouldBeNil)

		dynamoWrapper, err := mdynamodb.New(client, params, log) //nolint:contextcheck
		So(err, ShouldBeNil)

		dynamoWrapper.SetImageTrustStore(imgTrustStore)

		So(dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename), ShouldBeNil)  //nolint:contextcheck
		So(dynamoWrapper.ResetTable(dynamoWrapper.RepoBlobsTablename), ShouldBeNil) //nolint:contextcheck
		So(dynamoWrapper.ResetTable(dynamoWrapper.ImageMetaTablename), ShouldBeNil) //nolint:contextcheck
		So(dynamoWrapper.ResetTable(dynamoWrapper.UserDataTablename), ShouldBeNil)  //nolint:contextcheck

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("test")
		ctx := userAc.DeriveContext(context.Background())

		Convey("RemoveRepoReference", func() {
			Convey("getProtoRepoMeta errors", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})

			Convey("getProtoImageMeta errors", func() {
				err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    imageMeta.Digest.String(),
						},
					},
				})
				So(err, ShouldBeNil)

				err = setImageMeta(imageMeta.Digest, badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoBlobs errors", func() {
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = setRepoBlobInfo("repo", badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				err = dynamoWrapper.RemoveRepoReference("repo", "ref", imageMeta.Digest) //nolint: contextcheck
				So(err, ShouldNotBeNil)
			})
		})
		Convey("FilterImageMeta", func() {
			Convey("FilterImageMeta with duplicate digests", func() {
				image := CreateRandomImage()

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", image.AsImageMeta())
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.FilterImageMeta(ctx, []string{image.DigestStr(), image.DigestStr()})
				So(err, ShouldNotBeNil)
			})

			Convey("manifest meta unmarshal error", func() {
				err = setImageMeta(image.Digest(), badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.FilterImageMeta(ctx, []string{image.DigestStr()})
				So(err, ShouldNotBeNil)
			})

			Convey("MediaType ImageIndex, getProtoImageMeta fails", func() {
				err := dynamoWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta) //nolint: contextcheck
				So(err, ShouldBeNil)

				err = setImageMeta(image.Digest(), badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = dynamoWrapper.FilterImageMeta(ctx, []string{multiarchImageMeta.Digest.String()})
				So(err, ShouldNotBeNil)
			})
		})
		Convey("UpdateSignaturesValidity", func() {
			digest := image.Digest()

			Convey("image meta blob not found", func() {
				err := dynamoWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("UpdateSignaturesValidity with context done", func() {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				err := dynamoWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("image meta unmarshal fail", func() {
				err := setImageMeta(digest, badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta blob not found", func() {
				err := dynamoWrapper.SetImageMeta(digest, imageMeta)
				So(err, ShouldBeNil)

				err = dynamoWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta unmarshal fail", func() {
				err := dynamoWrapper.SetImageMeta(digest, imageMeta)
				So(err, ShouldBeNil)

				err = setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("UpdateStatsOnDownload", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.UpdateStatsOnDownload("repo", "ref")
				So(err, ShouldNotBeNil)
			})

			Convey("ref is tag and tag is not found", func() {
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = dynamoWrapper.UpdateStatsOnDownload("repo", "not-found-tag") //nolint: contextcheck
				So(err, ShouldNotBeNil)
			})

			Convey("digest not found in statistics", func() {
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = dynamoWrapper.UpdateStatsOnDownload("repo", godigest.FromString("not-found").String()) //nolint: contextcheck
				So(err, ShouldNotBeNil)
			})

			Convey("statistics entry missing but digest exists in tags - should create and increment", func() {
				// Set repo reference to create tag
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				// Manually remove Statistics entry to simulate missing Statistics
				repoMeta, err := dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				delete(repoMeta.Statistics, imageMeta.Digest.String())

				// Set repo meta back without Statistics
				err = dynamoWrapper.SetRepoMeta("repo", repoMeta)
				So(err, ShouldBeNil)

				// Verify Statistics entry doesn't exist
				repoMeta, err = dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				_, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeFalse)

				// Update stats - should create Statistics entry and increment
				err = dynamoWrapper.UpdateStatsOnDownload("repo", "tag") //nolint: contextcheck
				So(err, ShouldBeNil)

				// Verify Statistics entry was created and incremented
				repoMeta, err = dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 1)

				// Update stats again - should increment existing entry
				err = dynamoWrapper.UpdateStatsOnDownload("repo", "tag") //nolint: contextcheck
				So(err, ShouldBeNil)

				repoMeta, err = dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists = repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 2)
			})

			Convey("statistics entry missing but digest exists in tags - using digest reference", func() {
				// Set repo reference to create tag
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				// Manually remove Statistics entry
				repoMeta, err := dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				delete(repoMeta.Statistics, imageMeta.Digest.String())

				// Set repo meta back without Statistics
				err = dynamoWrapper.SetRepoMeta("repo", repoMeta)
				So(err, ShouldBeNil)

				// Update stats using digest directly
				err = dynamoWrapper.UpdateStatsOnDownload("repo", imageMeta.Digest.String()) //nolint: contextcheck
				So(err, ShouldBeNil)

				// Verify Statistics entry was created
				repoMeta, err = dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 1)
			})
		})
		Convey("GetReferrersInfo", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.GetReferrersInfo("repo", "refDig", []string{})
				So(err, ShouldNotBeNil)
			})
		})
		Convey("DecrementRepoStars", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.DecrementRepoStars("repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("IncrementRepoStars", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.IncrementRepoStars("repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("ResetRepoReferences", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper)
				So(err, ShouldBeNil)

				err = dynamoWrapper.ResetRepoReferences("repo", nil)
				So(err, ShouldNotBeNil)
			})

			Convey("preserve tags in tagsToKeep", func() {
				// Create repo with multiple tags
				image1 := CreateRandomImage()
				image2 := CreateRandomImage()

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag1", image1.AsImageMeta())
				So(err, ShouldBeNil)

				// Wait a bit to ensure different timestamps
				time.Sleep(10 * time.Millisecond)

				err = dynamoWrapper.SetRepoReference(ctx, "repo", "tag2", image2.AsImageMeta())
				So(err, ShouldBeNil)

				// Get repo meta to capture TaggedTimestamp
				repoMeta, err := dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldContainKey, "tag2")

				tag1Timestamp := repoMeta.Tags["tag1"].TaggedTimestamp

				// Reset with only tag1 in tagsToKeep
				tagsToKeep := map[string]bool{"tag1": true}
				err = dynamoWrapper.ResetRepoReferences("repo", tagsToKeep)
				So(err, ShouldBeNil)

				// Verify tag1 is preserved with its timestamp
				repoMeta, err = dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldNotContainKey, "tag2")
				So(repoMeta.Tags["tag1"].TaggedTimestamp, ShouldEqual, tag1Timestamp)
			})

			Convey("remove tags not in tagsToKeep", func() {
				// Create repo with multiple tags
				image1 := CreateRandomImage()
				image2 := CreateRandomImage()
				image3 := CreateRandomImage()

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag1", image1.AsImageMeta())
				So(err, ShouldBeNil)

				err = dynamoWrapper.SetRepoReference(ctx, "repo", "tag2", image2.AsImageMeta())
				So(err, ShouldBeNil)

				err = dynamoWrapper.SetRepoReference(ctx, "repo", "tag3", image3.AsImageMeta())
				So(err, ShouldBeNil)

				// Reset with tag1 and tag2 in tagsToKeep
				tagsToKeep := map[string]bool{"tag1": true, "tag2": true}
				err = dynamoWrapper.ResetRepoReferences("repo", tagsToKeep)
				So(err, ShouldBeNil)

				// Verify only tag1 and tag2 are preserved
				repoMeta, err := dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldContainKey, "tag2")
				So(repoMeta.Tags, ShouldNotContainKey, "tag3")
			})

			Convey("preserve statistics and stars", func() {
				image := CreateRandomImage()

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag1", image.AsImageMeta())
				So(err, ShouldBeNil)

				err = dynamoWrapper.IncrementRepoStars("repo")
				So(err, ShouldBeNil)

				// Get original stats
				repoMeta, err := dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				originalStars := repoMeta.StarCount

				// Reset with empty tagsToKeep
				err = dynamoWrapper.ResetRepoReferences("repo", map[string]bool{})
				So(err, ShouldBeNil)

				// Verify statistics and stars are preserved
				repoMeta, err = dynamoWrapper.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.StarCount, ShouldEqual, originalStars)
			})
		})

		Convey("GetMultipleRepoMeta", func() {
			Convey("repoMetaAttributeIterator.First fails", func() {
				dynamoWrapper.RepoMetaTablename = badTablename
				_, err := dynamoWrapper.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
				So(err, ShouldNotBeNil)
			})
			Convey("repo meta unmarshal fails", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
				So(err, ShouldNotBeNil)
			})
		})
		Convey("GetImageMeta", func() {
			Convey("get image meta fails", func() {
				_, err := dynamoWrapper.GetImageMeta(testDigest)
				So(err, ShouldNotBeNil)
			})
			Convey("image index, missing manifests are skipped gracefully", func() {
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", multiarchImageMeta)
				So(err, ShouldBeNil)

				// Missing manifests are skipped gracefully, so GetImageMeta succeeds
				// but returns an index with no manifests
				imageMeta, err := dynamoWrapper.GetImageMeta(multiarchImageMeta.Digest) //nolint: contextcheck
				So(err, ShouldBeNil)
				So(len(imageMeta.Manifests), ShouldEqual, 0)
			})
		})
		Convey("GetFullImageMeta", func() {
			Convey("repo meta not found", func() {
				_, err := dynamoWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("tag not found", func() {
				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.GetFullImageMeta(ctx, "repo", "tag-not-found")
				So(err, ShouldNotBeNil)
			})

			Convey("getProtoImageMeta fails", func() {
				err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromString("not-found").String(),
						},
					},
				})
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("image is index, missing manifests are skipped gracefully", func() {
				err := dynamoWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta) //nolint: contextcheck
				So(err, ShouldBeNil)

				err = dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    multiarchImageMeta.Digest.String(),
						},
					},
				})
				So(err, ShouldBeNil)

				// Missing manifests are skipped gracefully, so GetFullImageMeta succeeds
				// but returns an index with no manifests
				fullImageMeta, err := dynamoWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldBeNil)
				So(len(fullImageMeta.Manifests), ShouldEqual, 0)
			})
		})

		Convey("FilterTags", func() {
			Convey("repoMetaAttributeIterator.First fails", func() {
				dynamoWrapper.RepoMetaTablename = badTablename

				_, err = dynamoWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldNotBeNil)
			})
			Convey("repo meta unmarshal fails", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldNotBeNil)
			})
			Convey("found repo meta", func() {
				Convey("bad image manifest", func() {
					badImageDigest := godigest.FromString("bad-image-manifest")
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-manifest": {
								MediaType: ispec.MediaTypeImageManifest,
								Digest:    badImageDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badImageDigest, badProtoBlob, dynamoWrapper) //nolint: contextcheck
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
					So(err, ShouldNotBeNil)
				})
				Convey("bad image index", func() {
					badIndexDigest := godigest.FromString("bad-image-manifest")
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-index": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    badIndexDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badIndexDigest, badProtoBlob, dynamoWrapper) //nolint: contextcheck
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
					So(err, ShouldNotBeNil)
				})
				Convey("good image index, bad inside manifest", func() {
					goodIndexBadManifestDigest := godigest.FromString("good-index-bad-manifests")
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"good-index-bad-manifests": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    goodIndexBadManifestDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = dynamoWrapper.SetImageMeta(goodIndexBadManifestDigest, multiarchImageMeta) //nolint: contextcheck
					So(err, ShouldBeNil)

					err = setImageMeta(image.Digest(), badProtoBlob, dynamoWrapper) //nolint: contextcheck
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey("SearchTags", func() {
			Convey("getProtoRepoMeta errors", func() {
				dynamoWrapper.RepoMetaTablename = badTablename

				_, err := dynamoWrapper.SearchTags(ctx, "repo")
				So(err, ShouldNotBeNil)
			})
			Convey("found repo meta", func() {
				Convey("bad image manifest", func() {
					badImageDigest := godigest.FromString("bad-image-manifest")
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-manifest": {
								MediaType: ispec.MediaTypeImageManifest,
								Digest:    badImageDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badImageDigest, badProtoBlob, dynamoWrapper) //nolint: contextcheck
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("bad image index", func() {
					badIndexDigest := godigest.FromString("bad-image-manifest")
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-index": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    badIndexDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badIndexDigest, badProtoBlob, dynamoWrapper) //nolint: contextcheck
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("good image index, bad inside manifest", func() {
					goodIndexBadManifestDigest := godigest.FromString("good-index-bad-manifests")
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"good-index-bad-manifests": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    goodIndexBadManifestDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = dynamoWrapper.SetImageMeta(goodIndexBadManifestDigest, multiarchImageMeta) //nolint: contextcheck
					So(err, ShouldBeNil)

					err = setImageMeta(image.Digest(), badProtoBlob, dynamoWrapper) //nolint: contextcheck
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("bad media type", func() {
					err := dynamoWrapper.SetRepoMeta("repo", mTypes.RepoMeta{ //nolint: contextcheck
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"mad-media-type": {
								MediaType: "bad media type",
								Digest:    godigest.FromString("dig").String(),
							},
						},
					})
					So(err, ShouldBeNil)

					_, err = dynamoWrapper.SearchTags(ctx, "repo:")
					So(err, ShouldBeNil)
				})
			})
		})

		Convey("SearchRepos", func() {
			Convey("repoMetaAttributeIterator.First errors", func() {
				dynamoWrapper.RepoMetaTablename = badTablename

				_, err := dynamoWrapper.SearchRepos(ctx, "repo")
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta unmarshal errors", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.SearchRepos(ctx, "repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetRepoReference", func() {
			Convey("SetProtoImageMeta fails", func() {
				dynamoWrapper.ImageMetaTablename = badTablename

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", image.AsImageMeta())
				So(err, ShouldNotBeNil)
			})
			Convey("getProtoRepoMeta fails", func() {
				dynamoWrapper.RepoMetaTablename = badTablename

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", image.AsImageMeta())
				So(err, ShouldNotBeNil)
			})
			Convey("getProtoRepoBlobs fails", func() {
				dynamoWrapper.RepoBlobsTablename = badTablename

				err := dynamoWrapper.SetRepoReference(ctx, "repo", "tag", image.AsImageMeta())
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetProtoImageMeta", func() {
			Convey("Get request fails", func() {
				dynamoWrapper.ImageMetaTablename = badTablename

				_, err := dynamoWrapper.GetProtoImageMeta(ctx, testDigest)
				So(err, ShouldNotBeNil)
			})
			Convey("unmarshal fails", func() {
				err := setRepoMeta("repo", badProtoBlob, dynamoWrapper) //nolint: contextcheck
				So(err, ShouldBeNil)

				_, err = dynamoWrapper.GetProtoImageMeta(ctx, testDigest)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetUserData", func() {
			hashKey := "id"
			apiKeys := make(map[string]mTypes.APIKeyDetails)
			apiKeyDetails := mTypes.APIKeyDetails{
				Label:  "apiKey",
				Scopes: []string{"repo"},
				UUID:   hashKey,
			}

			apiKeys[hashKey] = apiKeyDetails

			userProfileSrc := mTypes.UserData{
				Groups:  []string{"group1", "group2"},
				APIKeys: apiKeys,
			}

			err := dynamoWrapper.SetUserData(ctx, userProfileSrc)
			So(err, ShouldBeNil)

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = dynamoWrapper.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData", func() {
			err := dynamoWrapper.DeleteUserData(ctx)
			So(err, ShouldBeNil)

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = dynamoWrapper.DeleteUserData(ctx) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo no access", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})

			ctx := userAc.DeriveContext(context.Background())

			_, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "unaccesible")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo GetUserMeta no user data", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			status, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldBeNil)
			So(status, ShouldEqual, mTypes.Added)
		})

		Convey("ToggleBookmarkRepo GetUserMeta client error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})

			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = badTablename

			status, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
			So(status, ShouldEqual, mTypes.NotChanged)
		})

		Convey("GetBookmarkedRepos", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})

			ctx := userAc.DeriveContext(context.Background())

			repos, err := dynamoWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("ToggleStarRepo GetUserMeta bad context", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetUserMeta no access", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})

			ctx := userAc.DeriveContext(context.Background())

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "unaccesible")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetUserMeta error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})

			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = badTablename

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetRepoMeta error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.RepoMetaTablename = badTablename

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			userData, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
			So(userData.BookmarkedRepos, ShouldBeEmpty)
			So(userData.StarredRepos, ShouldBeEmpty)
		})

		Convey("GetUserData client error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = badTablename

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserMeta unmarshal error, bad user data", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err := setBadUserData(dynamoWrapper.Client, userDataTablename, userAc.GetUsername())
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.DeleteUserAPIKey(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoLastUpdated", func() {
			Convey("bad table", func() {
				dynamoWrapper.RepoBlobsTablename = "bad-table"

				lastUpdated := dynamoWrapper.GetRepoLastUpdated("repo")
				So(lastUpdated, ShouldEqual, time.Time{})
			})

			Convey("unmarshal error", func() {
				err := setRepoLastUpdated("repo", []byte("bad-blob"), dynamoWrapper)
				So(err, ShouldBeNil)

				lastUpdated := dynamoWrapper.GetRepoLastUpdated("repo")
				So(lastUpdated, ShouldEqual, time.Time{})
			})
		})

		Convey("DeleteUserAPIKey returns nil", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("email")
			ctx := userAc.DeriveContext(context.Background())

			apiKeyDetails := make(map[string]mTypes.APIKeyDetails)
			apiKeyDetails["id"] = mTypes.APIKeyDetails{
				UUID: "id",
			}
			err := dynamoWrapper.SetUserData(ctx, mTypes.UserData{
				APIKeys: apiKeyDetails,
			})
			So(err, ShouldBeNil)

			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.DeleteUserAPIKey(ctx, "id")
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey", func() {
			Convey("no userid found", func() {
				userAc := reqCtx.NewUserAccessControl()
				ctx := userAc.DeriveContext(context.Background())

				err = dynamoWrapper.AddUserAPIKey(ctx, "key", &mTypes.APIKeyDetails{})
				So(err, ShouldNotBeNil)
			})

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("email")
			ctx := userAc.DeriveContext(context.Background())

			err := dynamoWrapper.AddUserAPIKey(ctx, "key", &mTypes.APIKeyDetails{})
			So(err, ShouldBeNil)

			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.AddUserAPIKey(ctx, "key", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo", func() {
			dynamoWrapper.APIKeyTablename = wrongTableName
			_, err := dynamoWrapper.GetUserAPIKeyInfo("key")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData", func() {
			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("email")
			ctx = userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = wrongTableName
			_, err = dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("PatchDB dwr.getDBVersion errors", func() {
			dynamoWrapper.VersionTablename = badTablename

			err := dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})

		Convey("PatchDB patchIndex < version.GetVersionIndex", func() {
			err := setVersion(dynamoWrapper.Client, versionTablename, "V2")
			So(err, ShouldBeNil)

			dynamoWrapper.Patches = []func(client *dynamodb.Client, tableNames map[string]string) error{
				func(client *dynamodb.Client, tableNames map[string]string) error { return nil },
				func(client *dynamodb.Client, tableNames map[string]string) error { return nil },
				func(client *dynamodb.Client, tableNames map[string]string) error { return nil },
			}

			err = dynamoWrapper.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("ResetRepoMetaTable client errors", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			err := dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename)
			So(err, ShouldNotBeNil)
		})

		Convey("getDBVersion client errors", func() {
			dynamoWrapper.VersionTablename = badTablename

			err := dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})
	})

	Convey("NewDynamoDBWrapper errors", t, func() {
		params := mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      "",
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       versionTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     "",
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       versionTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: "",
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       versionTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       "",
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			VersionTablename:       versionTablename,
			UserDataTablename:      "",
			APIKeyTablename:        apiKeyTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			VersionTablename:       versionTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        "",
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)
	})
}

func setRepoMeta(repo string, blob []byte, dynamoWrapper *mdynamodb.DynamoDB) error { //nolint: unparam
	userAttributeValue, err := attributevalue.Marshal(blob)
	if err != nil {
		return err
	}

	_, err = dynamoWrapper.Client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMeta",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMeta": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dynamoWrapper.RepoMetaTablename),
		UpdateExpression: aws.String("SET #RM = :RepoMeta"),
	})

	return err
}

func setRepoLastUpdated(repo string, blob []byte, dynamoWrapper *mdynamodb.DynamoDB) error { //nolint: unparam
	lastUpdatedAttributeValue, err := attributevalue.Marshal(blob)
	if err != nil {
		return err
	}

	_, err = dynamoWrapper.Client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RLU": "RepoLastUpdated",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoLastUpdated": lastUpdatedAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dynamoWrapper.RepoBlobsTablename),
		UpdateExpression: aws.String("SET #RLU = :RepoLastUpdated"),
	})

	return err
}

func setRepoBlobInfo(repo string, blob []byte, dynamoWrapper *mdynamodb.DynamoDB) error {
	userAttributeValue, err := attributevalue.Marshal(blob)
	if err != nil {
		return err
	}

	_, err = dynamoWrapper.Client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RB": "RepoBlobsInfo",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoBlobsInfo": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: repo,
			},
		},
		TableName:        aws.String(dynamoWrapper.RepoBlobsTablename),
		UpdateExpression: aws.String("SET #RB = :RepoBlobsInfo"),
	})

	return err
}

func setImageMeta(digest godigest.Digest, blob []byte, dynamoWrapper *mdynamodb.DynamoDB) error {
	userAttributeValue, err := attributevalue.Marshal(blob)
	if err != nil {
		return err
	}

	_, err = dynamoWrapper.Client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#IM": "ImageMeta",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ImageMeta": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: digest.String(),
			},
		},
		TableName:        aws.String(dynamoWrapper.ImageMetaTablename),
		UpdateExpression: aws.String("SET #IM = :ImageMeta"),
	})

	return err
}

func setBadUserData(client *dynamodb.Client, userDataTablename, userID string) error {
	userAttributeValue, err := attributevalue.Marshal("string")
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#UM": "UserData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":UserData": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: userID,
			},
		},
		TableName:        aws.String(userDataTablename),
		UpdateExpression: aws.String("SET #UM = :UserData"),
	})

	return err
}

func setVersion(client *dynamodb.Client, versionTablename string, version string) error {
	mdAttributeValue, err := attributevalue.Marshal(version)
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#V": "Version",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":Version": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: "DBVersion",
			},
		},
		TableName:        aws.String(versionTablename),
		UpdateExpression: aws.String("SET #V = :Version"),
	})

	return err
}
