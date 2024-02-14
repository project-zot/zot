package boltdb_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"math"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	proto_go "zotregistry.dev/zot/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
	. "zotregistry.dev/zot/pkg/test/image-utils"
)

type imgTrustStore struct{}

func (its imgTrustStore) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta,
	repo string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	return "", time.Time{}, false, nil
}

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

		log := log.NewLogger("debug", "")

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

				err = boltdbWrapper.ResetRepoReferences("repo")
				So(err, ShouldNotBeNil)
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

			Convey("image is index, fail to get manifests", func() {
				err := boltdbWrapper.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    multiarchImageMeta.Digest.String(),
						},
					},
				})
				So(err, ShouldBeNil)

				_, err = boltdbWrapper.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
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
			ctx = userAc.DeriveContext(context.Background())

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
			ctx = userAc.DeriveContext(context.Background())

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
