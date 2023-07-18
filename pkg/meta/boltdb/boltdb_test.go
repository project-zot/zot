package boltdb_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/boltdb"
	"zotregistry.io/zot/pkg/meta/signatures"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/test"
)

func TestWrapperErrors(t *testing.T) {
	Convey("Errors", t, func() {
		tmpDir := t.TempDir()
		boltDBParams := boltdb.DBParameters{RootDir: tmpDir}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		boltdbWrapper, err := boltdb.New(boltDriver, log)
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		repoMeta := mTypes.RepoMetadata{
			Tags:       map[string]mTypes.Descriptor{},
			Signatures: map[string]mTypes.ManifestSignatures{},
		}

		repoMetaBlob, err := json.Marshal(repoMeta)
		So(err, ShouldBeNil)

		authzCtxKey := localCtx.GetContextKey()

		acCtx := localCtx.AccessControlContext{
			Username: "test",
		}

		ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

		Convey("AddUserAPIKey", func() {
			Convey("no userid found", func() {
				acCtx := localCtx.AccessControlContext{
					Username: "",
				}

				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)
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

			acCtx := localCtx.AccessControlContext{
				Username: "",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)
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

				authzCtxKey := localCtx.GetContextKey()

				acCtx := localCtx.AccessControlContext{
					Username: "test",
				}

				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				err = boltdbWrapper.DeleteUserAPIKey(ctx, "")
				So(err, ShouldEqual, zerr.ErrBucketDoesNotExist)
			})

			Convey("userdata not found", func() {
				authzCtxKey := localCtx.GetContextKey()
				acCtx := localCtx.AccessControlContext{
					Username: "test",
				}

				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)
				err := boltdbWrapper.DeleteUserData(ctx)
				So(err, ShouldBeNil)

				err = boltdbWrapper.DeleteUserAPIKey(ctx, "")
				So(err, ShouldNotBeNil)
			})

			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx) //nolint: contextcheck

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
			acCtx = localCtx.AccessControlContext{
				Username: "",
			}

			ctx = context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)

			buff := make([]byte, int(math.Ceil(float64(1000000)/float64(1.33333333333))))
			_, err := rand.Read(buff)
			So(err, ShouldBeNil)

			longString := base64.RawURLEncoding.EncodeToString(buff)

			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: longString,
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserDataBucket))
			})
			So(err, ShouldBeNil)

			acCtx = localCtx.AccessControlContext{
				Username: "test",
			}

			ctx = context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData", func() {
			acCtx = localCtx.AccessControlContext{
				Username: "",
			}

			ctx = context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(boltdb.UserDataBucket))
			})
			So(err, ShouldBeNil)

			acCtx = localCtx.AccessControlContext{
				Username: "test",
			}

			ctx = context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserGroups and SetUserGroups", func() {
			acCtx = localCtx.AccessControlContext{
				Username: "",
			}

			ctx = context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err := boltdbWrapper.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestData", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				return dataBuck.Put([]byte("digest1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetManifestData("digest1")
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetManifestMeta("repo1", "digest1")
			So(err, ShouldNotBeNil)
		})

		Convey("SetManifestMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				err := dataBuck.Put([]byte("digest1"), repoMetaBlob)
				if err != nil {
					return err
				}

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetManifestMeta("repo1", "digest1", mTypes.ManifestMetadata{})
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetManifestMeta("repo1", "digest1")
			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				buck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				err := buck.Put([]byte("badRepo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.FilterRepos(context.Background(),
				func(repoMeta mTypes.RepoMetadata) bool { return true }, mTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SetReferrer", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetReferrer("repo", "ref", mTypes.ReferrerInfo{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteReferrer", func() {
			Convey("RepoMeta not found", func() {
				err := boltdbWrapper.DeleteReferrer("r", "dig", "dig")
				So(err, ShouldNotBeNil)
			})

			Convey("bad repo meta blob", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DeleteReferrer("repo", "dig", "dig")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetRepoReference", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetRepoReference("repo1", "tag", "digest", ispec.MediaTypeImageManifest)
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoMeta("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteRepoTag", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteRepoTag("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrersInfo", func() {
			_, err = boltdbWrapper.GetReferrersInfo("repo1", "tag", nil)
			So(err, ShouldNotBeNil)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetReferrersInfo("repo1", "tag", nil)
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementRepoStars("repo2")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.IncrementRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("DecrementRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DecrementRepoStars("repo2")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DecrementRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetMultipleRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetMultipleRepoMeta(context.TODO(), func(repoMeta mTypes.RepoMetadata) bool {
				return true
			}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementImageDownloads", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo2", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				mTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			// signatures not found
			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				mTypes.SignatureMetadata{})
			So(err, ShouldBeNil)

			//
			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				repoMeta := mTypes.RepoMetadata{
					Tags: map[string]mTypes.Descriptor{},
					Signatures: map[string]mTypes.ManifestSignatures{
						"digest1": {
							"cosgin": {{}},
						},
						"digest2": {
							"notation": {{}},
						},
					},
				}

				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				mTypes.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: "digest1",
				})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				mTypes.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: "digest2",
				})
			So(err, ShouldBeNil)

			repoData, err := boltdbWrapper.GetRepoMeta("repo1")
			So(err, ShouldBeNil)
			So(len(repoData.Signatures[string(digest.FromString("dig"))][signatures.CosignSignature]),
				ShouldEqual, 1)
			So(repoData.Signatures[string(digest.FromString("dig"))][signatures.CosignSignature][0].SignatureManifestDigest,
				ShouldEqual, "digest2")

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				mTypes.SignatureMetadata{
					SignatureType:   "notation",
					SignatureDigest: "digest2",
				})
			So(err, ShouldBeNil)
		})

		Convey("DeleteSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteSignature("repo2", digest.FromString("dig"),
				mTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DeleteSignature("repo1", digest.FromString("dig"),
				mTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				repoMeta := mTypes.RepoMetadata{
					Tags: map[string]mTypes.Descriptor{},
					Signatures: map[string]mTypes.ManifestSignatures{
						"digest1": {
							"cosgin": []mTypes.SignatureInfo{
								{
									SignatureManifestDigest: "sigDigest1",
								},
								{
									SignatureManifestDigest: "sigDigest2",
								},
							},
						},
						"digest2": {
							"notation": {{}},
						},
					},
				}

				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteSignature("repo1", "digest1",
				mTypes.SignatureMetadata{
					SignatureType:   "cosgin",
					SignatureDigest: "sigDigest2",
				})
			So(err, ShouldBeNil)
		})

		Convey("SearchRepos", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				err := dataBuck.Put([]byte("dig1"), []byte("wrong json"))
				if err != nil {
					return err
				}

				repoMeta := mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]mTypes.ManifestSignatures{},
				}
				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo1"), repoMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = mTypes.RepoMetadata{
					Name: "repo2",
					Tags: map[string]mTypes.Descriptor{
						"tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]mTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo2"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo2", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				manifestMeta := mTypes.ManifestMetadata{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("wrong json"),
					Signatures:   mTypes.ManifestSignatures{},
				}

				manifestMetaBlob, err := json.Marshal(manifestMeta)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("dig1"), manifestMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]mTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("Index Errors", func() {
			Convey("Bad index data", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = setBadIndexData(boltdbWrapper.DB, indexDigest.String())
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", mTypes.Filter{}, mTypes.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", mTypes.Filter{}, mTypes.PageInput{})
				So(err, ShouldNotBeNil)
			})

			Convey("Bad indexBlob in IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, mTypes.IndexData{
					IndexBlob: []byte("bad json"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", mTypes.Filter{}, mTypes.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", mTypes.Filter{}, mTypes.PageInput{})
				So(err, ShouldNotBeNil)
			})

			Convey("Good index data, bad manifest inside index", func() {
				var (
					indexDigest              = digest.FromString("indexDigest")
					manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
					manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
				)

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
					manifestDigestFromIndex1, manifestDigestFromIndex2,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, mTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, mTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, mTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", mTypes.Filter{}, mTypes.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", mTypes.Filter{}, mTypes.PageInput{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SearchTags", func() {
			ctx := context.Background()

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				manifestMeta := mTypes.ManifestMetadata{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("wrong json"),
					Signatures:   mTypes.ManifestSignatures{},
				}

				manifestMetaBlob, err := json.Marshal(manifestMeta)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("dig1"), manifestMetaBlob)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("wrongManifestData"), []byte("wrong json"))
				if err != nil {
					return err
				}

				// manifest data doesn't exist
				repoMeta = mTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]mTypes.Descriptor{
						"tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]mTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo1"), repoMetaBlob)
				if err != nil {
					return err
				}

				// manifest data is wrong
				repoMeta = mTypes.RepoMetadata{
					Name: "repo2",
					Tags: map[string]mTypes.Descriptor{
						"tag2": {Digest: "wrongManifestData", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]mTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo2"), repoMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = mTypes.RepoMetadata{
					Name: "repo3",
					Tags: map[string]mTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]mTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo3"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo2:", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo3:", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags Index errors", func() {
			Convey("FilterTags bad IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = setBadIndexData(boltdbWrapper.DB, indexDigest.String())
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true },
					mTypes.Filter{},
					mTypes.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})

			Convey("FilterTags bad indexBlob in IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, mTypes.IndexData{
					IndexBlob: []byte("bad json"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true },
					mTypes.Filter{},
					mTypes.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})

			Convey("FilterTags didn't match any index manifest", func() {
				var (
					indexDigest              = digest.FromString("indexDigest")
					manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
					manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
				)

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
					manifestDigestFromIndex1, manifestDigestFromIndex2,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, mTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, mTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, mTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return false },
					mTypes.Filter{},
					mTypes.PageInput{},
				)
				So(err, ShouldBeNil)
			})

			Convey("FilterTags bad config blob in image with a single manifest", func() {
				manifestDigest := digest.FromString("manifestDigestBadConfig")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", //nolint:contextcheck
					manifestDigest, ispec.MediaTypeImageManifest,
				)
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigest, mTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("bad blob"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true },
					mTypes.Filter{},
					mTypes.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})

			Convey("FilterTags bad config blob in index", func() {
				var (
					indexDigest              = digest.FromString("indexDigest")
					manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndexGoodConfig")
					manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndexBadConfig")
				)

				err := boltdbWrapper.SetRepoReference("repo", "tag1", //nolint:contextcheck
					indexDigest, ispec.MediaTypeImageIndex,
				)
				So(err, ShouldBeNil)

				indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
					manifestDigestFromIndex1, manifestDigestFromIndex2,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, mTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, mTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, mTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("bad blob"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true },
					mTypes.Filter{},
					mTypes.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("ToggleStarRepo bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, no repoMeta found", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				err := repoBuck.Put([]byte("repo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, bad repoMeta found", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := boltdbWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserGroups bad context errors", func() {
			_, err := boltdbWrapper.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err = boltdbWrapper.GetUserGroups(ctx) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserGroups bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := boltdbWrapper.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := boltdbWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := boltdbWrapper.DeleteUserAPIKey(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := boltdbWrapper.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := boltdbWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetStarredRepos bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.GetStarredRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetBookmarkedRepos bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("Unsuported type", func() {
			digest := digest.FromString("digest")

			err := boltdbWrapper.SetRepoReference("repo", "tag1", digest, "invalid type") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", mTypes.Filter{}, mTypes.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.FilterTags(
				ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true },
				mTypes.Filter{},
				mTypes.PageInput{},
			)
			So(err, ShouldBeNil)
		})

		Convey("GetUserRepoMeta unmarshal error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				err := repoBuck.Put([]byte("repo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err := boltdbWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateSignaturesValidity", func() {
			Convey("manifestMeta of signed manifest not found", func() {
				err := boltdbWrapper.UpdateSignaturesValidity("repo", digest.FromString("dig"))
				So(err, ShouldBeNil)
			})

			Convey("repoMeta of signed manifest not found", func() {
				// repo Meta not found
				err := boltdbWrapper.SetManifestData(digest.FromString("dig"), mTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo", digest.FromString("dig"))
				So(err, ShouldNotBeNil)
			})

			Convey("manifest - bad content", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

					return dataBuck.Put([]byte("digest1"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", "digest1")
				So(err, ShouldNotBeNil)
			})

			Convey("index - bad content", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					dataBuck := tx.Bucket([]byte(boltdb.IndexDataBucket))

					return dataBuck.Put([]byte("digest1"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", "digest1")
				So(err, ShouldNotBeNil)
			})

			Convey("repo - bad content", func() {
				// repo Meta not found
				err := boltdbWrapper.SetManifestData(digest.FromString("dig"), mTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", digest.FromString("dig"))
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func setBadIndexData(dB *bbolt.DB, digest string) error {
	return dB.Update(func(tx *bbolt.Tx) error {
		indexDataBuck := tx.Bucket([]byte(boltdb.IndexDataBucket))

		return indexDataBuck.Put([]byte(digest), []byte("bad json"))
	})
}
