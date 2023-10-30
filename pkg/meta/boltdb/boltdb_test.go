package boltdb_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"math"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/boltdb"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	reqCtx "zotregistry.io/zot/pkg/requestcontext"
)

type imgTrustStore struct{}

func (its imgTrustStore) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest digest.Digest, imageMeta mTypes.ImageMeta,
	repo string,
) (string, time.Time, bool, error) {
	return "", time.Time{}, false, nil
}

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

		boltdbWrapper.SetImageTrustStore(imgTrustStore{})

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("test")

		ctx := userAc.DeriveContext(context.Background())

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
