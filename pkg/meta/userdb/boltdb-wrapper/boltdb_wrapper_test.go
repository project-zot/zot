package bolt_test

import (
	"encoding/json"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/pkg/meta/userdb"
	bolt "zotregistry.io/zot/pkg/meta/userdb/boltdb-wrapper"
)

func TestWrapperErrors(t *testing.T) {
	Convey("Errors", t, func() {
		tmpDir := t.TempDir()
		boltDBParams := bolt.DBParameters{RootDir: tmpDir}
		boltdbWrapper, err := bolt.NewBoltDBWrapper(boltDBParams)
		defer os.Remove("user.db")
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("AddUserAPIKey", func() {
			err := boltdbWrapper.AddUserAPIKey("hashedKey", "test@email", &userdb.APIKeyDetails{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.AddUserAPIKey("", "test@email", &userdb.APIKeyDetails{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.SetUserProfile("test2@email", userdb.UserProfile{})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddUserAPIKey("hashedKey2", "test2@email", &userdb.APIKeyDetails{})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				err := tx.DeleteBucket([]byte(userdb.UserAPIKeysBucket))
				if err != nil {
					return err
				}

				return nil
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddUserAPIKey("hashedKey3", "test3@email", &userdb.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey", func() {
			err := boltdbWrapper.SetUserProfile("test@email", userdb.UserProfile{
				APIKeys: map[string]userdb.APIKeyDetails{
					"hashedKey": {
						UUID: "123",
					},
				},
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserAPIKey("123", "test@email")
			So(err, ShouldBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				err := tx.DeleteBucket([]byte(userdb.UserAPIKeysBucket))
				if err != nil {
					return err
				}

				return nil
			})

			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserAPIKey("123", "test@email")
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetUserProfile("test2@email", userdb.UserProfile{
				APIKeys: map[string]userdb.APIKeyDetails{
					"hashedKey": {
						UUID: "321",
					},
				},
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserAPIKey("321", "test2@email")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				err := tx.DeleteBucket([]byte(userdb.UserSecurityBucket))
				if err != nil {
					return err
				}

				return nil
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserAPIKey("321", "test2@email")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				dataBuck := tx.Bucket([]byte(userdb.UserAPIKeysBucket))

				return dataBuck.Put([]byte("hashedKey"), []byte("test@email"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetUserAPIKeyInfo("hashedKey")
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetUserAPIKeyInfo("invalid")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserProfile", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				userSecBuck := tx.Bucket([]byte(userdb.UserSecurityBucket))

				userProfileBlob, err := json.Marshal(userdb.UserProfile{})
				if err != nil {
					return err
				}

				err = userSecBuck.Put([]byte("email3"), userProfileBlob)
				if err != nil {
					return err
				}

				return userSecBuck.Put([]byte("email"), []byte("invalidBlob"))
			})

			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetUserProfile("email")
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetUserProfile("email2")
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetUserProfile("email3")
			So(err, ShouldBeNil)
		})

		Convey("SetUserProfile", func() {
			err := boltdbWrapper.SetUserProfile("email", userdb.UserProfile{})

			So(err, ShouldBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				err := tx.DeleteBucket([]byte(userdb.UserSecurityBucket))
				if err != nil {
					return err
				}

				return nil
			})

			So(err, ShouldBeNil)

			err = boltdbWrapper.SetUserProfile("email", userdb.UserProfile{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserProfile", func() {
			err := boltdbWrapper.SetUserProfile("email", userdb.UserProfile{})

			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserProfile("email")

			So(err, ShouldBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				err := tx.DeleteBucket([]byte(userdb.UserSecurityBucket))
				if err != nil {
					return err
				}

				return nil
			})

			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteUserProfile("email")
			So(err, ShouldNotBeNil)
		})
	})
}
