package bolt

import (
	"encoding/json"
	"os"
	"path"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/userdb"

	"zotregistry.io/zot/pkg/meta/userdb/version"
)

type DBParameters struct {
	RootDir string
}

type DBWrapper struct {
	DB      *bolt.DB
	Patches []func(DB *bolt.DB) error
	Log     log.Logger
}

func NewBoltDBWrapper(params DBParameters) (*DBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "user.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		versionBuck, err := transaction.CreateBucketIfNotExists([]byte(userdb.VersionBucket))
		if err != nil {
			return err
		}

		err = versionBuck.Put([]byte(version.DBVersionKey), []byte(version.CurrentVersion))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(userdb.UserSecurityBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(userdb.UserAPIKeysBucket))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &DBWrapper{
		DB:      boltDB,
		Patches: version.GetBoltDBPatches(),
		Log:     log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func(bdw *DBWrapper) GetBoltDBPatches() []func() error {
	return []func() error{}
}




func (bdw *DBWrapper) PatchDB() error {
	var DBVersion string

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		versionBuck := tx.Bucket([]byte(userdb.VersionBucket))
		DBVersion = string(versionBuck.Get([]byte(version.DBVersionKey)))

		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "patching the database failed, can't read db version")
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return errors.New("DB has broken format, no version found")
	}

	for patchIndex, patch := range bdw.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		err := patch(bdw.DB)
		if err != nil {
			return err
		}
	}

	return nil
}

func (bdw *DBWrapper) AddUserAPIKey(hashedKey string, email string, apiKeyDetails *userdb.ApiKeyDetails) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		apiKeysbuck := tx.Bucket([]byte(userdb.UserAPIKeysBucket))
		if apiKeysbuck == nil {
			return zerr.ErrBucketDoesNotExist
		}
		userInfo := &userdb.UserInfo{
			Email: email,
		}

		uiBlob, err := json.Marshal(userInfo)
		if err != nil {
			return errors.Wrapf(err, "repoDB: error while marshaling userInfo for hashedKey %s", hashedKey)
		}

		err = apiKeysbuck.Put([]byte(hashedKey), uiBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting userProfile  for email %s", email)
		}

		return nil
	})
	if err != nil {
		return err
	}

	userProfile, err := bdw.GetUserProfile(email)
	if err != nil {
		return errors.Wrapf(err, "repoDB: error while getting userProfile for email %s", email)
	}
	if userProfile.ApiKeys == nil {
		userProfile.ApiKeys = make(map[string]userdb.ApiKeyDetails)
	}

	userProfile.ApiKeys[hashedKey] = *apiKeyDetails

	err = bdw.SetUserProfile(email, userProfile)

	return err
}

func (bdw *DBWrapper) DeleteUserAPIKey(id string, userEmail string) error {
	userProfile, err := bdw.GetUserProfile(userEmail)
	if err != nil {
		return errors.Wrapf(err, "repoDB: error while getting userProfile for email %s", userEmail)
	}

	for hash, apiKeyDetails := range userProfile.ApiKeys {
		if apiKeyDetails.UUID == id {
			delete(userProfile.ApiKeys, hash)
			err = bdw.DB.Update(func(tx *bolt.Tx) error {
				apiKeysbuck := tx.Bucket([]byte(userdb.UserAPIKeysBucket))
				if apiKeysbuck == nil {
					return zerr.ErrBucketDoesNotExist
				}
				err := apiKeysbuck.Delete([]byte(hash))
				if err != nil {
					return errors.Wrapf(err, "repodb: error while deleting userAPIKey entry for hash %s", hash)
				}

				return nil
			})

			if err != nil {
				return err
			}

			err := bdw.SetUserProfile(userEmail, userProfile)

			return err
		}
	}

	return nil
}

func (bdw *DBWrapper) GetUserAPIKeyInfo(hashedKey string) (userdb.UserInfo, error) {
	var userInfo userdb.UserInfo
	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(userdb.UserAPIKeysBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		uiBlob := buck.Get([]byte(hashedKey))
		if len(uiBlob) == 0 {
			return zerr.ErrUserAPIKeyNotFound
		}

		err := json.Unmarshal(uiBlob, &userInfo)
		if err != nil {
			return errors.Wrapf(err,
				"repoDB: error while unmarshaling userInfo blob for hashedKey %s", hashedKey)
		}

		return nil
	})

	return userInfo, err
}

func (bdw *DBWrapper) GetUserProfile(email string) (userdb.UserProfile, error) {
	var userProfile userdb.UserProfile
	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(userdb.UserSecurityBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		upBlob := buck.Get([]byte(email))

		if len(upBlob) == 0 {
			return zerr.ErrUserProfileNotFound
		}

		err := json.Unmarshal(upBlob, &userProfile)
		if err != nil {
			return errors.Wrapf(err,
				"repoDB: error while unmarshaling userProfile blob for email %s", email)
		}

		return nil
	})

	return userProfile, err
}

func (bdw *DBWrapper) SetUserProfile(email string, userProfile userdb.UserProfile) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(userdb.UserSecurityBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		upBlob, err := json.Marshal(userProfile)
		if err != nil {
			return errors.Wrapf(err, "repoDB: error while marshaling userProfile for email %s", email)
		}

		err = buck.Put([]byte(email), upBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting userProfile  for email %s", email)
		}

		return nil
	})

	return err
}

func (bdw *DBWrapper) DeleteUserProfile(email string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(userdb.UserSecurityBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := buck.Delete([]byte(email))
		if err != nil {
			return errors.Wrapf(err, "repodb: error while deleting userProfile  for email %s", email)
		}

		return nil
	})

	return err
}

// func (bdw *DBWrapper) GetUserInfoForSession(sessionID string) (repodb.UserInfo, error) {
// 	var userInfo repodb.UserInfo
// 	err := bdw.DB.View(func(tx *bolt.Tx) error {
// 		buck := tx.Bucket([]byte(repodb.UserSessionBucket))
// 		if buck == nil {
// 			return zerr.ErrBucketDoesNotExist
// 		}

// 		usBlob := buck.Get([]byte(sessionID))

// 		if len(usBlob) == 0 {
// 			return zerr.ErrUserSessionNotFound
// 		}

// 		err := json.Unmarshal(usBlob, &userInfo)
// 		if err != nil {
// 			return errors.Wrapf(err,
// 				"repoDB: error while unmarshaling userSession blob for sessionID %s", sessionID)
// 		}

// 		return nil
// 	})

// 	return userInfo, err
// }

// func (bdw *DBWrapper) SetUserInfoForSession(sessionID string, userInfo repodb.UserInfo) error {
// 	err := bdw.DB.Update(func(tx *bolt.Tx) error {
// 		buck := tx.Bucket([]byte(repodb.UserSessionBucket))
// 		if buck == nil {
// 			return zerr.ErrBucketDoesNotExist
// 		}

// 		uiBlob, err := json.Marshal(userInfo)
// 		if err != nil {
// 			return errors.Wrapf(err, "repoDB: error while marshaling userSession for sessionID %s", sessionID)
// 		}

// 		err = buck.Put([]byte(sessionID), uiBlob)
// 		if err != nil {
// 			return errors.Wrapf(err, "repodb: error while setting userSession  for sessionID %s", sessionID)
// 		}

// 		return nil
// 	})

// 	return err
// }

// func (bdw *DBWrapper) DeleteUserSession(sessionID string) error {
// 	err := bdw.DB.Update(func(tx *bolt.Tx) error {
// 		buck := tx.Bucket([]byte(repodb.UserSessionBucket))
// 		if buck == nil {
// 			return zerr.ErrBucketDoesNotExist
// 		}

// 		err := buck.Delete([]byte(sessionID))
// 		if err != nil {
// 			return errors.Wrapf(err, "repodb: error while deleting userSession  for sessionID %s", sessionID)
// 		}

// 		return nil
// 	})

// 	return err
// }
