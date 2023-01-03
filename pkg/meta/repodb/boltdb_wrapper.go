package repodb

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
)

type BoltDBParameters struct {
	RootDir string
}

type BoltDBWrapper struct {
	db  *bolt.DB
	log log.Logger
}

func NewBoltDBWrapper(params BoltDBParameters) (*BoltDBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "users.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		_, err := transaction.CreateBucketIfNotExists([]byte(UserMetadataBucket))
		if err != nil {
			return err
		}
		_, err = transaction.CreateBucketIfNotExists([]byte(UserSessionBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(UserAPIKeysBucket))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &BoltDBWrapper{
		db:  boltDB,
		log: log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (bdw BoltDBWrapper) AddUserAPIKey(hashedKey string, email string, apiKeyDetails *ApiKeyDetails) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		apiKeysbuck := tx.Bucket([]byte(UserAPIKeysBucket))
		if apiKeysbuck == nil {
			return zerr.ErrBucketDoesNotExist
		}
		userInfo := &UserInfo{
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
		userProfile.ApiKeys = make(map[string]ApiKeyDetails)
	}
	
	userProfile.ApiKeys[hashedKey] = *apiKeyDetails

	err = bdw.SetUserProfile(email, userProfile)

	return err
}

func (bdw BoltDBWrapper) DeleteUserAPIKey(id string, userEmail string) error {
	userProfile, err := bdw.GetUserProfile(userEmail)
	if err != nil {
		return errors.Wrapf(err, "repoDB: error while getting userProfile for email %s", userEmail)
	}

	for hash, apiKeyDetails := range userProfile.ApiKeys {
		if apiKeyDetails.UUID == id {
			delete(userProfile.ApiKeys, hash)
			err = bdw.db.Update(func(tx *bolt.Tx) error {
				apiKeysbuck := tx.Bucket([]byte(UserAPIKeysBucket))
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

func (bdw BoltDBWrapper) GetUserAPIKeyInfo(hashedKey string) (UserInfo, error) {
	var userInfo UserInfo
	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserAPIKeysBucket))
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

func (bdw BoltDBWrapper) GetUserProfile(email string) (UserProfile, error) {
	var userProfile UserProfile
	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserMetadataBucket))
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

func (bdw BoltDBWrapper) SetUserProfile(email string, userProfile UserProfile) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserMetadataBucket))
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

func (bdw BoltDBWrapper) DeleteUserProfile(email string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserMetadataBucket))
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

func (bdw BoltDBWrapper) GetUserInfoForSession(sessionID string) (UserInfo, error) {
	var userInfo UserInfo
	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserSessionBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		usBlob := buck.Get([]byte(sessionID))

		if len(usBlob) == 0 {
			return zerr.ErrUserSessionNotFound
		}

		err := json.Unmarshal(usBlob, &userInfo)
		if err != nil {
			return errors.Wrapf(err,
				"repoDB: error while unmarshaling userSession blob for sessionID %s", sessionID)
		}

		return nil
	})

	return userInfo, err
}

func (bdw BoltDBWrapper) SetUserInfoForSession(sessionID string, userInfo UserInfo) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserSessionBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		uiBlob, err := json.Marshal(userInfo)
		if err != nil {
			return errors.Wrapf(err, "repoDB: error while marshaling userSession for sessionID %s", sessionID)
		}

		err = buck.Put([]byte(sessionID), uiBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting userSession  for sessionID %s", sessionID)
		}

		return nil
	})

	return err
}

func (bdw BoltDBWrapper) DeleteUserSession(sessionID string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(UserSessionBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := buck.Delete([]byte(sessionID))
		if err != nil {
			return errors.Wrapf(err, "repodb: error while deleting userSession  for sessionID %s", sessionID)
		}

		return nil
	})

	return err
}
