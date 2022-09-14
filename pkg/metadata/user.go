package metadata

import (
	"encoding/json"
	"path"
	"time"

	"go.etcd.io/bbolt"
	"zotregistry.io/zot/pkg/common"
	zlog "zotregistry.io/zot/pkg/log"
	merrors "zotregistry.io/zot/pkg/metadata/errors"
)

const (
	MetadataDBName          = "metadata"
	UserMetadataName        = "Users"
	DBExtensionName         = ".db"
	dbCacheLockCheckTimeout = 10 * time.Second
)

const (
	starredReposKey    = "starredReposKey"
	bookmarkedReposKey = "bookmarkedReposKey"
)

type UserMetadataLocalStore struct {
	// xTODOx: not yet logging.
	rootDir string
	db      *bbolt.DB
	log     zlog.Logger
}

type UserMetadata struct {
	// data for each user.
	StarredRepos    []string
	BookmarkedRepos []string
}

//nolint:dupl
func (d *UserMetadataLocalStore) ToggleStarRepo(userid, reponame string) error { //nolint:dupl
	if err := d.db.Update(func(tx *bbolt.Tx) error {
		userdb := tx.Bucket([]byte(UserMetadataName))
		userBucket, err := userdb.CreateBucketIfNotExists([]byte(userid))
		if err != nil {
			// this is a serious failure
			return merrors.ErrUnableToCreateUserBucket
		}

		mdata := userBucket.Get([]byte(starredReposKey))
		unpacked := []string{}
		if mdata != nil {
			if err = json.Unmarshal(mdata, &unpacked); err != nil {
				return merrors.ErrInvalidOldUserStarredRepos
			}
		}

		if unpacked == nil {
			// should we panic now?
			return merrors.ErrUnmarshalledRepoListIsNil
		}

		if !common.Contains(unpacked, reponame) {
			unpacked = append(unpacked, reponame)
		} else {
			unpacked = common.RemoveFrom(unpacked, reponame)
		}

		var repacked []byte
		if repacked, err = json.Marshal(unpacked); err != nil {
			return merrors.ErrCouldNotMarshalStarredRepos
		}

		err = userBucket.Put([]byte(starredReposKey), repacked)
		if err != nil {
			return merrors.ErrCouldNotPersistData
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (d *UserMetadataLocalStore) GetStarredRepos(userid string) ([]string, error) {
	var starredRepos []string

	err := d.db.View(func(tx *bbolt.Tx) error { // nolint:dupl
		userdb := tx.Bucket([]byte(UserMetadataName))
		if userid == "" {
			starredRepos = []string{}

			return nil
		}

		userBucket := userdb.Bucket([]byte(userid))
		if userBucket == nil {
			return nil
		}

		mdata := userBucket.Get([]byte(starredReposKey))
		if mdata == nil {
			return nil
		}
		if err := json.Unmarshal(mdata, &starredRepos); err != nil {
			return merrors.ErrInvalidOldUserStarredRepos
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return starredRepos, nil
}

func (d *UserMetadataLocalStore) ToggleBookmarkRepo(userid, reponame string) error {
	if err := d.db.Update(func(tx *bbolt.Tx) error { // nolint:dupl
		userdb := tx.Bucket([]byte(UserMetadataName))
		userBucket, err := userdb.CreateBucketIfNotExists([]byte(userid))
		if err != nil {
			// this is a serious failure
			return merrors.ErrUnableToCreateUserBucket
		}

		mdata := userBucket.Get([]byte(bookmarkedReposKey))
		unpacked := []string{}
		if mdata != nil {
			if err = json.Unmarshal(mdata, &unpacked); err != nil {
				return merrors.ErrInvalidOldUserBookmarkedRepos
			}
		}

		if unpacked == nil {
			return merrors.ErrUnmarshalledRepoListIsNil
			// should we panic now?
		}

		if !common.Contains(unpacked, reponame) {
			unpacked = append(unpacked, reponame)
		} else {
			unpacked = common.RemoveFrom(unpacked, reponame)
		}

		var repacked []byte
		if repacked, err = json.Marshal(unpacked); err != nil {
			return merrors.ErrCouldNotMarshalBookmarkedRepos
		}

		err = userBucket.Put([]byte(bookmarkedReposKey), repacked)
		if err != nil {
			return merrors.ErrUnableToCreateUserBucket
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (d *UserMetadataLocalStore) GetBookmarkedRepos(userid string) ([]string, error) {
	var bookmarkedRepos []string

	err := d.db.View(func(tx *bbolt.Tx) error { // nolint:dupl
		userdb := tx.Bucket([]byte(UserMetadataName))
		if userid == "" {
			bookmarkedRepos = []string{}

			return nil
		}

		userBucket := userdb.Bucket([]byte(userid))
		if userBucket == nil {
			return nil
		}
		mdata := userBucket.Get([]byte(bookmarkedReposKey))
		if mdata == nil {
			return nil
		}
		if err := json.Unmarshal(mdata, &bookmarkedRepos); err != nil {
			return merrors.ErrInvalidOldUserBookmarkedRepos
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return bookmarkedRepos, nil
}

// Constructor for bbolt based drivers that implement UserMetadata.
func NewUserMetadataLocalStore(rootDir, storageName string, log zlog.Logger) UserStore {
	var metadataDB *bbolt.DB
	dbPath := path.Join(rootDir, storageName+DBExtensionName)
	dbOpts := &bbolt.Options{
		Timeout:      dbCacheLockCheckTimeout,
		FreelistType: bbolt.FreelistArrayType,
	}

	metadataDB, err := bbolt.Open(dbPath, 0o600, dbOpts) //nolint:gomnd
	if err != nil {
		log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create user db")

		return nil
	}

	if err := metadataDB.Update(func(tx *bbolt.Tx) error {
		var err error
		if _, err = tx.CreateBucketIfNotExists([]byte(UserMetadataName)); err != nil {
			// this is a serious failure.
			log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create USERS bucket")

			return err
		}

		return nil
	}); err != nil {
		// something went wrong
		log.Error().Err(err).Msg("unable to create a cache")

		return nil
	}

	return &UserMetadataLocalStore{
		rootDir: rootDir,
		db:      metadataDB,
		log:     log,
	}
}
