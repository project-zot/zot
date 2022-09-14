package userdb

import (
	"encoding/json"
	"path"
	"time"

	"go.etcd.io/bbolt"

	"zotregistry.io/zot/pkg/common"
	zlog "zotregistry.io/zot/pkg/log"
	msConfig "zotregistry.io/zot/pkg/meta/config"
	merrors "zotregistry.io/zot/pkg/meta/errors"
	"zotregistry.io/zot/pkg/test"
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

type UserStore interface {
	GetStarredRepos(userid string) ([]string, error)
	GetBookmarkedRepos(userid string) ([]string, error)
	ToggleStarRepo(userid, reponame string) (msConfig.UserState, error)
	ToggleBookmarkRepo(userid, reponame string) (msConfig.UserState, error)
}

type UserMetadataLocalStore struct {
	// xTODOx: not yet logging.
	userMetaConfig msConfig.UserMetadataStoreConfig
	db             *bbolt.DB
	log            zlog.Logger
}

type UserMetadata struct {
	// data for each user.
	StarredRepos    []string
	BookmarkedRepos []string
}

type UserMetadataEmptyStore struct{}

//nolint:dupl
func (d *UserMetadataLocalStore) ToggleStarRepo(userid, reponame string) (
	msConfig.UserState, error,
) { //nolint:dupl
	var res msConfig.UserState

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
			res = msConfig.Added
			unpacked = append(unpacked, reponame)
		} else {
			unpacked = common.RemoveFrom(unpacked, reponame)
			res = msConfig.Removed
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
		return msConfig.NotChanged, err
	}

	return res, nil
}

func (d *UserMetadataLocalStore) GetStarredRepos(userid string) ([]string, error) {
	starredRepos := make([]string, 0)

	err := d.db.View(func(tx *bbolt.Tx) error { //nolint:dupl
		if userid == "" {
			return nil
		}

		userdb := tx.Bucket([]byte(UserMetadataName))
		userBucket := userdb.Bucket([]byte(userid))

		if userBucket == nil {
			return nil
		}

		mdata := userBucket.Get([]byte(starredReposKey))
		if mdata == nil {
			return nil
		}

		if err := json.Unmarshal(mdata, &starredRepos); err != nil {
			d.log.Info().Str("user", userid).Err(err).Msg("unmarshal error")

			return merrors.ErrInvalidOldUserStarredRepos
		}

		if starredRepos == nil {
			starredRepos = make([]string, 0)
		}

		return nil
	})

	return starredRepos, err
}

func (d *UserMetadataLocalStore) ToggleBookmarkRepo(userid, reponame string) ( //nolint:dupl
	msConfig.UserState, error,
) {
	var res msConfig.UserState

	if err := d.db.Update(func(tx *bbolt.Tx) error { //nolint:dupl
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
			res = msConfig.Added
			unpacked = append(unpacked, reponame)
		} else {
			unpacked = common.RemoveFrom(unpacked, reponame)
			res = msConfig.Removed
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
		return msConfig.NotChanged, err
	}

	return res, nil
}

func (d *UserMetadataLocalStore) GetBookmarkedRepos(userid string) ([]string, error) {
	bookmarkedRepos := []string{}

	err := d.db.View(func(tx *bbolt.Tx) error { //nolint:dupl
		if userid == "" {
			return nil
		}

		userdb := tx.Bucket([]byte(UserMetadataName))
		userBucket := userdb.Bucket([]byte(userid))

		if userBucket == nil {
			return nil
		}

		mdata := userBucket.Get([]byte(bookmarkedReposKey))
		if mdata == nil {
			return nil
		}

		if err := json.Unmarshal(mdata, &bookmarkedRepos); err != nil {
			d.log.Info().Str("user", userid).Err(err).Msg("unmarshal error")

			return merrors.ErrInvalidOldUserBookmarkedRepos
		}

		if bookmarkedRepos == nil {
			bookmarkedRepos = make([]string, 0)
		}

		return nil
	})

	return bookmarkedRepos, err
}

func FactoryUserMetadataStore(
	umsc *msConfig.UserMetadataStoreConfig, log zlog.Logger,
) (UserStore, error) {
	emptyStore := &UserMetadataEmptyStore{}

	if umsc != nil {
		if umsc.Enabled == nil {
			defaultEnabled := true
			umsc.Enabled = &defaultEnabled

			return emptyStore, nil
		}

		if umsc.Driver == msConfig.UserMetadataLocalDriver {
			return NewUserMetadataLocalStore(umsc, msConfig.UserMetadataLocalFile, log)
		} // else: unsupported driver!
	}

	return emptyStore, nil
}

// Constructor for bbolt based drivers that implement UserMetadata.
func NewUserMetadataLocalStore(umsc *msConfig.UserMetadataStoreConfig,
	storageName string, log zlog.Logger,
) (UserStore, error) {
	var (
		metadataDB *bbolt.DB
		err        error
	)

	dbPath := path.Join(umsc.RootDir, storageName+DBExtensionName)
	dbOpts := &bbolt.Options{
		Timeout:      dbCacheLockCheckTimeout,
		FreelistType: bbolt.FreelistArrayType,
	}

	metadataDB, err = bbolt.Open(dbPath, 0o600, dbOpts) //nolint:gomnd
	if err != nil {
		log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create user db")

		return nil, err
	}

	// log outside the clojure
	err = metadataDB.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(UserMetadataName))

		return err
	})

	err = test.Error(err)
	if err != nil {
		// something went wrong
		log.Error().Err(err).Msg("unable to create a cache")

		return nil, err
	}

	return &UserMetadataLocalStore{
		userMetaConfig: *umsc,
		db:             metadataDB,
		log:            log,
	}, err
}

func (umes *UserMetadataEmptyStore) ToggleBookmarkRepo(userid, reponame string) (msConfig.UserState, error) {
	return msConfig.NotChanged, nil
}

func (umes *UserMetadataEmptyStore) GetBookmarkedRepos(userid string) ([]string, error) {
	return []string{}, nil
}

func (umes *UserMetadataEmptyStore) ToggleStarRepo(userid, reponame string) (msConfig.UserState, error) {
	return msConfig.NotChanged, nil
}

func (umes *UserMetadataEmptyStore) GetStarredRepos(userid string) ([]string, error) {
	return []string{}, nil
}
