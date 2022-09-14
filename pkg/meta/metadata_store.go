package meta

import (
	zlog "zotregistry.io/zot/pkg/log"
	msConfig "zotregistry.io/zot/pkg/meta/config"
)

type MetadataStore struct {
	userDB UserStore
}

type UserStore interface {
	GetStarredRepos(userid string) ([]string, error)
	GetBookmarkedRepos(userid string) ([]string, error)
	ToggleStarRepo(userid, reponame string) (msConfig.UserState, error)
	ToggleBookmarkRepo(userid, reponame string) (msConfig.UserState, error)
}

type RepoDB interface {
	RepoDB()
}

func NewBaseMetaDB(msc msConfig.MetadataStoreConfig, log zlog.Logger) (MetadataStore, error) {
	var (
		userdata UserStore
		err      error
	)

	emptyStore := &UserMetadataEmptyStore{}

	if msc.User != nil {
		userdata, err = FactoryUserMetadataStore(msc.User, log)
	}

	if err != nil {
		return MetadataStore{
			userDB: emptyStore,
		}, err
	}

	return MetadataStore{
		// config: msc,
		userDB: userdata,
	}, nil
}

func (m MetadataStore) GetBookmarkedRepos(userid string) ([]string, error) {
	return m.userDB.GetBookmarkedRepos(userid)
}

func (m MetadataStore) ToggleStarRepo(userid, reponame string) (msConfig.UserState, error) {
	return m.userDB.ToggleStarRepo(userid, reponame)
}

func (m MetadataStore) GetStarredRepos(userid string) ([]string, error) {
	return m.userDB.GetStarredRepos(userid)
}

func (m MetadataStore) ToggleBookmarkRepo(userid, reponame string) (msConfig.UserState, error) {
	return m.userDB.ToggleBookmarkRepo(userid, reponame)
}
