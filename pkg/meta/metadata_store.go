package meta

import (
	zlog "zotregistry.io/zot/pkg/log"
	msConfig "zotregistry.io/zot/pkg/meta/config"
	"zotregistry.io/zot/pkg/meta/userdb"
)

type MetadataStore struct {
	userDB userdb.UserStore
}

type RepoDB interface {
	RepoDB()
}

func FactoryBaseMetaDB(msc msConfig.MetadataStoreConfig, log zlog.Logger) (MetadataStore, error) {
	var (
		userdata userdb.UserStore
		err      error
	)

	emptyStore := &userdb.UserMetadataEmptyStore{}

	if msc.User != nil {
		userdata, err = userdb.FactoryUserMetadataStore(msc.User, log)
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
