package metadata

import (
	zlog "zotregistry.io/zot/pkg/log"
	msConfig "zotregistry.io/zot/pkg/metadata/config"
)

type Store interface {
	UserStore
	RepoDB
}

type StoreLocal struct {
	config msConfig.MetadataStoreConfig
	userDB UserStore
	repoDB RepoDB
}

type UserStore interface {
	GetStarredRepos(userid string) ([]string, error)
	GetBookmarkedRepos(userid string) ([]string, error)
	ToggleStarRepo(userid, reponame string) error
	ToggleBookmarkRepo(userid, reponame string) error
}

type RepoDB interface {
	RepoDB()
}

func NewBaseMetaDB(msc msConfig.MetadataStoreConfig, log zlog.Logger) (Store, error) {
	return StoreLocal{
		config: msc,
		userDB: NewUserMetadataLocalStore(msc.RootDir, "storageName", log),
		repoDB: BaseRepoDB{},
	}, nil
}

func (m StoreLocal) ToggleStarRepo(userid, reponame string) error {
	return m.userDB.ToggleStarRepo(userid, reponame)
}

func (m StoreLocal) GetStarredRepos(userid string) ([]string, error) {
	return m.userDB.GetStarredRepos(userid)
}

func (m StoreLocal) ToggleBookmarkRepo(userid, reponame string) error {
	return m.userDB.ToggleBookmarkRepo(userid, reponame)
}

func (m StoreLocal) GetBookmarkedRepos(userid string) ([]string, error) {
	return m.userDB.GetBookmarkedRepos(userid)
}

func (m StoreLocal) RepoDB() {
	m.repoDB.RepoDB()
}

type BaseRepoDB struct{}

func (bo BaseRepoDB) RepoDB() {}
