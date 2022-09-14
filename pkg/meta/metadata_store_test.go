package meta_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/meta"
	msConfig "zotregistry.io/zot/pkg/meta/config"
)

func TestGetEmptyUser(t *testing.T) {
	Convey("Retrieve starred repos for empty user", t, func() {
		t.Helper()

		srcConfig := config.New()
		srcConfig.Storage.RootDirectory = t.TempDir()
		sctlr := api.NewController(srcConfig)
		enabled := true
		mstore, err := meta.FactoryBaseMetaDB(msConfig.MetadataStoreConfig{
			User: &msConfig.UserMetadataStoreConfig{
				RootDir: srcConfig.Storage.RootDirectory,
				Driver:  "local",
				Enabled: &enabled,
			},
		}, sctlr.Log)

		sctlr.MetaStore = &mstore
		So(err, ShouldBeNil)

		srepos, err := sctlr.MetaStore.GetStarredRepos("")
		So(srepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		brepos, err := sctlr.MetaStore.GetBookmarkedRepos("")
		So(brepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		srepos, err = sctlr.MetaStore.GetStarredRepos("user")
		So(srepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		brepos, err = sctlr.MetaStore.GetBookmarkedRepos("user")
		So(brepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		res, err := sctlr.MetaStore.ToggleStarRepo("user", "super-repo")
		So(res, ShouldEqual, 1)
		So(err, ShouldEqual, nil)

		res, err = sctlr.MetaStore.ToggleBookmarkRepo("user", "super-repo")
		So(res, ShouldEqual, 1)
		So(err, ShouldEqual, nil)
	})
}

func TestMetadataConfigNegative(t *testing.T) {
	Convey("Cannot create User metadata - config driver does not exist", t, func() {
		t.Helper()

		srcConfig := config.New()
		srcConfig.Storage.RootDirectory = t.TempDir()
		sctlr := api.NewController(srcConfig)
		enabled := true
		mstore, err := meta.FactoryBaseMetaDB(msConfig.MetadataStoreConfig{
			User: &msConfig.UserMetadataStoreConfig{
				RootDir: srcConfig.Storage.RootDirectory,
				Driver:  "DOES_NOT_EXIST!",
				Enabled: &enabled,
			},
		}, sctlr.Log)

		sctlr.MetaStore = &mstore
		So(err, ShouldBeNil)
		srepos, err := sctlr.MetaStore.GetStarredRepos("")
		So(srepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		brepos, err := sctlr.MetaStore.GetBookmarkedRepos("")
		So(brepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		unchangedState, err := sctlr.MetaStore.ToggleStarRepo("", "")
		So(unchangedState, ShouldEqual, 0)
		So(err, ShouldBeNil)

		unchangedState, err = sctlr.MetaStore.ToggleBookmarkRepo("", "")
		So(unchangedState, ShouldEqual, 0)
		So(err, ShouldBeNil)
	})

	Convey("Cannot create User metadata - no permission to write data to config dir", t, func() {
		t.Helper()

		srcConfig := config.New()
		srcConfig.Storage.RootDirectory = "/proc/cannotbe/created"
		sctlr := api.NewController(srcConfig)
		enabled := true
		mstore, err := meta.FactoryBaseMetaDB(msConfig.MetadataStoreConfig{
			User: &msConfig.UserMetadataStoreConfig{
				RootDir: srcConfig.Storage.RootDirectory,
				Driver:  "local",
				Enabled: &enabled,
			},
		}, sctlr.Log)

		sctlr.MetaStore = &mstore
		So(err, ShouldNotBeNil)
		brepos, err := sctlr.MetaStore.GetStarredRepos("")
		So(brepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		srepos, err := sctlr.MetaStore.GetBookmarkedRepos("")
		So(srepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		unchangedState, err := sctlr.MetaStore.ToggleStarRepo("", "")
		So(unchangedState, ShouldEqual, 0)
		So(err, ShouldBeNil)

		unchangedState, err = sctlr.MetaStore.ToggleBookmarkRepo("", "")
		So(unchangedState, ShouldEqual, 0)
		So(err, ShouldBeNil)
	})
}
