package sync_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

func TestRegistryConfig_ShouldSyncLegacyCosignTags(t *testing.T) {
	Convey("ShouldSyncLegacyCosignTags", t, func() {
		Convey("returns true when SyncLegacyCosignTags is nil (default)", func() {
			cfg := syncconf.RegistryConfig{}
			So(cfg.SyncLegacyCosignTags, ShouldBeNil)
			So(cfg.ShouldSyncLegacyCosignTags(), ShouldBeTrue)
		})

		Convey("returns true when SyncLegacyCosignTags is true", func() {
			v := true
			cfg := syncconf.RegistryConfig{SyncLegacyCosignTags: &v}
			So(cfg.ShouldSyncLegacyCosignTags(), ShouldBeTrue)
		})

		Convey("returns false when SyncLegacyCosignTags is false", func() {
			v := false
			cfg := syncconf.RegistryConfig{SyncLegacyCosignTags: &v}
			So(cfg.ShouldSyncLegacyCosignTags(), ShouldBeFalse)
		})
	})
}

func TestRegistryConfig_ShouldSyncReferrersRecursively(t *testing.T) {
	Convey("ShouldSyncReferrersRecursively", t, func() {
		Convey("returns true when SyncReferrersRecursive is nil (default)", func() {
			cfg := syncconf.RegistryConfig{}
			So(cfg.SyncReferrersRecursive, ShouldBeNil)
			So(cfg.ShouldSyncReferrersRecursively(), ShouldBeTrue)
		})

		Convey("returns true when SyncReferrersRecursive is true", func() {
			v := true
			cfg := syncconf.RegistryConfig{SyncReferrersRecursive: &v}
			So(cfg.ShouldSyncReferrersRecursively(), ShouldBeTrue)
		})

		Convey("returns false when SyncReferrersRecursive is false", func() {
			v := false
			cfg := syncconf.RegistryConfig{SyncReferrersRecursive: &v}
			So(cfg.ShouldSyncReferrersRecursively(), ShouldBeFalse)
		})
	})
}
