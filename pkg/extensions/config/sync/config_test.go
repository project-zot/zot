package sync_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

func TestRegistryConfig_IsStreamEnabled(t *testing.T) {
	Convey("IsStreamEnabled", t, func() {
		Convey("returns false when Stream is nil (default)", func() {
			cfg := syncconf.RegistryConfig{}
			So(cfg.Stream, ShouldBeNil)
			So(cfg.IsStreamEnabled(), ShouldBeFalse)
		})

		Convey("returns true when Stream is true", func() {
			v := true
			cfg := syncconf.RegistryConfig{Stream: &v}
			So(cfg.IsStreamEnabled(), ShouldBeTrue)
		})

		Convey("returns false when Stream is false", func() {
			v := false
			cfg := syncconf.RegistryConfig{Stream: &v}
			So(cfg.IsStreamEnabled(), ShouldBeFalse)
		})
	})
}

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
