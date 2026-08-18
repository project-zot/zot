package sync_test

import (
	"testing"
	"time"

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

func TestRegistryConfig_ManifestCheckInterval(t *testing.T) {
	Convey("ManifestCheckInterval", t, func() {
		Convey("defaults to zero, which keeps checking upstream on every request", func() {
			cfg := syncconf.RegistryConfig{}
			So(cfg.ManifestCheckInterval, ShouldEqual, time.Duration(0))
		})

		Convey("holds the configured duration", func() {
			cfg := syncconf.RegistryConfig{ManifestCheckInterval: 10 * time.Minute}
			So(cfg.ManifestCheckInterval, ShouldEqual, 10*time.Minute)
		})
	})
}
