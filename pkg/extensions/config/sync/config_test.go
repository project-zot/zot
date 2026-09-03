package sync_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
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

func TestRegistryConfig_SyncTimeoutOrDefault(t *testing.T) {
	Convey("SyncTimeoutOrDefault", t, func() {
		Convey("returns default when unset", func() {
			So(syncconf.RegistryConfig{}.SyncTimeoutOrDefault(), ShouldEqual, syncConstants.DefaultSyncTimeout)
		})

		Convey("returns configured value", func() {
			cfg := syncconf.RegistryConfig{SyncTimeout: 2 * time.Hour}
			So(cfg.SyncTimeoutOrDefault(), ShouldEqual, 2*time.Hour)
		})
	})
}

func TestConfig_LargestSyncTimeout(t *testing.T) {
	Convey("LargestSyncTimeout", t, func() {
		Convey("returns default when sync is nil", func() {
			So((*syncconf.Config)(nil).LargestSyncTimeout(), ShouldEqual, syncConstants.DefaultSyncTimeout)
		})

		Convey("returns default when no registries are configured", func() {
			So((&syncconf.Config{}).LargestSyncTimeout(), ShouldEqual, syncConstants.DefaultSyncTimeout)
		})

		Convey("returns largest per-registry timeout with defaults applied", func() {
			cfg := &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{SyncTimeout: 2 * time.Hour},
					{},
					{SyncTimeout: 4 * time.Hour},
				},
			}

			So(cfg.LargestSyncTimeout(), ShouldEqual, 4*time.Hour)
		})
	})
}
