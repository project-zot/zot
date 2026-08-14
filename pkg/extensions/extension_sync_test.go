//go:build sync

package extensions_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestEnableSyncExtension_StreamManager(t *testing.T) {
	Convey("EnableSyncExtension stream manager setup", t, func() {
		logger := log.NewTestLogger()
		cfg := config.New()
		cfg.Storage.RootDirectory = t.TempDir()

		metaDB := mocks.MetaDBMock{}
		storeController := storage.StoreController{}
		metrics := monitoring.NewMetricsServer(false, logger)
		t.Cleanup(metrics.Stop)
		sch := scheduler.NewScheduler(cfg, metrics, logger)

		Convey("stream manager is nil when Stream is not set on any registry", func() {
			cfg.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Registries: []syncconf.RegistryConfig{
						{
							URLs:     []string{"http://localhost:5000"},
							OnDemand: true,
						},
					},
				},
			}

			onDemand, err := extensions.EnableSyncExtension(cfg, metaDB, storeController, sch, logger)
			So(err, ShouldBeNil)
			So(onDemand, ShouldNotBeNil)
			So(onDemand.StreamManager(), ShouldBeNil)
		})

		Convey("stream manager is nil when streaming is explicitly disabled on all registries", func() {
			streamDisabled := false

			cfg.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Registries: []syncconf.RegistryConfig{
						{
							URLs:     []string{"http://localhost:5000"},
							OnDemand: true,
							Stream:   &streamDisabled,
						},
					},
				},
			}

			onDemand, err := extensions.EnableSyncExtension(cfg, metaDB, storeController, sch, logger)
			So(err, ShouldBeNil)
			So(onDemand, ShouldNotBeNil)
			So(onDemand.StreamManager(), ShouldBeNil)
		})

		Convey("stream manager is set when a registry has streaming enabled", func() {
			streamEnabled := true

			cfg.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Registries: []syncconf.RegistryConfig{
						{
							URLs:     []string{"http://localhost:5000"},
							OnDemand: true,
							Stream:   &streamEnabled,
						},
					},
				},
			}

			onDemand, err := extensions.EnableSyncExtension(cfg, metaDB, storeController, sch, logger)
			So(err, ShouldBeNil)
			So(onDemand, ShouldNotBeNil)
			So(onDemand.StreamManager(), ShouldNotBeNil)
		})

		Convey("stream manager is set when only one of multiple registries has streaming enabled", func() {
			streamEnabled := true
			streamDisabled := false

			cfg.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Registries: []syncconf.RegistryConfig{
						{
							URLs:     []string{"http://localhost:5000"},
							OnDemand: true,
							Stream:   &streamDisabled,
						},
						{
							URLs:     []string{"http://localhost:5001"},
							OnDemand: true,
							Stream:   &streamEnabled,
						},
					},
				},
			}

			onDemand, err := extensions.EnableSyncExtension(cfg, metaDB, storeController, sch, logger)
			So(err, ShouldBeNil)
			So(onDemand, ShouldNotBeNil)
			So(onDemand.StreamManager(), ShouldNotBeNil)
		})

		Convey("stream manager is set with mix of polling and on-demand with streaming enabled", func() {
			streamEnabled := true

			cfg.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Registries: []syncconf.RegistryConfig{
						{
							URLs:         []string{"http://localhost:5000"},
							PollInterval: 60,
						},
						{
							URLs:     []string{"http://localhost:5001"},
							OnDemand: true,
							Stream:   &streamEnabled,
						},
					},
				},
			}

			onDemand, err := extensions.EnableSyncExtension(cfg, metaDB, storeController, sch, logger)
			So(err, ShouldBeNil)
			So(onDemand, ShouldNotBeNil)
			So(onDemand.StreamManager(), ShouldNotBeNil)
		})

		Convey("returns nil onDemand when sync is disabled", func() {
			syncDisabled := false

			cfg.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Enable: &syncDisabled,
					Registries: []syncconf.RegistryConfig{
						{
							URLs:     []string{"http://localhost:5000"},
							OnDemand: true,
						},
					},
				},
			}

			onDemand, err := extensions.EnableSyncExtension(cfg, metaDB, storeController, sch, logger)
			So(err, ShouldBeNil)
			So(onDemand, ShouldBeNil)
		})
	})
}
