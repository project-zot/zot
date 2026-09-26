//go:build sync

package extensions_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

func newTestSyncExtensionDeps(t *testing.T) (storage.StoreController, *scheduler.Scheduler, log.Logger) {
	t.Helper()

	logger := log.NewTestLogger()

	imageStore := local.NewImageStore(t.TempDir(), false, false,
		logger, monitoring.NewNopMetricServer(), nil, nil, nil, nil)
	storeController := storage.StoreController{DefaultStore: imageStore}

	sch := scheduler.NewScheduler(config.New(), monitoring.NewNopMetricServer(), logger)

	return storeController, sch, logger
}

// TestEnableSyncExtensionSharesStreamManager: all registries, streaming or not, share one stream
// manager.
func TestEnableSyncExtensionSharesStreamManager(t *testing.T) {
	Convey("A streaming and a non-streaming registry share one stream manager", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://streaming-upstream.invalid"},
						OnDemand: true,
						Stream:   &stream,
						Content:  []syncconf.Content{{Prefix: "streamed/**"}},
					},
					{
						URLs:     []string{"https://plain-upstream.invalid"},
						OnDemand: true,
						Content:  []syncconf.Content{{Prefix: "plain/**"}},
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)

		// Streaming is decided per repo by content rules, but the manager is shared.
		So(onDemand.IsStreamingEnabledForRepo("streamed/foo"), ShouldBeTrue)
		So(onDemand.IsStreamingEnabledForRepo("plain/foo"), ShouldBeFalse)
		So(onDemand.StreamManager(), ShouldNotBeNil)
	})

	Convey("No streaming registry means no stream manager at all", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://plain-upstream.invalid"},
						OnDemand: true,
						Content:  []syncconf.Content{{Prefix: "plain/**"}},
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)

		// Not created when no registry streams, so no "_stream" directory appears.
		So(onDemand.StreamManager(), ShouldBeNil)
		So(onDemand.IsStreamingEnabledForRepo("plain/foo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionReusesStreamManager: a config reload keeps the previous stream manager,
// so streams staged before the reload stay reachable from the blob routes.
func TestEnableSyncExtensionReusesStreamManager(t *testing.T) {
	Convey("A reload that still streams reuses the previous stream manager", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://streaming-upstream.invalid"},
						OnDemand: true,
						Stream:   &stream,
						Content:  []syncconf.Content{{Prefix: "streamed/**"}},
					},
				},
			},
		}

		prev, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(prev.StreamManager(), ShouldNotBeNil)

		reloaded, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, prev, logger)
		So(err, ShouldBeNil)
		So(reloaded, ShouldNotEqual, prev)
		So(reloaded.StreamManager(), ShouldEqual, prev.StreamManager())
	})

	Convey("A previous SyncOnDemand without a stream manager gets a new one", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true

		plain := config.New()
		plain.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://plain-upstream.invalid"},
						OnDemand: true,
						Content:  []syncconf.Content{{Prefix: "plain/**"}},
					},
				},
			},
		}

		prev, err := extensions.EnableSyncExtension(plain, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(prev.StreamManager(), ShouldBeNil)

		streaming := config.New()
		streaming.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://streaming-upstream.invalid"},
						OnDemand: true,
						Stream:   &stream,
						Content:  []syncconf.Content{{Prefix: "streamed/**"}},
					},
				},
			},
		}

		reloaded, err := extensions.EnableSyncExtension(streaming, nil, storeController, sch, prev, logger)
		So(err, ShouldBeNil)
		So(reloaded.StreamManager(), ShouldNotBeNil)
	})

	Convey("A reload that turns streaming off keeps the previous stream manager", t, func() {
		// Its streams may still be draining for clients served before the reload; nothing new is
		// staged, since no registry streams.
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true

		streaming := config.New()
		streaming.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://streaming-upstream.invalid"},
						OnDemand: true,
						Stream:   &stream,
						Content:  []syncconf.Content{{Prefix: "streamed/**"}},
					},
				},
			},
		}

		prev, err := extensions.EnableSyncExtension(streaming, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(prev.StreamManager(), ShouldNotBeNil)

		plain := config.New()
		plain.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://streaming-upstream.invalid"},
						OnDemand: true,
						Content:  []syncconf.Content{{Prefix: "streamed/**"}},
					},
				},
			},
		}

		reloaded, err := extensions.EnableSyncExtension(plain, nil, storeController, sch, prev, logger)
		So(err, ShouldBeNil)
		So(reloaded, ShouldNotEqual, prev)
		So(reloaded.StreamManager(), ShouldEqual, prev.StreamManager())
		So(reloaded.IsStreamingEnabledForRepo("streamed/repo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionNoURLsLeft: a registry whose URLs are all filtered out as self-references
// is an error.
func TestEnableSyncExtensionNoURLsLeft(t *testing.T) {
	Convey("A registry whose every URL points at this server itself fails to start", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		conf := config.New()
		conf.HTTP.Address = "127.0.0.1"
		conf.HTTP.Port = "8080"
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs: []string{
							"http://127.0.0.1:8080/one",
							"http://127.0.0.1:8080/two",
						},
						OnDemand: true,
						Content:  []syncconf.Content{{Prefix: "**"}},
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldEqual, zerr.ErrSyncNoURLsLeft)
		So(onDemand, ShouldBeNil)
	})
}

// TestEnableSyncExtensionSkipsRegistryWithNeitherPeriodicalNorOnDemand: such a registry is skipped,
// not an error.
func TestEnableSyncExtensionSkipsRegistryWithNeitherPeriodicalNorOnDemand(t *testing.T) {
	Convey("A registry with neither OnDemand nor a poll interval is skipped", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:    []string{"https://skipped-upstream.invalid"},
						Content: []syncconf.Content{{Prefix: "skipped/**"}},
						// Neither OnDemand nor PollInterval, so no service is built.
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)

		// Skipped, so it never registered with onDemand and can't be streaming.
		So(onDemand.IsStreamingEnabledForRepo("skipped/foo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionPeriodicalRegistration: a registry with Content and a PollInterval is
// scheduled for periodic sync.
func TestEnableSyncExtensionPeriodicalRegistration(t *testing.T) {
	Convey("A registry with Content and a poll interval is scheduled periodically", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:         []string{"https://periodical-upstream.invalid"},
						Content:      []syncconf.Content{{Prefix: "periodical/**"}},
						PollInterval: time.Hour,
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)

		// Periodic only, so not added to onDemand.
		So(onDemand.IsStreamingEnabledForRepo("periodical/foo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionMaxConcurrentStreamsOverride: an explicit MaxConcurrentStreams sizes the
// shared stream manager.
func TestEnableSyncExtensionMaxConcurrentStreamsOverride(t *testing.T) {
	Convey("MaxConcurrentStreams on the first streaming registry configures the shared stream manager", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true
		maxStreams := 7

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:                 []string{"https://streaming-upstream.invalid"},
						OnDemand:             true,
						Stream:               &stream,
						MaxConcurrentStreams: &maxStreams,
						Content:              []syncconf.Content{{Prefix: "streamed/**"}},
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)
		So(onDemand.StreamManager(), ShouldNotBeNil)
	})
}

// TestEnableSyncExtensionReloadResizesStreamCap: a reload applies the new maxConcurrentStreams to
// the reused stream manager, but a reload that fails leaves the live manager's cap alone, since the
// controller keeps the previous SyncOnDemand.
func TestEnableSyncExtensionReloadResizesStreamCap(t *testing.T) {
	Convey("Reloading the stream cap", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true

		streamingConfig := func(maxStreams int, extra ...syncconf.RegistryConfig) *config.Config {
			conf := config.New()
			conf.Extensions = &extconf.ExtensionConfig{
				Sync: &syncconf.Config{
					Registries: append([]syncconf.RegistryConfig{{
						URLs:                 []string{"https://streaming-upstream.invalid"},
						OnDemand:             true,
						Stream:               &stream,
						MaxConcurrentStreams: &maxStreams,
						Content:              []syncconf.Content{{Prefix: "streamed/**"}},
					}}, extra...),
				},
			}

			return conf
		}

		prev, err := extensions.EnableSyncExtension(streamingConfig(5), nil, storeController, sch, nil, logger)
		So(err, ShouldBeNil)

		manager, ok := prev.StreamManager().(*sync.ChunkingStreamManager)
		So(ok, ShouldBeTrue)
		So(manager.MaxConcurrentStreams(), ShouldEqual, 5)

		Convey("a failed reload keeps the old cap", func() {
			badCertDir := filepath.Join(t.TempDir(), "not-a-dir")
			require.NoError(t, os.WriteFile(badCertDir, []byte("not a directory"), 0o600))

			// The streaming registry comes first, so the manager is reused before the failure.
			_, err := extensions.EnableSyncExtension(streamingConfig(9, syncconf.RegistryConfig{
				URLs:     []string{"https://upstream.invalid"},
				OnDemand: true,
				CertDir:  badCertDir,
				Content:  []syncconf.Content{{Prefix: "other/**"}},
			}), nil, storeController, sch, prev, logger)
			So(err, ShouldNotBeNil)
			So(manager.MaxConcurrentStreams(), ShouldEqual, 5)
		})

		Convey("a successful reload applies the new cap", func() {
			reloaded, err := extensions.EnableSyncExtension(streamingConfig(9), nil, storeController, sch, prev, logger)
			So(err, ShouldBeNil)
			So(reloaded.StreamManager(), ShouldEqual, manager)
			So(manager.MaxConcurrentStreams(), ShouldEqual, 9)
		})
	})
}

// TestEnableSyncExtensionServiceInitFailure: sync.New failing (CertDir is a file, not a directory)
// fails EnableSyncExtension.
func TestEnableSyncExtensionServiceInitFailure(t *testing.T) {
	Convey("A registry whose service fails to initialize aborts EnableSyncExtension", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		badCertDir := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(badCertDir, []byte("not a directory"), 0o600))

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:     []string{"https://upstream.invalid"},
						OnDemand: true,
						CertDir:  badCertDir,
						Content:  []syncconf.Content{{Prefix: "**"}},
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, nil, logger)
		So(err, ShouldNotBeNil)
		So(onDemand, ShouldBeNil)
	})
}
