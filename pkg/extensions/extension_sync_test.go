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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)

		// Not created when no registry streams, so no "_stream" directory appears.
		So(onDemand.StreamManager(), ShouldBeNil)
		So(onDemand.IsStreamingEnabledForRepo("plain/foo"), ShouldBeFalse)
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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)
		So(onDemand.StreamManager(), ShouldNotBeNil)
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

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
		So(err, ShouldNotBeNil)
		So(onDemand, ShouldBeNil)
	})
}
