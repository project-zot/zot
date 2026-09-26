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

// TestEnableSyncExtensionSharesStreamManager is the regression test for the shared-stream-manager
// behavior EnableSyncExtension implements (see its doc comment): the concurrent-stream cap and
// active-stream bookkeeping are properties of a single manager shared by every streaming-enabled
// registry, not built per-registry - and every registry, streaming-enabled or not, is wired to
// the same instance once one exists. This was previously only ever exercised indirectly (via
// starting a full HTTP server in pkg/cli/server's TestServeSyncExtension), never directly.
func TestEnableSyncExtensionSharesStreamManager(t *testing.T) {
	Convey("A streaming and a non-streaming registry share one stream manager", t, func() {
		storeController, sch, logger := newTestSyncExtensionDeps(t)

		stream := true

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				Registries: []syncconf.RegistryConfig{
					{
						URLs:           []string{"https://streaming-upstream.invalid"},
						OnDemand:       true,
						PreserveDigest: true,
						Stream:         &stream,
						Content:        []syncconf.Content{{Prefix: "streamed/**"}},
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

		// IsStreamingEnabledForRepo is per-repo (routed via each registry's own content rules),
		// but the manager instance backing it is the single shared one.
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

		// Left nil rather than eagerly constructed, so a config with no streaming registries
		// never creates the "_stream" staging directory (see StreamManager's doc comment).
		So(onDemand.StreamManager(), ShouldBeNil)
		So(onDemand.IsStreamingEnabledForRepo("plain/foo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionNoURLsLeft covers the error path where a multi-URL registry has every
// URL filtered out as a self-reference by removeSelfURLs, leaving EnableSyncExtension nothing to
// sync against.
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

// TestEnableSyncExtensionSkipsRegistryWithNeitherPeriodicalNorOnDemand covers a registry entry
// that is neither on-demand nor periodical (no PollInterval set alongside its Content), which
// EnableSyncExtension must silently skip rather than treat as an error.
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
						// OnDemand left false and PollInterval left zero: isPeriodical and
						// isOnDemand are both false, so this registry's service is never built.
					},
				},
			},
		}

		onDemand, err := extensions.EnableSyncExtension(conf, nil, storeController, sch, logger)
		So(err, ShouldBeNil)
		So(onDemand, ShouldNotBeNil)

		// No service was ever registered with onDemand for this registry, so it cannot be
		// streaming-enabled - the only externally observable effect of it being skipped.
		So(onDemand.IsStreamingEnabledForRepo("skipped/foo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionPeriodicalRegistration covers the periodical branch, where a registry
// with Content and a nonzero PollInterval is submitted to the task scheduler as a generator
// instead of (or in addition to) being added to onDemand.
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

		// Never added to onDemand: it's periodical only, not on-demand.
		So(onDemand.IsStreamingEnabledForRepo("periodical/foo"), ShouldBeFalse)
	})
}

// TestEnableSyncExtensionMaxConcurrentStreamsOverride covers the branch that reads a streaming
// registry's MaxConcurrentStreams pointer to size the shared stream manager, instead of falling
// back to its built-in default.
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

// TestEnableSyncExtensionServiceInitFailure covers the error path where a registry's sync.New
// fails to initialize (here, because CertDir points at a plain file rather than a directory, so
// loading its certificates errors out instead of just finding nothing).
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
