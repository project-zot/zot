package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

type timingStep struct {
	Calls   int     `json:"calls"`
	Seconds float64 `json:"seconds"`
}

type timingEvent struct {
	Message    string                `json:"msg"`
	Operation  string                `json:"operation"`
	Repository string                `json:"repository"`
	Found      bool                  `json:"found"`
	Size       int64                 `json:"size"`
	Processed  int                   `json:"processed_repositories"`
	LockWait   int64                 `json:"lock_wait"`
	LockHold   int64                 `json:"lock_hold"`
	Duration   int64                 `json:"duration"`
	Steps      map[string]timingStep `json:"steps"`
}

func timingEvents(t *testing.T, output *bytes.Buffer, message string) []timingEvent {
	t.Helper()

	events := []timingEvent{}

	for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}

		var event timingEvent

		So(json.Unmarshal(line, &event), ShouldBeNil)

		if event.Message == message {
			events = append(events, event)
		}
	}

	return events
}

func newTimingLogger(output *bytes.Buffer) zlog.Logger {
	return zlog.Logger{Logger: slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
}

func TestCheckBlobTiming(t *testing.T) {
	Convey("CheckBlob logs the time spent in each step", t, func() {
		ctx := context.Background()
		content := []byte("timing-blob")
		digest := godigest.FromBytes(content)

		Convey("without dedupe the read lock is timed", func() {
			var output bytes.Buffer

			imgStore := local.NewImageStore(t.TempDir(), false, false, newTimingLogger(&output),
				monitoring.NewNopMetricServer(), nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			_, _, err := imgStore.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, size, err := imgStore.CheckBlob(ctx, "repo", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			events := timingEvents(t, &output, "blob check completed")
			So(events, ShouldHaveLength, 1)
			So(events[0].Found, ShouldBeTrue)
			So(events[0].Size, ShouldEqual, len(content))
			So(events[0].Duration, ShouldBeGreaterThan, 0)

			for _, step := range []string{"read_lock_wait", "read_lock_hold", "stat", "descriptor_lookup"} {
				So(events[0].Steps[step].Calls, ShouldEqual, 1)
			}

			So(events[0].Steps, ShouldNotContainKey, "write_lock_wait")
			So(events[0].Steps, ShouldNotContainKey, "cache_lookup")
		})

		Convey("a missing blob is logged with its error", func() {
			var output bytes.Buffer

			imgStore := local.NewImageStore(t.TempDir(), false, false, newTimingLogger(&output),
				monitoring.NewNopMetricServer(), nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			found, _, err := imgStore.CheckBlob(ctx, "repo", digest)
			So(err, ShouldNotBeNil)
			So(found, ShouldBeFalse)

			events := timingEvents(t, &output, "blob check completed")
			So(events, ShouldHaveLength, 1)
			So(events[0].Found, ShouldBeFalse)
			So(events[0].Steps["stat"].Calls, ShouldEqual, 1)
			So(events[0].Steps["read_lock_hold"].Calls, ShouldEqual, 1)
		})

		Convey("with dedupe the write lock and the cache copy are timed", func() {
			var output bytes.Buffer

			dir := t.TempDir()
			log := newTimingLogger(&output)

			cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)
			So(err, ShouldBeNil)

			imgStore := local.NewImageStore(dir, true, true, log, monitoring.NewNopMetricServer(), nil,
				cacheDriver, nil, nil)
			So(imgStore.InitRepo(ctx, "repo1"), ShouldBeNil)

			_, _, err = imgStore.FullBlobUpload(ctx, "repo1", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, size, err := imgStore.CheckBlob(ctx, "repo2", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			events := timingEvents(t, &output, "blob check completed")
			So(events, ShouldHaveLength, 1)

			for _, step := range []string{
				"write_lock_wait", "write_lock_hold", "stat", "cache_lookup", "copy_blob", "cache_put",
			} {
				So(events[0].Steps[step].Calls, ShouldEqual, 1)
			}

			So(events[0].Steps, ShouldNotContainKey, "read_lock_wait")
		})

		Convey("nothing is logged when debug logging is disabled", func() {
			var output bytes.Buffer

			logger := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))}

			imgStore := local.NewImageStore(t.TempDir(), false, false, logger,
				monitoring.NewNopMetricServer(), nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			_, _, err := imgStore.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, size, err := imgStore.CheckBlob(ctx, "repo", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			repo, err := imgStore.GetNextRepository(map[string]struct{}{})
			So(err, ShouldBeNil)
			So(repo, ShouldEqual, "repo")

			So(output.Len(), ShouldEqual, 0)
		})

		Convey("an invalid digest is rejected before any timing", func() {
			var output bytes.Buffer

			imgStore := local.NewImageStore(t.TempDir(), false, false, newTimingLogger(&output),
				monitoring.NewNopMetricServer(), nil, nil, nil, nil)

			_, _, err := imgStore.CheckBlob(ctx, "repo", godigest.Digest("invalid"))
			So(err, ShouldNotBeNil)
			So(timingEvents(t, &output, "blob check completed"), ShouldBeEmpty)
		})
	})
}

func TestGetNextRepositoryTiming(t *testing.T) {
	Convey("GetNextRepository logs the lock wait and hold", t, func() {
		var output bytes.Buffer

		imgStore := local.NewImageStore(t.TempDir(), false, false, newTimingLogger(&output),
			monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		So(imgStore.InitRepo(context.Background(), "repo"), ShouldBeNil)

		held := make(chan struct{})
		released := make(chan struct{})

		var releasedAt time.Time

		go func() {
			defer close(released)

			_ = imgStore.WithBlobstoreLock(func() error {
				close(held)
				time.Sleep(30 * time.Millisecond)
				releasedAt = time.Now()

				return nil
			})
		}()

		<-held

		repo, err := imgStore.GetNextRepository(map[string]struct{}{"done": {}})
		finished := time.Now()

		<-released

		So(err, ShouldBeNil)
		So(repo, ShouldEqual, "repo")

		events := timingEvents(t, &output, "repository scan completed")
		So(events, ShouldHaveLength, 1)
		So(events[0].Operation, ShouldEqual, "GetNextRepository")
		So(events[0].Repository, ShouldEqual, "repo")
		So(events[0].Processed, ShouldEqual, 1)
		So(finished.Before(releasedAt), ShouldBeFalse)
		So(events[0].LockWait, ShouldBeGreaterThan, 0)
		So(events[0].LockHold, ShouldBeGreaterThan, 0)
		So(events[0].LockWait+events[0].LockHold, ShouldBeLessThanOrEqualTo, events[0].Duration)
	})

	Convey("an empty store logs no repository", t, func() {
		var output bytes.Buffer

		imgStore := local.NewImageStore(t.TempDir(), false, false, newTimingLogger(&output),
			monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		repo, err := imgStore.GetNextRepository(map[string]struct{}{})
		So(err, ShouldBeNil)
		So(repo, ShouldBeEmpty)

		events := timingEvents(t, &output, "repository scan completed")
		So(events, ShouldHaveLength, 1)
		So(events[0].Repository, ShouldBeEmpty)
	})
}
