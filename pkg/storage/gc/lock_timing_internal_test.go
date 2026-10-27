package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type gcTimingEvent struct {
	Message    string `json:"msg"`
	Operation  string `json:"operation"`
	Storage    string `json:"storage"`
	Repository string `json:"repository"`
	Acquired   bool   `json:"lock_acquired"`
	Wait       int64  `json:"lock_wait"`
	Hold       int64  `json:"lock_hold"`
	Duration   int64  `json:"duration"`
	Error      string `json:"error"`
}

type gcTimingStore struct {
	mocks.MockedImageStore
	lockDelay time.Duration
	lockErr   error
}

func (s gcTimingStore) WithRepoCleanupLock(_ string, wrappedFunc func() error) error {
	time.Sleep(s.lockDelay)

	if s.lockErr != nil {
		return s.lockErr
	}

	return wrappedFunc()
}

func gcTimingEvents(output *bytes.Buffer) []gcTimingEvent {
	events := []gcTimingEvent{}

	for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
		var event gcTimingEvent

		So(json.Unmarshal(line, &event), ShouldBeNil)

		if event.Message == "gc repository operation completed" {
			events = append(events, event)
		}
	}

	return events
}

func TestGCRepositoryLockTiming(t *testing.T) {
	Convey("CleanRepo logs how long it waited for and held the repository lock", t, func() {
		var output bytes.Buffer

		logger := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
		indexErr := errors.New("index read failed") //nolint:err113 // test

		store := gcTimingStore{lockDelay: 20 * time.Millisecond}
		store.RootDirFn = func() string { return "/store" }
		store.GetIndexContentFn = func(string) ([]byte, error) {
			time.Sleep(15 * time.Millisecond)

			return nil, indexErr
		}

		gc := NewGarbageCollect(store, nil, Options{}, &logger, logger, monitoring.NewNopMetricServer())

		Convey("the wait and the hold are reported separately", func() {
			err := gc.CleanRepo(context.Background(), "repo")
			So(errors.Is(err, indexErr), ShouldBeTrue)

			events := gcTimingEvents(&output)
			So(events, ShouldHaveLength, 1)
			So(events[0].Operation, ShouldEqual, "CleanRepo")
			So(events[0].Storage, ShouldEqual, "/store")
			So(events[0].Repository, ShouldEqual, "repo")
			So(events[0].Acquired, ShouldBeTrue)
			So(events[0].Wait, ShouldBeGreaterThanOrEqualTo, int64(15*time.Millisecond))
			So(events[0].Hold, ShouldBeGreaterThanOrEqualTo, int64(10*time.Millisecond))
			So(events[0].Wait+events[0].Hold, ShouldBeLessThanOrEqualTo, events[0].Duration)
			So(events[0].Error, ShouldEqual, err.Error())
		})

		Convey("nothing is logged when debug logging is disabled", func() {
			output.Reset()

			logger := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))}
			gc := NewGarbageCollect(store, nil, Options{}, &logger, logger, monitoring.NewNopMetricServer())

			err := gc.CleanRepo(context.Background(), "repo")
			So(errors.Is(err, indexErr), ShouldBeTrue)

			So(gcTimingEvents(&output), ShouldBeEmpty)
		})

		Convey("a lock that was never acquired reports no hold", func() {
			lockErr := errors.New("lock unavailable") //nolint:err113 // test
			store.lockErr = lockErr

			gc := NewGarbageCollect(store, nil, Options{}, &logger, logger, monitoring.NewNopMetricServer())

			err := gc.CleanRepo(context.Background(), "repo")
			So(errors.Is(err, lockErr), ShouldBeTrue)

			events := gcTimingEvents(&output)
			So(events, ShouldHaveLength, 1)
			So(events[0].Acquired, ShouldBeFalse)
			So(events[0].Hold, ShouldEqual, 0)
			So(events[0].Wait, ShouldBeGreaterThanOrEqualTo, int64(15*time.Millisecond))
		})
	})
}
