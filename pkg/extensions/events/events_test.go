//go:build events
// +build events

package events_test

import (
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/extensions/events"
	"zotregistry.dev/zot/pkg/log"
)

type mockSink struct {
	store map[string]int
}

func (s *mockSink) Emit(e *cloudevents.Event) cloudevents.Result {
	s.store[e.Type()] += 1

	return nil
}

var _ events.Sink = (*mockSink)(nil)

func newMockSink() *mockSink {
	return &mockSink{
		store: make(map[string]int),
	}
}

func TestEventSinkMissing(t *testing.T) {
	Convey("missing sink", t, func() {
		_, err := events.NewRecorder(nil, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrEventSinkIsNil)
	})
}

func TestEvents(t *testing.T) {
	Convey("emits events", t, func() {
		sink := newMockSink()
		recorder, err := events.NewRecorder(sink, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		Convey("repository created", func() {
			err = recorder.RepositoryCreated("test")
			So(err, ShouldBeNil)
			So(sink.store[events.RepositoryCreatedEventType.String()], ShouldEqual, 1)
		})
		Convey("image updated", func() {
			err = recorder.ImageUpdated("test", "v1", "", string(types.OCIManifestSchema1), "")
			So(err, ShouldBeNil)
			So(sink.store[events.ImageUpdatedEventType.String()], ShouldEqual, 1)
		})
		Convey("image deleted", func() {
			err = recorder.ImageDeleted("test", "v1", "", string(types.OCIManifestSchema1))
			So(err, ShouldBeNil)
			So(sink.store[events.ImageDeletedEventType.String()], ShouldEqual, 1)
		})
		Convey("image lint failed", func() {
			err = recorder.ImageLintFailed("test", "v1", "", string(types.OCIManifestSchema1), "")
			So(err, ShouldBeNil)
			So(sink.store[events.ImageLintFailedEventType.String()], ShouldEqual, 1)
		})
	})
}
