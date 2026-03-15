//go:build events

package events_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	cehttp "github.com/cloudevents/sdk-go/v2/protocol/http"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	. "github.com/smartystreets/goconvey/convey"
	"k8s.io/apimachinery/pkg/util/rand"

	zerr "zotregistry.dev/zot/v2/errors"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/log"
)

type mockSink struct {
	store chan *cloudevents.Event
}

func (s *mockSink) Emit(e *cloudevents.Event) cloudevents.Result {
	s.store <- e

	return nil
}

func (s *mockSink) Close() error {
	return nil
}

var _ events.Sink = (*mockSink)(nil)

func newMockSink() *mockSink {
	return &mockSink{
		store: make(chan *cloudevents.Event),
	}
}

func TestEventSinkMissing(t *testing.T) {
	Convey("missing sink", t, func() {
		_, err := events.NewRecorder(log.NewTestLogger())
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrEventSinkIsNil)
	})
}

func TestEvents(t *testing.T) {
	Convey("emits events", t, func() {
		sink := newMockSink()
		recorder, err := events.NewRecorder(log.NewTestLogger(), sink)
		So(err, ShouldBeNil)
		Convey("repository created", func() {
			recorder.RepositoryCreated("test", nil)
			ev := <-sink.store
			So(ev.Type(), ShouldEqual, events.RepositoryCreatedEventType.String())
		})
		Convey("image updated", func() {
			recorder.ImageUpdated("test", "v1", "", string(types.OCIManifestSchema1), "", nil)
			ev := <-sink.store
			So(ev.Type(), ShouldEqual, events.ImageUpdatedEventType.String())
		})
		Convey("image deleted", func() {
			recorder.ImageDeleted("test", "v1", "", string(types.OCIManifestSchema1), nil)
			ev := <-sink.store
			So(ev.Type(), ShouldEqual, events.ImageDeletedEventType.String())
		})
		Convey("image lint failed", func() {
			recorder.ImageLintFailed("test", "v1", "", string(types.OCIManifestSchema1), "", nil)
			ev := <-sink.store
			So(ev.Type(), ShouldEqual, events.ImageLintFailedEventType.String())
		})
	})
}

func TestEventsWithContext(t *testing.T) {
	Convey("emits events with actor and request metadata", t, func() {
		sink := newMockSink()
		recorder, err := events.NewRecorder(log.NewTestLogger(), sink)
		So(err, ShouldBeNil)

		ectx := &events.EventContext{
			Actor: &events.ActorInfo{Name: "testuser"},
			Request: &events.RequestInfo{
				Addr:      "192.168.1.1:12345",
				Method:    "PUT",
				UserAgent: "docker/24.0.5",
			},
		}

		Convey("image updated includes actor and request", func() {
			recorder.ImageUpdated("test", "v1", "sha256:abc", string(types.OCIManifestSchema1), "{}", ectx)
			ev := <-sink.store
			So(ev.Type(), ShouldEqual, events.ImageUpdatedEventType.String())

			var data map[string]any
			err := ev.DataAs(&data)
			So(err, ShouldBeNil)

			actor, ok := data["actor"].(map[string]any)
			So(ok, ShouldBeTrue)
			So(actor["name"], ShouldEqual, "testuser")

			req, ok := data["request"].(map[string]any)
			So(ok, ShouldBeTrue)
			So(req["addr"], ShouldEqual, "192.168.1.1:12345")
			So(req["method"], ShouldEqual, "PUT")
			So(req["useragent"], ShouldEqual, "docker/24.0.5")
		})

		Convey("image deleted includes actor and request", func() {
			recorder.ImageDeleted("test", "v1", "sha256:abc", string(types.OCIManifestSchema1), ectx)
			ev := <-sink.store
			So(ev.Type(), ShouldEqual, events.ImageDeletedEventType.String())

			var data map[string]any
			err := ev.DataAs(&data)
			So(err, ShouldBeNil)

			actor, ok := data["actor"].(map[string]any)
			So(ok, ShouldBeTrue)
			So(actor["name"], ShouldEqual, "testuser")
		})

		Convey("nil event context omits actor and request", func() {
			recorder.ImageUpdated("test", "v1", "sha256:abc", string(types.OCIManifestSchema1), "{}", nil)
			ev := <-sink.store

			var data map[string]any
			err := ev.DataAs(&data)
			So(err, ShouldBeNil)

			_, hasActor := data["actor"]
			So(hasActor, ShouldBeFalse)

			_, hasRequest := data["request"]
			So(hasRequest, ShouldBeFalse)
		})
	})
}

func TestEventContextHelpers(t *testing.T) {
	Convey("EventContext context helpers", t, func() {
		Convey("round-trips through context", func() {
			ectx := &events.EventContext{
				Actor:   &events.ActorInfo{Name: "user1"},
				Request: &events.RequestInfo{Addr: "1.2.3.4", Method: "PUT", UserAgent: "test/1.0"},
			}

			ctx := events.WithEventContext(context.Background(), ectx)
			got := events.EventContextFromContext(ctx)
			So(got, ShouldNotBeNil)
			So(got.Actor.Name, ShouldEqual, "user1")
			So(got.Request.Addr, ShouldEqual, "1.2.3.4")
		})

		Convey("returns nil from empty context", func() {
			got := events.EventContextFromContext(context.Background())
			So(got, ShouldBeNil)
		})
	})
}

func TestHTTPSinkEvents(t *testing.T) {
	Convey("emits events to http sink", t, func() {
		eventChan := make(chan *cloudevents.Event, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			event, err := cehttp.NewEventFromHTTPRequest(r)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			eventChan <- event

			w.WriteHeader(http.StatusOK)
		}))

		defer server.Close()

		config := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: server.URL,
			Timeout: 5 * time.Second,
		}
		sink, err := events.NewHTTPSink(config)
		So(err, ShouldBeNil)

		recorder, err := events.NewRecorder(log.NewTestLogger(), sink)
		So(err, ShouldBeNil)

		Convey("repository created", func() {
			recorder.RepositoryCreated("test", nil)
			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.RepositoryCreatedEventType.String())
		})

		Convey("image updated", func() {
			recorder.ImageUpdated("test", "v1", "", string(types.OCIManifestSchema1), "", nil)
			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.ImageUpdatedEventType.String())
		})

		Convey("image deleted", func() {
			recorder.ImageDeleted("test", "v1", "", string(types.OCIManifestSchema1), nil)
			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.ImageDeletedEventType.String())
		})

		Convey("image lint failed", func() {
			recorder.ImageLintFailed("test", "v1", "", string(types.OCIManifestSchema1), "", nil)
			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.ImageLintFailedEventType.String())
		})
	})
}

func TestNATSSinkEvents(t *testing.T) {
	Convey("emits events to nats sink", t, func() {
		Convey("repository created", func() {
			natsServer, natsURL := setupTestNATSServer(t)
			defer natsServer.Shutdown()

			testChannel := "test-events-" + randomString()

			recorder, err := createRecorder(t, natsURL, testChannel)
			defer recorder.Close()
			So(err, ShouldBeNil)

			eventChan := make(chan *cloudevents.Event, 1)

			nc, err := createSubscription(t, natsURL, testChannel, eventChan)
			defer nc.Close()
			So(err, ShouldBeNil)

			recorder.RepositoryCreated("test", nil)

			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.RepositoryCreatedEventType.String())
		})

		Convey("image updated", func() {
			natsServer, natsURL := setupTestNATSServer(t)
			defer natsServer.Shutdown()

			testChannel := "test-events-" + randomString()

			recorder, err := createRecorder(t, natsURL, testChannel)
			So(err, ShouldBeNil)
			defer recorder.Close()

			eventChan := make(chan *cloudevents.Event, 1)

			nc, err := createSubscription(t, natsURL, testChannel, eventChan)
			defer nc.Close()
			So(err, ShouldBeNil)

			recorder.ImageUpdated("test", "v1", "", string(types.OCIManifestSchema1), "", nil)

			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.ImageUpdatedEventType.String())
		})

		Convey("image deleted", func() {
			natsServer, natsURL := setupTestNATSServer(t)
			defer natsServer.Shutdown()

			testChannel := "test-events-" + randomString()

			eventChan := make(chan *cloudevents.Event, 1)

			nc, err := createSubscription(t, natsURL, testChannel, eventChan)
			defer nc.Close()
			So(err, ShouldBeNil)

			recorder, err := createRecorder(t, natsURL, testChannel)
			defer recorder.Close()
			So(err, ShouldBeNil)

			recorder.ImageDeleted("test", "v1", "", string(types.OCIManifestSchema1), nil)

			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.ImageDeletedEventType.String())
		})

		Convey("image lint failed", func() {
			natsServer, natsURL := setupTestNATSServer(t)
			defer natsServer.Shutdown()

			testChannel := "test-events-" + randomString()

			recorder, err := createRecorder(t, natsURL, testChannel)
			defer recorder.Close()
			So(err, ShouldBeNil)

			eventChan := make(chan *cloudevents.Event, 1)

			nc, err := createSubscription(t, natsURL, testChannel, eventChan)
			defer nc.Close()
			So(err, ShouldBeNil)

			recorder.ImageLintFailed("test", "v1", "", string(types.OCIManifestSchema1), "", nil)

			e := getEvent(t, eventChan)
			So(e, ShouldNotBeNil)
			So(e.Type(), ShouldEqual, events.ImageLintFailedEventType.String())
		})
	})
}

func setupTestNATSServer(t *testing.T) (*server.Server, string) {
	t.Helper()

	opts := server.Options{
		Host:           "127.0.0.1",
		Port:           -1, // Use random available port
		NoLog:          true,
		NoSigs:         true,
		MaxControlLine: 4096,
	}

	natsServer, err := server.NewServer(&opts)
	if err != nil {
		panic(err)
	}

	go natsServer.Start()

	if !natsServer.ReadyForConnections(5 * time.Second) {
		panic("NATS server failed to start")
	}

	return natsServer, natsServer.ClientURL()
}

func createRecorder(t *testing.T, natsURL, testChannel string) (events.Recorder, error) {
	t.Helper()
	config := eventsconf.SinkConfig{
		Type:    eventsconf.NATS,
		Address: natsURL,
		Channel: testChannel,
		Timeout: 15 * time.Second,
	}

	sink, err := events.NewNATSSink(config)
	if err != nil {
		return nil, err
	}

	recorder, err := events.NewRecorder(log.NewTestLogger(), sink)
	if err != nil {
		return nil, err
	}

	return recorder, nil
}

func createSubscription(t *testing.T, natsURL, channelName string, bus chan *cloudevents.Event) (*nats.Conn, error) {
	t.Helper()

	natsConnection, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	_, err = natsConnection.Subscribe(channelName, func(msg *nats.Msg) {
		event := cloudevents.NewEvent()

		headers := msg.Header
		event.SetID(headers.Get("ce-id"))
		event.SetSource(headers.Get("ce-source"))
		event.SetType(headers.Get("ce-type"))

		if subj := headers.Get("ce-subject"); subj != "" {
			event.SetSubject(subj)
		}

		if err := event.UnmarshalJSON(msg.Data); err == nil {
			bus <- &event
		}

		_ = msg.Respond([]byte("OK"))
	})
	if err != nil {
		return nil, err
	}

	err = natsConnection.FlushTimeout(2 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("flush failed: %w", err)
	}

	return natsConnection, nil
}

func getEvent(t *testing.T, c chan *cloudevents.Event) *cloudevents.Event {
	t.Helper()

	var evt *cloudevents.Event
	select {
	case evt = <-c:
	case <-time.After(time.Second * 2):
		t.Fatal("timed out waiting for event")
	}

	return evt
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString() string {
	rand.Seed(time.Now().UnixNano())

	buf := make([]byte, 5)

	for i := range buf {
		buf[i] = charset[rand.Intn(len(charset))]
	}

	return string(buf)
}
