//go:build events

package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	cehttp "github.com/cloudevents/sdk-go/v2/protocol/http"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

// eventSink is a receiving endpoint standing in for a webhook.
func eventSink(t *testing.T) (string, chan *cloudevents.Event) {
	t.Helper()

	received := make(chan *cloudevents.Event, 8)
	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		event, err := cehttp.NewEventFromHTTPRequest(req)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)

			return
		}

		received <- event
		resp.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(server.Close)

	return server.URL, received
}

// countingEventSink also reports how many connections were opened to it.
func countingEventSink(t *testing.T) (string, chan *cloudevents.Event, *atomic.Int32) {
	t.Helper()

	var opened atomic.Int32

	received := make(chan *cloudevents.Event, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		event, err := cehttp.NewEventFromHTTPRequest(req)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)

			return
		}

		received <- event
		resp.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	server.Start()

	t.Cleanup(server.Close)

	return server.URL, received, &opened
}

func eventsConfig(address string) *config.Config {
	enabled := true
	cfg := config.New()
	cfg.Extensions = &extconf.ExtensionConfig{}

	if address != "" {
		cfg.Extensions.Events = &eventsconf.Config{
			Enable: &enabled,
			Sinks: []eventsconf.SinkConfig{{
				Type:    eventsconf.HTTP,
				Address: address,
				Timeout: 5 * time.Second,
			}},
		}
	}

	return cfg
}

// refuteEvent reports whether the sink stayed silent long enough to be sure.
func refuteEvent(received chan *cloudevents.Event) bool {
	select {
	case <-received:
		return false
	case <-time.After(2 * time.Second):
		return true
	}
}

func awaitEvent(received chan *cloudevents.Event) *cloudevents.Event {
	select {
	case event := <-received:
		return event
	case <-time.After(5 * time.Second):
		return nil
	}
}

func TestEventRecorderReload(t *testing.T) {
	Convey("A changed events config re-points the recorder without a restart", t, func() {
		firstURL, firstSink := eventSink(t)
		secondURL, secondSink := eventSink(t)

		ctlr := NewController(eventsConfig(firstURL))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(firstSink), ShouldNotBeNil)

		// the full reload path, not just the recorder helper
		ctlr.LoadNewConfig(eventsConfig(secondURL))

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(secondSink), ShouldNotBeNil)
		So(refuteEvent(firstSink), ShouldBeTrue)
	})

	Convey("Events enabled by a reload start being delivered", t, func() {
		sinkURL, sink := eventSink(t)

		ctlr := NewController(eventsConfig(""))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		// nothing to publish to yet, and publishing must still be safe
		ctlr.EventRecorder.RepositoryCreated("repo", nil)

		ctlr.LoadNewConfig(eventsConfig(sinkURL))

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)
	})

	Convey("Events disabled by a reload stop being delivered", t, func() {
		sinkURL, sink := eventSink(t)

		ctlr := NewController(eventsConfig(sinkURL))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)

		ctlr.LoadNewConfig(eventsConfig(""))

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(refuteEvent(sink), ShouldBeTrue)
	})

	Convey("An unchanged events config keeps the same recorder", t, func() {
		sinkURL, sink, opened := countingEventSink(t)

		ctlr := NewController(eventsConfig(sinkURL))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		// deliver first, so a keep-alive connection is open when the reload lands
		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)
		So(opened.Load(), ShouldEqual, 1)

		ctlr.LoadNewConfig(eventsConfig(sinkURL))

		// a rebuild would have dialled a second connection
		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)
		So(opened.Load(), ShouldEqual, 1)
	})
}

func TestEventRecorderReloadReachesImageStores(t *testing.T) {
	Convey("A swap reaches the stores the recorder was handed to at startup", t, func() {
		firstURL, firstSink := eventSink(t)
		secondURL, secondSink := eventSink(t)

		conf := eventsConfig(firstURL)
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := NewController(conf)
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		// the stores are handed the recorder once, exactly as Init does
		storeController, err := storage.New(ctlr.Config, nil, monitoring.NewNopMetricServer(),
			ctlr.Log, ctlr.EventRecorder)
		So(err, ShouldBeNil)

		store := storeController.GetDefaultImageStore()
		So(store.InitRepo(context.Background(), "before"), ShouldBeNil)
		So(awaitEvent(firstSink), ShouldNotBeNil)

		ctlr.LoadNewConfig(eventsConfig(secondURL))

		So(store.InitRepo(context.Background(), "after"), ShouldBeNil)
		So(awaitEvent(secondSink), ShouldNotBeNil)
		So(refuteEvent(firstSink), ShouldBeTrue)
	})
}

// brokenEventsConfig keeps a usable sink ahead of one with a missing CA file.
func brokenEventsConfig() *config.Config {
	conf := eventsConfig("http://receiver")
	conf.Extensions.Events.Sinks = append(conf.Extensions.Events.Sinks, eventsconf.SinkConfig{
		Type:      eventsconf.HTTP,
		Address:   "http://receiver",
		Timeout:   5 * time.Second,
		TLSConfig: &eventsconf.TLSConfig{CACertFile: "/nonexistent/ca.pem"},
	})

	return conf
}

func TestEventRecorderReloadFailures(t *testing.T) {
	Convey("A recorder that cannot be built at startup fails Init", t, func() {
		ctlr := NewController(brokenEventsConfig())
		ctlr.Log = log.NewTestLogger()

		So(ctlr.InitEventRecorder(), ShouldNotBeNil)
	})

	Convey("A rebuild that fails keeps the previous recorder delivering", t, func() {
		sinkURL, sink := eventSink(t)

		ctlr := NewController(eventsConfig(sinkURL))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)

		ctlr.LoadNewConfig(brokenEventsConfig())

		// the broken config was rejected, so the working sink is still in place
		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)
	})
}

func TestEventRecorderReloadRetriesAfterFailure(t *testing.T) {
	Convey("A rebuild that failed is retried when the same config comes back", t, func() {
		firstURL, firstSink := eventSink(t)
		secondURL, secondSink := eventSink(t)

		ctlr := NewController(eventsConfig(firstURL))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(firstSink), ShouldNotBeNil)

		// valid except for a CA file that is not there yet
		caPath := path.Join(t.TempDir(), "ca.pem")
		pending := eventsConfig(secondURL)
		pending.Extensions.Events.Sinks[0].TLSConfig = &eventsconf.TLSConfig{CACertFile: caPath}

		ctlr.LoadNewConfig(pending)

		// the rebuild failed, so the previous sink is still the live one
		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(firstSink), ShouldNotBeNil)

		// the missing piece arrives and the very same config is applied again
		caCert, _, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		So(os.WriteFile(caPath, caCert, 0o600), ShouldBeNil)

		ctlr.LoadNewConfig(pending)

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(secondSink), ShouldNotBeNil)
	})
}

func TestShutdownClosesEventRecorder(t *testing.T) {
	Convey("shutdown closes the recorder instead of dropping it", t, func() {
		sinkURL, sink, opened := countingEventSink(t)

		ctlr := NewController(eventsConfig(sinkURL))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(awaitEvent(sink), ShouldNotBeNil)
		So(opened.Load(), ShouldEqual, 1)

		ctlr.Shutdown()

		// closed and detached, so nothing reaches the sink
		ctlr.EventRecorder.RepositoryCreated("repo", nil)
		So(refuteEvent(sink), ShouldBeTrue)
	})

	Convey("shutdown is safe when events are disabled", t, func() {
		ctlr := NewController(eventsConfig(""))
		ctlr.Log = log.NewTestLogger()
		So(ctlr.InitEventRecorder(), ShouldBeNil)

		So(func() { ctlr.Shutdown() }, ShouldNotPanic)
	})

	Convey("shutdown is safe before a recorder was ever built", t, func() {
		ctlr := NewController(eventsConfig(""))
		ctlr.Log = log.NewTestLogger()

		So(ctlr.EventRecorder, ShouldBeNil)
		So(func() { ctlr.Shutdown() }, ShouldNotPanic)
	})
}
