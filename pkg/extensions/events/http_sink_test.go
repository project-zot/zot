//go:build events
// +build events

package events_test

import (
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
)

func TestHTTPSink(t *testing.T) {
	Convey("NewHTTPSink returns error for invalid type", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    "invalid",
			Address: "http://localhost",
		}

		sink, err := events.NewHTTPSink(cfg)
		So(sink, ShouldBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidEventSinkType)
	})

	Convey("NewHTTPSink returns error for empty address", t, func() {
		cfg := eventsconf.SinkConfig{
			Type: eventsconf.HTTP,
		}

		sink, err := events.NewHTTPSink(cfg)
		So(sink, ShouldBeNil)
		So(err, ShouldEqual, zerr.ErrEventSinkAddressEmpty)
	})

	Convey("NewHTTPSink returns sink for valid config", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)
		So(sink, ShouldNotBeNil)
	})

	Convey("NewHTTPSink handles basic auth config", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
			Credentials: &eventsconf.Credentials{
				Username: "user",
				Password: "pass",
			},
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)
		So(sink, ShouldNotBeNil)
	})

	Convey("NewHTTPSink handles token auth config", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
			Credentials: &eventsconf.Credentials{
				Token: "thisisamocktoken",
			},
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)
		So(sink, ShouldNotBeNil)
	})

	Convey("NewHTTPSink handles custom headers config", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
			Headers: map[string]string{
				"X-Tenant-ID": "tenant-abc123",
			},
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)
		So(sink, ShouldNotBeNil)
	})

	Convey("GetHTTPClientForConfig returns error for invalid proxy", t, func() {
		badProxy := "://bad-url"
		cfg := eventsconf.SinkConfig{
			Proxy: &badProxy,
		}

		client, err := events.GetHTTPClientForConfig(cfg)
		So(client, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("GetHTTPClientForConfig returns client with default transport", t, func() {
		cfg := eventsconf.SinkConfig{
			Timeout: 2 * time.Second,
		}

		client, err := events.GetHTTPClientForConfig(cfg)
		So(err, ShouldBeNil)
		So(client, ShouldNotBeNil)
	})

	Convey("BasicAuth encodes credentials", t, func() {
		auth := events.BasicAuth("foo", "bar")
		So(auth, ShouldEqual, "Zm9vOmJhcg==")
	})

	Convey("HTTPSink emits event and sets channel extension", t, func() {
		event := cloudevents.NewEvent()
		event.SetID("1234")
		event.SetType("test.event")
		event.SetSource("unit.test")

		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
			Timeout: 1 * time.Second,
			Channel: "test-channel",
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)

		_ = sink.Emit(&event)
		So(event.Extensions()["channel"], ShouldEqual, "test-channel")
	})

	Convey("HTTPSink.Emit returns error for invalid event", t, func() {
		event := cloudevents.NewEvent() // invalid

		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
			Timeout: 1 * time.Second,
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)

		err = sink.Emit(&event)
		So(err, ShouldNotBeNil)
	})

	Convey("HTTPSink.Close completes successfully", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.HTTP,
			Address: "http://localhost",
		}

		sink, err := events.NewHTTPSink(cfg)
		So(err, ShouldBeNil)

		err = sink.Close()
		So(err, ShouldBeNil)
	})
}
