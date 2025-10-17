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

func TestNATSSink(t *testing.T) {
	Convey("NewNATSSink returns error for invalid type", t, func() {
		cfg := eventsconf.SinkConfig{
			Type:    "invalid",
			Address: "nats://localhost",
		}

		sink, err := events.NewNATSSink(cfg)
		So(sink, ShouldBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidEventSinkType)
	})

	Convey("NewNATSSink returns error for empty address", t, func() {
		cfg := eventsconf.SinkConfig{
			Type: eventsconf.NATS,
		}

		sink, err := events.NewNATSSink(cfg)
		So(sink, ShouldBeNil)
		So(err, ShouldEqual, zerr.ErrEventSinkAddressEmpty)
	})

	Convey("NewNATSSink with username/password credentials", t, func() {
		natsServer, natsURL := setupTestNATSServer(t)
		defer natsServer.Shutdown()

		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.NATS,
			Address: natsURL,
			Timeout: 2 * time.Second,
			Credentials: &eventsconf.Credentials{
				Username: "user",
				Password: "pass",
			},
		}

		sink, err := events.NewNATSSink(cfg)
		So(err, ShouldBeNil)
		So(sink, ShouldNotBeNil)
	})

	Convey("NewNATSSink with nonexistent credentials file", t, func() {
		natsServer, natsURL := setupTestNATSServer(t)
		defer natsServer.Shutdown()

		credsFile := "nonexistent.creds"
		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.NATS,
			Address: natsURL,
			Timeout: 1 * time.Second,
			Credentials: &eventsconf.Credentials{
				File: &credsFile,
			},
		}

		sink, err := events.NewNATSSink(cfg)
		So(sink, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("NewNATSSink fails with invalid TLS config", t, func() {
		natsServer, natsURL := setupTestNATSServer(t)
		defer natsServer.Shutdown()

		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.NATS,
			Address: natsURL,
			TLSConfig: &eventsconf.TLSConfig{
				CACertFile: "invalid",
				CertFile:   "invalid",
			},
		}

		sink, err := events.NewNATSSink(cfg)
		So(sink, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("Emit returns error for invalid event", t, func() {
		natsServer, natsURL := setupTestNATSServer(t)
		defer natsServer.Shutdown()

		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.NATS,
			Address: natsURL,
			Timeout: 1 * time.Second,
		}

		sink, err := events.NewNATSSink(cfg)
		So(err, ShouldBeNil)

		event := cloudevents.NewEvent() // invalid: no ID/type/source
		err = sink.Emit(&event)
		So(err, ShouldNotBeNil)
	})

	Convey("Close succeeds even without Emit", t, func() {
		natsServer, natsURL := setupTestNATSServer(t)
		defer natsServer.Shutdown()

		cfg := eventsconf.SinkConfig{
			Type:    eventsconf.NATS,
			Address: natsURL,
			Timeout: 1 * time.Second,
		}

		sink, err := events.NewNATSSink(cfg)
		So(err, ShouldBeNil)

		err = sink.Close()
		So(err, ShouldBeNil)
	})
}
