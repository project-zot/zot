//go:build events

package extensions_test

import (
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestNewEventRecorderSinkRollback(t *testing.T) {
	Convey("A NATS sink connects while it is being built", t, func() {
		natsServer := runTestNATSServer(t)

		recorder, err := extensions.NewEventRecorder(
			eventSinksConfig(natsSink(natsServer.ClientURL())), log.NewTestLogger())
		So(err, ShouldBeNil)
		So(recorder, ShouldNotBeNil)

		So(awaitClients(natsServer, 1), ShouldEqual, 1)

		recorder.Close()
		So(awaitClients(natsServer, 0), ShouldEqual, 0)
	})

	Convey("A sink opened before a later one fails is closed again", t, func() {
		natsServer := runTestNATSServer(t)

		// the NATS sink connects before the HTTP sink fails
		recorder, err := extensions.NewEventRecorder(
			eventSinksConfig(natsSink(natsServer.ClientURL()), brokenHTTPSink()), log.NewTestLogger())
		So(err, ShouldNotBeNil)
		So(recorder, ShouldBeNil)

		So(awaitClients(natsServer, 0), ShouldEqual, 0)
	})
}

func natsSink(address string) eventsconf.SinkConfig {
	return eventsconf.SinkConfig{
		Type:    eventsconf.NATS,
		Address: address,
		Channel: "zot",
		Timeout: 5 * time.Second,
	}
}

func brokenHTTPSink() eventsconf.SinkConfig {
	return eventsconf.SinkConfig{
		Type:      eventsconf.HTTP,
		Address:   "http://receiver",
		Timeout:   5 * time.Second,
		TLSConfig: &eventsconf.TLSConfig{CACertFile: "/nonexistent/ca.pem"},
	}
}

func eventSinksConfig(sinks ...eventsconf.SinkConfig) *config.Config {
	enabled := true
	cfg := config.New()
	cfg.Extensions = &extconf.ExtensionConfig{
		Events: &eventsconf.Config{
			Enable: &enabled,
			Sinks:  sinks,
		},
	}

	return cfg
}

// awaitClients waits for the server to settle on want connected clients.
func awaitClients(natsServer *server.Server, want int) int {
	clients := natsServer.NumClients()

	for range 100 {
		if clients == want {
			break
		}

		time.Sleep(50 * time.Millisecond)

		clients = natsServer.NumClients()
	}

	return clients
}

func runTestNATSServer(t *testing.T) *server.Server {
	t.Helper()

	natsServer, err := server.NewServer(&server.Options{
		Host:           "127.0.0.1",
		Port:           -1,
		NoLog:          true,
		NoSigs:         true,
		MaxControlLine: 4096,
	})
	if err != nil {
		t.Fatalf("failed to create NATS server: %v", err)
	}

	go natsServer.Start()

	if !natsServer.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to start")
	}

	t.Cleanup(natsServer.Shutdown)

	return natsServer
}
