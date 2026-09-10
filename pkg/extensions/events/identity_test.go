//go:build events

package events_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/events"
)

func TestIdentityDefaults(t *testing.T) {
	Convey("A zero Identity reproduces the built-in values", t, func() {
		var identity events.Identity

		So(identity.SourceOrDefault(), ShouldEqual, events.EventSource)
		So(identity.TypeOf(events.ImageUpdatedEventType), ShouldEqual, "zotregistry.image.updated")
		So(identity.TypeOf(events.RepositoryCreatedEventType), ShouldEqual, "zotregistry.repository.created")
	})

	Convey("Naming the built-in prefix explicitly changes nothing", t, func() {
		identity := events.Identity{TypePrefix: events.DefaultEventTypePrefix}

		So(identity.TypeOf(events.ImageDeletedEventType), ShouldEqual, "zotregistry.image.deleted")
	})
}

func TestIdentityOverrides(t *testing.T) {
	Convey("A configured source replaces the built-in one", t, func() {
		identity := events.Identity{Source: "https://registry.example.com/acme"}

		So(identity.SourceOrDefault(), ShouldEqual, "https://registry.example.com/acme")
	})

	Convey("A configured prefix renames the namespace and keeps the event", t, func() {
		identity := events.Identity{TypePrefix: "com.example.registry"}

		So(identity.TypeOf(events.ImageUpdatedEventType), ShouldEqual, "com.example.registry.image.updated")
		So(identity.TypeOf(events.ImageDeletedEventType), ShouldEqual, "com.example.registry.image.deleted")
		So(identity.TypeOf(events.ImageLintFailedEventType), ShouldEqual, "com.example.registry.image.lint_failed")
		So(identity.TypeOf(events.RepositoryCreatedEventType), ShouldEqual, "com.example.registry.repository.created")
	})

	Convey("Source and prefix are independent", t, func() {
		identity := events.Identity{Source: "urn:acme:registry:1", TypePrefix: "com.example"}

		So(identity.SourceOrDefault(), ShouldEqual, "urn:acme:registry:1")
		So(identity.TypeOf(events.ImageUpdatedEventType), ShouldEqual, "com.example.image.updated")
	})

	Convey("A type outside the built-in namespace is left alone", t, func() {
		identity := events.Identity{TypePrefix: "com.example"}

		So(identity.TypeOf(events.EventType("custom.thing.happened")), ShouldEqual, "custom.thing.happened")
	})
}
