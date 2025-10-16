package auth_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	auth "zotregistry.dev/zot/v2/pkg/test/auth"
)

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { auth.MakeAuthTestServer("", "", "") }, ShouldPanic)
	})
}

func TestBearerServerLegacy(t *testing.T) {
	Convey("test MakeAuthTestServerLegacy() no serve key", t, func() {
		So(func() { auth.MakeAuthTestServerLegacy("", "") }, ShouldPanic)
	})
}
