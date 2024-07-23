package auth_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	auth "zotregistry.dev/zot/pkg/test/auth"
)

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { auth.MakeAuthTestServer("", "") }, ShouldPanic)
	})
}
