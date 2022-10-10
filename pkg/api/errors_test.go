package api_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
)

func TestUnknownCodeError(t *testing.T) {
	Convey("Retrieve a new error with unknown code", t, func() {
		So(func() { _ = api.NewError(123456789, nil) }, ShouldPanic)
	})
}
