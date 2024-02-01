package errors_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	apiErr "zotregistry.dev/zot/pkg/api/errors"
)

func TestUnknownCodeError(t *testing.T) {
	Convey("Retrieve a new error with unknown code", t, func() {
		So(func() { _ = apiErr.NewError(123456789) }, ShouldPanic)
	})
}
