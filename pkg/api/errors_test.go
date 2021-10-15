package api_test

import (
	"testing"

	"github.com/anuvu/zot/pkg/api"
	. "github.com/smartystreets/goconvey/convey"
)

func TestUnknownCodeError(t *testing.T) {
	Convey("Retrieve a new error with unknown code", t, func() {
		So(func() { _ = api.NewError(123456789, nil) }, ShouldPanic)
	})
}
