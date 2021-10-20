package swagger_test

import (
	"testing"

	"github.com/anuvu/zot/swagger"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDocs(t *testing.T) {
	Convey("Read docs", t, func() {
		s := swagger.New()
		So(s.ReadDoc(), ShouldNotBeEmpty)
	})
}
