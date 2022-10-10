package swagger_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/swagger"
)

func TestDocs(t *testing.T) {
	Convey("Read docs", t, func() {
		s := swagger.New()
		So(s.ReadDoc(), ShouldNotBeEmpty)
	})
}
