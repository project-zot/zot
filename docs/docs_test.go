package docs_test

import (
	"testing"

	"github.com/anuvu/zot/docs"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDocs(t *testing.T) {
	Convey("Read docs", t, func() {
		s := docs.New()
		So(s.ReadDoc(), ShouldNotBeEmpty)
	})
}
