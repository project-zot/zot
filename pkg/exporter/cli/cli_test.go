//go:build !metrics
// +build !metrics

package cli_test

import (
	_ "crypto/sha256"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/exporter/cli"
)

func TestExporterCli(t *testing.T) {
	Convey("New", t, func(c C) {
		cl := cli.NewExporterCmd()
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}
