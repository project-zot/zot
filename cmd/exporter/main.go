// +build minimal

package main

import (
	"os"

	"github.com/anuvu/zot/pkg/exporter/cli"
)

func main() {
	if err := cli.NewExporterCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
