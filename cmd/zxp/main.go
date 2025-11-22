//go:build !metrics

package main

import (
	"os"

	"zotregistry.dev/zot/v2/pkg/exporter/cli"
)

func main() {
	if err := cli.NewExporterCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
