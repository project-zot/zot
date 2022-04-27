//go:build !metrics
// +build !metrics

package main

import (
	"os"

	"zotregistry.io/zot/pkg/exporter/cli"
)

func main() {
	if err := cli.NewExporterCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
