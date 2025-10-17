//go:build search
// +build search

package main

import (
	"os"

	cli "zotregistry.dev/zot/v2/pkg/cli/client"
)

func main() {
	if err := cli.NewCliRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
