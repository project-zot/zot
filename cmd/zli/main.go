//go:build search
// +build search

package main

import (
	"os"

	cli "zotregistry.io/zot/pkg/cli/client"
)

func main() {
	if err := cli.NewCliRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
