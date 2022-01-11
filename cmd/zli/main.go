package main

import (
	"os"

	"zotregistry.io/zot/pkg/cli"
)

func main() {
	if err := cli.NewCliRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
