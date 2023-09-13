package main

import (
	"os"

	cli "zotregistry.io/zot/pkg/cli/server"
)

func main() {
	if err := cli.NewServerRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
