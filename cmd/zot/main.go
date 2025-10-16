package main

import (
	"os"

	cli "zotregistry.dev/zot/v2/pkg/cli/server"
)

func main() {
	if err := cli.NewServerRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
