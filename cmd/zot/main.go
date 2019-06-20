package main

import (
	"os"

	"github.com/anuvu/zot/pkg/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
