package main

import (
	"os"
	"path"

	"github.com/anuvu/zot/pkg/cli"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	configPath := path.Join(home + "/.zot")

	if err := cli.NewRootCmd(configPath).Execute(); err != nil {
		os.Exit(1)
	}
}
