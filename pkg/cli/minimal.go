//go:build !search && !cli
// +build !search,!cli

package cli

import "github.com/spf13/cobra"

func enableCli(rootCmd *cobra.Command) {
}
