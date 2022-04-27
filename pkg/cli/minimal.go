//go:build !search && !ui_base
// +build !search,!ui_base

package cli

import "github.com/spf13/cobra"

func enableCli(rootCmd *cobra.Command) {
}
