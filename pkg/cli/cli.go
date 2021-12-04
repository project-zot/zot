//go:build extended
// +build extended

package cli

import "github.com/spf13/cobra"

func enableCli(rootCmd *cobra.Command) {
	rootCmd.AddCommand(NewConfigCommand())
	rootCmd.AddCommand(NewImageCommand(NewSearchService()))
	rootCmd.AddCommand(NewCveCommand(NewSearchService()))
}
