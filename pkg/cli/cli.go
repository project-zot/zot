//go:build search
// +build search

package cli

import "github.com/spf13/cobra"

func enableCli(rootCmd *cobra.Command) {
	rootCmd.AddCommand(NewConfigCommand())
	rootCmd.AddCommand(NewImageCommand(NewSearchService()))
	rootCmd.AddCommand(NewCVECommand(NewSearchService()))
	rootCmd.AddCommand(NewRepoCommand(NewSearchService()))
	rootCmd.AddCommand(NewSearchCommand(NewSearchService()))
}
