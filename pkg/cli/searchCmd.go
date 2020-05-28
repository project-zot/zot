package cli

import (
	"github.com/spf13/cobra"
)

func initSearchCommand(rootCmd *cobra.Command) {
	rootCmd.AddCommand(searchCmd)
}

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search in zot",
	Long:  `Search in zot`,
}
