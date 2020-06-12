package cli

import (
	"github.com/spf13/cobra"
)

func NewSearchCmd() *cobra.Command {
	var searchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search in zot",
		Long:  `Search in zot`,
	}

	searchCmd.AddCommand(NewCveCommand(NewCveSearchService()))
	searchCmd.AddCommand(NewImageCommand(NewCveSearchService()))

	return searchCmd
}
