package cli

import (
	"github.com/spf13/cobra"
)

func NewSearchCmd(cveCmdCreator func() *cobra.Command, imageCmdCreator func() *cobra.Command) *cobra.Command {
	var searchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search in zot",
		Long:  `Search in zot`,
	}
	searchCmd.AddCommand(cveCmdCreator())
	searchCmd.AddCommand(imageCmdCreator())
	return searchCmd
}
