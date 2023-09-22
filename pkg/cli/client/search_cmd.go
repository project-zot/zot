//go:build search
// +build search

package client

import (
	"github.com/spf13/cobra"
)

func NewSearchCommand(searchService SearchService) *cobra.Command {
	searchCmd := &cobra.Command{
		Use:   "search [command]",
		Short: "Search images and their tags",
		Long:  `Search repos or images`,
		RunE:  ShowSuggestionsIfUnknownCommand,
	}

	searchCmd.SetUsageTemplate(searchCmd.UsageTemplate() + usageFooter)

	searchCmd.PersistentFlags().String(URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	searchCmd.PersistentFlags().String(ConfigFlag, "",
		"Specify the registry configuration to use for connection")
	searchCmd.PersistentFlags().StringP(UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	searchCmd.PersistentFlags().StringP(OutputFormatFlag, "f", "", "Specify output format [text/json/yaml]")
	searchCmd.PersistentFlags().Bool(VerboseFlag, false, "Show verbose output")
	searchCmd.PersistentFlags().Bool(DebugFlag, false, "Show debug output")

	searchCmd.AddCommand(NewSearchQueryCommand(searchService))
	searchCmd.AddCommand(NewSearchSubjectCommand(searchService))

	return searchCmd
}
