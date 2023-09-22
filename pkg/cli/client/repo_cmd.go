//go:build search
// +build search

package client

import (
	"github.com/spf13/cobra"
)

const prefix = "Searching... "

func NewRepoCommand(searchService SearchService) *cobra.Command {
	repoCmd := &cobra.Command{
		Use:   "repo [config-name]",
		Short: "List all repositories",
		Long:  `List all repositories`,
		RunE:  ShowSuggestionsIfUnknownCommand,
	}

	repoCmd.SetUsageTemplate(repoCmd.UsageTemplate() + usageFooter)

	repoCmd.PersistentFlags().String(URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	repoCmd.PersistentFlags().String(ConfigFlag, "",
		"Specify the registry configuration to use for connection")
	repoCmd.PersistentFlags().StringP(UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	repoCmd.PersistentFlags().Bool(DebugFlag, false, "Show debug output")

	repoCmd.AddCommand(NewListReposCommand(searchService))

	return repoCmd
}
