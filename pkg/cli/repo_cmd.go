//go:build search
// +build search

package cli

import (
	"github.com/spf13/cobra"

	"zotregistry.io/zot/pkg/cli/cmdflags"
)

const prefix = "Searching... "

func NewRepoCommand(searchService SearchService) *cobra.Command {
	repoCmd := &cobra.Command{
		Use:   "repo [config-name]",
		Short: "List all repositories",
		Long:  `List all repositories`,
	}

	repoCmd.SetUsageTemplate(repoCmd.UsageTemplate() + usageFooter)

	repoCmd.PersistentFlags().String(cmdflags.URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	repoCmd.PersistentFlags().String(cmdflags.ConfigFlag, "",
		"Specify the registry configuration to use for connection")
	repoCmd.PersistentFlags().StringP(cmdflags.UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	repoCmd.PersistentFlags().Bool(cmdflags.DebugFlag, false, "Show debug output")

	repoCmd.AddCommand(NewListReposCommand(searchService))

	return repoCmd
}
