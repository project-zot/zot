//go:build search
// +build search

package cli

import (
	"github.com/spf13/cobra"

	"zotregistry.io/zot/pkg/cli/cmdflags"
)

func NewSearchCommand(searchService SearchService) *cobra.Command {
	searchCmd := &cobra.Command{
		Use:   "search [config-name]",
		Short: "Search images and their tags",
		Long:  `Search repos or images`,
	}

	searchCmd.SetUsageTemplate(searchCmd.UsageTemplate() + usageFooter)

	searchCmd.PersistentFlags().String(cmdflags.URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	searchCmd.PersistentFlags().String(cmdflags.ConfigFlag, "",
		"Specify the registry configuration to use for connection")
	searchCmd.PersistentFlags().StringP(cmdflags.UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	searchCmd.PersistentFlags().StringP(cmdflags.OutputFormatFlag, "f", "", "Specify output format [text/json/yaml]")
	searchCmd.PersistentFlags().Bool(cmdflags.VerboseFlag, false, "Show verbose output")
	searchCmd.PersistentFlags().Bool(cmdflags.DebugFlag, false, "Show debug output")

	searchCmd.AddCommand(NewSearchQueryCommand(searchService))
	searchCmd.AddCommand(NewSearchSubjectCommand(searchService))

	return searchCmd
}
