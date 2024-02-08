//go:build search
// +build search

package client

import (
	"github.com/spf13/cobra"
)

func NewCVECommand(searchService SearchService) *cobra.Command {
	cvesCmd := &cobra.Command{
		Use:   "cve [command]",
		Short: "Lookup CVEs in images hosted on the zot registry",
		Long:  `List CVEs (Common Vulnerabilities and Exposures) of images hosted on the zot registry`,
		RunE:  ShowSuggestionsIfUnknownCommand,
	}

	cvesCmd.SetUsageTemplate(cvesCmd.UsageTemplate() + usageFooter)

	cvesCmd.PersistentFlags().String(URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	cvesCmd.PersistentFlags().String(ConfigFlag, "",
		"Specify the registry configuration to use for connection")
	cvesCmd.PersistentFlags().StringP(UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	cvesCmd.PersistentFlags().StringP(OutputFormatFlag, "f", "", "Specify output format [text/json/yaml]")
	cvesCmd.PersistentFlags().Bool(VerboseFlag, false, "Show verbose output")
	cvesCmd.PersistentFlags().Bool(DebugFlag, false, "Show debug output")

	cvesCmd.AddCommand(NewCveForImageCommand(searchService))
	cvesCmd.AddCommand(NewImagesByCVEIDCommand(searchService))
	cvesCmd.AddCommand(NewFixedTagsCommand(searchService))
	cvesCmd.AddCommand(NewCVEDiffCommand(searchService))

	return cvesCmd
}
