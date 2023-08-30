//go:build search
// +build search

package cli

import (
	"github.com/spf13/cobra"

	"zotregistry.io/zot/pkg/cli/cmdflags"
)

func NewCVESCommand(searchService SearchService) *cobra.Command {
	cvesCmd := &cobra.Command{
		Use:   "cves [command]",
		Short: "Lookup CVEs in images hosted on the zot registry",
		Long:  `List CVEs (Common Vulnerabilities and Exposures) of images hosted on the zot registry`,
	}

	cvesCmd.SetUsageTemplate(cvesCmd.UsageTemplate() + usageFooter)

	cvesCmd.PersistentFlags().StringP(cmdflags.OutputFormatFlag, "f", "", "Specify output format [text/json/yaml]")
	cvesCmd.PersistentFlags().Bool(cmdflags.VerboseFlag, false, "Show verbose output")
	cvesCmd.PersistentFlags().Bool(cmdflags.DebugFlag, false, "Show debug output")

	cvesCmd.AddCommand(NewCveForImageCommand(searchService))
	cvesCmd.AddCommand(NewImagesByCVEIDCommand(searchService))
	cvesCmd.AddCommand(NewFixedTagsCommand(searchService))

	return cvesCmd
}
