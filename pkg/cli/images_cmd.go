//go:build search
// +build search

package cli

import (
	"github.com/spf13/cobra"

	"zotregistry.io/zot/pkg/cli/cmdflags"
)

func NewImagesCommand(searchService SearchService) *cobra.Command {
	imageCmd := &cobra.Command{
		Use:   "images [command]",
		Short: "List images hosted on the zot registry",
		Long:  `List images hosted on the zot registry`,
	}

	imageCmd.SetUsageTemplate(imageCmd.UsageTemplate() + usageFooter)

	imageCmd.PersistentFlags().StringP(cmdflags.OutputFormatFlag, "f", "", "Specify output format [text/json/yaml]")
	imageCmd.PersistentFlags().Bool(cmdflags.VerboseFlag, false, "Show verbose output")
	imageCmd.PersistentFlags().Bool(cmdflags.DebugFlag, false, "Show debug output")

	imageCmd.AddCommand(NewImageListCommand(searchService))
	imageCmd.AddCommand(NewImageCVEListCommand(searchService))
	imageCmd.AddCommand(NewImageBaseCommand(searchService))
	imageCmd.AddCommand(NewImageDerivedCommand(searchService))
	imageCmd.AddCommand(NewImageDigestCommand(searchService))
	imageCmd.AddCommand(NewImageNameCommand(searchService))

	return imageCmd
}
