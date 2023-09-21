//go:build search
// +build search

package client

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

const (
	spinnerDuration = 150 * time.Millisecond
	usageFooter     = `
Run 'zli config -h' for details on [config-name] argument
`
)

func NewImageCommand(searchService SearchService) *cobra.Command {
	imageCmd := &cobra.Command{
		Use:   "image [command]",
		Short: "List images hosted on the zot registry",
		Long:  `List images hosted on the zot registry`,
		RunE:  ShowSuggestionsIfUnknownCommand,
	}

	imageCmd.SetUsageTemplate(imageCmd.UsageTemplate() + usageFooter)

	imageCmd.PersistentFlags().String(URLFlag, "",
		"Specify zot server URL if config-name is not mentioned")
	imageCmd.PersistentFlags().String(ConfigFlag, "",
		"Specify the registry configuration to use for connection")
	imageCmd.PersistentFlags().StringP(UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	imageCmd.PersistentFlags().StringP(OutputFormatFlag, "f", "", "Specify output format [text/json/yaml]")
	imageCmd.PersistentFlags().Bool(VerboseFlag, false, "Show verbose output")
	imageCmd.PersistentFlags().Bool(DebugFlag, false, "Show debug output")

	imageCmd.AddCommand(NewImageListCommand(searchService))
	imageCmd.AddCommand(NewImageCVEListCommand(searchService))
	imageCmd.AddCommand(NewImageBaseCommand(searchService))
	imageCmd.AddCommand(NewImageDerivedCommand(searchService))
	imageCmd.AddCommand(NewImageDigestCommand(searchService))
	imageCmd.AddCommand(NewImageNameCommand(searchService))

	return imageCmd
}

func parseBooleanConfig(configPath, configName, configParam string) (bool, error) {
	config, err := getConfigValue(configPath, configName, configParam)
	if err != nil {
		return false, err
	}

	val, err := strconv.ParseBool(config)
	if err != nil {
		return false, err
	}

	return val, nil
}
