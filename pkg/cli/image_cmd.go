package cli

import (
	"strconv"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

func NewImageCommand(searchService ImageSearchService, configPath string) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL string

	var user string

	var outputFormat string

	var imageCmd = &cobra.Command{
		Use:   "images [config-name]",
		Short: "List hosted images",
		Long:  `List images hosted on zot`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if servURL == "" {
				if len(args) > 0 {
					urlFromConfig, err := getConfigValue(configPath, args[0], "url")
					if err != nil {
						cmd.SilenceUsage = true
						return err
					}
					if urlFromConfig == "" {
						return zotErrors.ErrNoURLProvided
					}
					servURL = urlFromConfig
				} else {
					return zotErrors.ErrNoURLProvided
				}
			}

			var isSpinner bool

			if len(args) > 0 {
				var err error
				isSpinner, err = isSpinnerEnabled(configPath, args[0])
				if err != nil {
					cmd.SilenceUsage = true
					return err
				}
			} else {
				isSpinner = true
			}

			err := searchImage(cmd, searchImageParams, searchService, &servURL, &user, &outputFormat, isSpinner)

			if err != nil {
				cmd.SilenceUsage = true
				return err
			}

			return nil
		},
	}

	setupCmdFlags(imageCmd, searchImageParams, &servURL, &user, &outputFormat)
	imageCmd.SetUsageTemplate(imageCmd.UsageTemplate() + usageFooter)

	return imageCmd
}

func isSpinnerEnabled(configPath, configName string) (bool, error) {
	spinnerConfig, err := getConfigValue(configPath, configName, "showspinner")
	if err != nil {
		return false, err
	}

	if spinnerConfig == "" {
		return true, nil // spinner is enabled by default
	}

	isSpinner, err := strconv.ParseBool(spinnerConfig)
	if err != nil {
		return false, err
	}

	return isSpinner, nil
}

func setupCmdFlags(imageCmd *cobra.Command, searchImageParams map[string]*string, servURL, user, outputFormat *string) {
	searchImageParams["imageName"] = imageCmd.Flags().StringP("name", "n", "", "List image details by name")

	imageCmd.Flags().StringVar(servURL, "url", "", "Specify zot server URL if config-name is not mentioned")
	imageCmd.Flags().StringVarP(user, "user", "u", "", `User Credentials of zot server in "username:password" format`)
	imageCmd.Flags().StringVarP(outputFormat, "output", "o", "", "Specify output format [text/json/yaml]")
}

func searchImage(cmd *cobra.Command, params map[string]*string,
	service ImageSearchService, servURL, user, outputFormat *string, isSpinner bool) error {
	spin := spinner.New(spinner.CharSets[39], spinnerDuration, spinner.WithWriter(cmd.ErrOrStderr()))
	spin.Prefix = "Searching... "

	for _, searcher := range getSearchers() {
		found, err := searcher.search(params, service, servURL, user, outputFormat,
			cmd.OutOrStdout(), spinnerState{spin, isSpinner})
		if found {
			if err != nil {
				return err
			}

			return nil
		}
	}

	return zotErrors.ErrInvalidFlagsCombination
}

const (
	spinnerDuration = 150 * time.Millisecond
	usageFooter     = `
Run 'zot config -h' for details on [config-name] argument
`
)
