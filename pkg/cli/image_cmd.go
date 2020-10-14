// +build extended

package cli

import (
	"os"
	"path"
	"strconv"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

func NewImageCommand(searchService SearchService) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS bool

	var imageCmd = &cobra.Command{
		Use:   "images [config-name]",
		Short: "List hosted images",
		Long:  `List images hosted on zot`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}

			configPath := path.Join(home + "/.zot")
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

			if len(args) > 0 {
				var err error
				isSpinner, err = parseBooleanConfig(configPath, args[0], showspinnerConfig)
				if err != nil {
					cmd.SilenceUsage = true
					return err
				}
				verifyTLS, err = parseBooleanConfig(configPath, args[0], verifyTLSConfig)
				if err != nil {
					cmd.SilenceUsage = true
					return err
				}
			}

			spin := spinner.New(spinner.CharSets[39], spinnerDuration, spinner.WithWriter(cmd.ErrOrStderr()))
			spin.Prefix = "Searching... "

			searchConfig := searchConfig{
				params:        searchImageParams,
				searchService: searchService,
				servURL:       &servURL,
				user:          &user,
				outputFormat:  &outputFormat,
				spinner:       spinnerState{spin, isSpinner},
				verifyTLS:     &verifyTLS,
				resultWriter:  cmd.OutOrStdout(),
			}

			err = searchImage(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true
				return err
			}

			return nil
		},
	}

	setupImageFlags(imageCmd, searchImageParams, &servURL, &user, &outputFormat)
	imageCmd.SetUsageTemplate(imageCmd.UsageTemplate() + usageFooter)

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

func setupImageFlags(imageCmd *cobra.Command, searchImageParams map[string]*string,
	servURL, user, outputFormat *string) {
	searchImageParams["imageName"] = imageCmd.Flags().StringP("name", "n", "", "List image details by name")

	imageCmd.Flags().StringVar(servURL, "url", "", "Specify zot server URL if config-name is not mentioned")
	imageCmd.Flags().StringVarP(user, "user", "u", "", `User Credentials of zot server in "username:password" format`)
	imageCmd.Flags().StringVarP(outputFormat, "output", "o", "", "Specify output format [text/json/yaml]")
}

func searchImage(searchConfig searchConfig) error {
	for _, searcher := range getImageSearchers() {
		found, err := searcher.search(searchConfig)
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
