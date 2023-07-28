//go:build search
// +build search

package cli

import (
	"os"
	"path"
	"strconv"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"

	zerr "zotregistry.io/zot/errors"
)

//nolint:dupl
func NewImageCommand(searchService SearchService) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, verbose, debug bool

	imageCmd := &cobra.Command{
		Use:   "image [config-name]",
		Short: "DEPRECATED (see images)",
		Long:  `DEPRECATED (see images)! List images hosted on the zot registry`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}

			configPath := path.Join(home, "/.zot")
			if servURL == "" {
				if len(args) > 0 {
					urlFromConfig, err := getConfigValue(configPath, args[0], "url")
					if err != nil {
						cmd.SilenceUsage = true

						return err
					}

					if urlFromConfig == "" {
						return zerr.ErrNoURLProvided
					}

					servURL = urlFromConfig
				} else {
					return zerr.ErrNoURLProvided
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
			spin.Prefix = prefix

			searchConfig := searchConfig{
				params:        searchImageParams,
				searchService: searchService,
				servURL:       &servURL,
				user:          &user,
				outputFormat:  &outputFormat,
				verbose:       &verbose,
				debug:         &debug,
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

	setupImageFlags(imageCmd, searchImageParams, &servURL, &user, &outputFormat, &verbose, &debug)
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
	servURL, user, outputFormat *string, verbose *bool, debug *bool,
) {
	searchImageParams["imageName"] = imageCmd.Flags().StringP("name", "n", "", "List image details by name")
	searchImageParams["digest"] = imageCmd.Flags().StringP("digest", "d", "",
		"List images containing a specific manifest, config, or layer digest")
	searchImageParams["derivedImage"] = imageCmd.Flags().StringP("derived-images", "D", "",
		"List images that are derived from given image")
	searchImageParams["baseImage"] = imageCmd.Flags().StringP("base-images", "b", "",
		"List images that are base for the given image")

	imageCmd.PersistentFlags().StringVar(servURL, "url", "", "Specify zot server URL if config-name is not mentioned")
	imageCmd.PersistentFlags().StringVarP(user, "user", "u", "",
		`User Credentials of zot server in "username:password" format`)
	imageCmd.PersistentFlags().StringVarP(outputFormat, "output", "o", "", "Specify output format [text/json/yaml]")
	imageCmd.PersistentFlags().BoolVar(verbose, "verbose", false, "Show verbose output")
	imageCmd.PersistentFlags().BoolVar(debug, "debug", false, "Show debug output")
}

func searchImage(searchConfig searchConfig) error {
	var searchers []searcher

	if checkExtEndPoint(searchConfig) {
		searchers = getImageSearchersGQL()
	} else {
		searchers = getImageSearchers()
	}

	for _, searcher := range searchers {
		found, err := searcher.search(searchConfig)
		if found {
			if err != nil {
				return err
			}

			return nil
		}
	}

	return zerr.ErrInvalidFlagsCombination
}

const (
	spinnerDuration = 150 * time.Millisecond
	usageFooter     = `
Run 'zli config -h' for details on [config-name] argument
`
)
