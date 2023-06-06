//go:build search
// +build search

package cli

import (
	"os"
	"path"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"

	zotErrors "zotregistry.io/zot/errors"
)

//nolint:dupl
func NewReferrersCommand(searchService SearchService) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, verbose, debug bool

	imageCmd := &cobra.Command{
		Use:   "referrers [config-name]",
		Short: "List images that refer the given image under Subeject field",
		Long:  `List images that refer the given image under Subeject field`,
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

			err = getReferrers(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true

				return err
			}

			return nil
		},
	}

	setupReferrersFlags(imageCmd, searchImageParams, &servURL, &user, &outputFormat, &verbose, &debug)
	imageCmd.SetUsageTemplate(imageCmd.UsageTemplate() + usageFooter)

	return imageCmd
}

func setupReferrersFlags(imageCmd *cobra.Command, searchImageParams map[string]*string,
	servURL, user, outputFormat *string, verbose *bool, debug *bool,
) {
	searchImageParams["repo"] = imageCmd.Flags().StringP("repo", "r", "", "List image details by name")
	searchImageParams["digest"] = imageCmd.Flags().StringP("digest", "d", "",
		"List images containing a specific manifest, config, or layer digest")

	imageCmd.Flags().StringVar(servURL, "url", "", "Specify zot server URL if config-name is not mentioned")
	imageCmd.Flags().StringVarP(user, "user", "u", "", `User Credentials of zot server in "username:password" format`)
	imageCmd.Flags().StringVarP(outputFormat, "output", "o", "", "Specify output format [text/json/yaml]")
	imageCmd.Flags().BoolVar(verbose, "verbose", false, "Show verbose output")
	imageCmd.Flags().BoolVar(debug, "debug", false, "Show debug output")
}

func getReferrers(searchConfig searchConfig) error {
	var searchers []searcher

	if checkExtEndPoint(searchConfig) {
		searchers = getReferrersSearchersGQL()
	} else {
		searchers = getReferrersSearchers()
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

	return zotErrors.ErrInvalidFlagsCombination
}
