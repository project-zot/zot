//go:build search
// +build search

package cli

import (
	"os"
	"path"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/cli/cmdflags"
)

//nolint:dupl
func NewSearchCommand(searchService SearchService) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, verbose, debug bool

	searchCmd := &cobra.Command{
		Use:   "search [config-name]",
		Short: "Search images and their tags",
		Long: `Search repos or images
Example:
  # For repo search specify a substring of the repo name without the tag
  zli search --query test/repo

  # For image search specify the full repo name followed by the tag or a prefix of the tag.
  zli search --query test/repo:2.1.

  # For referrers search specify the referred subject using it's full digest or tag:
  zli search --subject repo@sha256:f9a0981...
  zli search --subject repo:tag
		`,
		Args: cobra.MaximumNArgs(1),
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

			err = globalSearch(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true

				return err
			}

			return nil
		},
	}

	setupSearchFlags(searchCmd, searchImageParams, &servURL, &user, &outputFormat, &verbose, &debug)
	searchCmd.SetUsageTemplate(searchCmd.UsageTemplate() + usageFooter)

	searchCmd.AddCommand(NewSearchQueryCommand(searchService))
	searchCmd.AddCommand(NewSearchSubjectCommand(searchService))

	return searchCmd
}

func setupSearchFlags(searchCmd *cobra.Command, searchImageParams map[string]*string,
	servURL, user, outputFormat *string, verbose *bool, debug *bool,
) {
	searchImageParams["query"] = searchCmd.Flags().StringP("query", "q", "",
		"Specify what repo or image(repo:tag) to be searched")

	searchImageParams["subject"] = searchCmd.Flags().StringP("subject", "s", "",
		"List all referrers for this subject. The subject can be specified by tag(repo:tag) or by digest"+
			"(repo@digest)")

	searchCmd.Flags().StringVar(servURL, cmdflags.URLFlag, "", "Specify zot server URL if config-name is not mentioned")
	searchCmd.Flags().StringVarP(user, cmdflags.UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	searchCmd.PersistentFlags().StringVarP(outputFormat, cmdflags.OutputFormatFlag, "f", "",
		"Specify output format [text/json/yaml]")
	searchCmd.PersistentFlags().BoolVar(verbose, cmdflags.VerboseFlag, false, "Show verbose output")
	searchCmd.PersistentFlags().BoolVar(debug, cmdflags.DebugFlag, false, "Show debug output")
}

func globalSearch(searchConfig searchConfig) error {
	var searchers []searcher

	if checkExtEndPoint(searchConfig) {
		searchers = getGlobalSearchersGQL()
	} else {
		searchers = getGlobalSearchersREST()
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
