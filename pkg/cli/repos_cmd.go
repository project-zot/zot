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

const prefix = "Searching... "

func NewRepoCommand(searchService SearchService) *cobra.Command {
	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, verbose, debug bool

	repoCmd := &cobra.Command{
		Use:   "repos [config-name]",
		Short: "List all repositories",
		Long:  `List all repositories`,
		Args:  cobra.MaximumNArgs(1),
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

			err = listRepos(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true

				return err
			}

			return nil
		},
	}

	repoCmd.SetUsageTemplate(repoCmd.UsageTemplate() + usageFooter)

	repoCmd.AddCommand(NewListReposCommand(searchService))

	repoCmd.Flags().StringVar(&servURL, cmdflags.URLFlag, "", "Specify zot server URL if config-name is not mentioned")
	repoCmd.Flags().StringVarP(&user, cmdflags.UserFlag, "u", "",
		`User Credentials of zot server in "username:password" format`)
	repoCmd.Flags().BoolVar(&debug, cmdflags.DebugFlag, false, "Show debug output")

	return repoCmd
}

func listRepos(searchConfig searchConfig) error {
	searcher := new(repoSearcher)
	err := searcher.searchRepos(searchConfig)

	return err
}
