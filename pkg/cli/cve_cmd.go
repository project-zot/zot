//go:build extended
// +build extended

package cli

import (
	"fmt"
	"os"
	"path"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	zotErrors "zotregistry.io/zot/errors"
)

func NewCveCommand(searchService SearchService) *cobra.Command {
	searchCveParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, fixedFlag, verbose bool

	cveCmd := &cobra.Command{
		Use:   "cve [config-name]",
		Short: "Lookup CVEs in images hosted on zot",
		Long:  `List CVEs (Common Vulnerabilities and Exposures) of images hosted on a zot instance`,
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
			spin.Prefix = fmt.Sprintf("Fetching from %s.. ", servURL)

			verbose = false

			searchConfig := searchConfig{
				params:        searchCveParams,
				searchService: searchService,
				servURL:       &servURL,
				user:          &user,
				outputFormat:  &outputFormat,
				fixedFlag:     &fixedFlag,
				verifyTLS:     &verifyTLS,
				verbose:       &verbose,
				resultWriter:  cmd.OutOrStdout(),
				spinner:       spinnerState{spin, isSpinner},
			}

			err = searchCve(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true

				return err
			}

			return nil
		},
	}

	vars := cveFlagVariables{
		searchCveParams: searchCveParams,
		servURL:         &servURL,
		user:            &user,
		outputFormat:    &outputFormat,
		fixedFlag:       &fixedFlag,
	}

	setupCveFlags(cveCmd, vars)

	return cveCmd
}

func setupCveFlags(cveCmd *cobra.Command, variables cveFlagVariables) {
	variables.searchCveParams["imageName"] = cveCmd.Flags().StringP("image", "I", "", "List CVEs by IMAGENAME[:TAG]")
	variables.searchCveParams["cvid"] = cveCmd.Flags().StringP("cve-id", "i", "", "List images affected by a CVE")

	cveCmd.Flags().StringVar(variables.servURL, "url", "", "Specify zot server URL if config-name is not mentioned")
	cveCmd.Flags().StringVarP(variables.user, "user", "u", "", `User Credentials of `+
		`zot server in USERNAME:PASSWORD format`)
	cveCmd.Flags().StringVarP(variables.outputFormat, "output", "o", "", "Specify output format [text/json/yaml]."+
		" JSON and YAML format return all info for CVEs")

	cveCmd.Flags().BoolVar(variables.fixedFlag, "fixed", false, "List tags which have fixed a CVE")
}

type cveFlagVariables struct {
	searchCveParams map[string]*string
	servURL         *string
	user            *string
	outputFormat    *string
	fixedFlag       *bool
}

func searchCve(searchConfig searchConfig) error {
	for _, searcher := range getCveSearchers() {
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
