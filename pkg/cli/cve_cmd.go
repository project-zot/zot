//go:build search
// +build search

package cli

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"

	zerr "zotregistry.io/zot/errors"
)

const (
	cveDBRetryInterval = 3
)

func NewCveCommand(searchService SearchService) *cobra.Command {
	searchCveParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, fixedFlag, verbose, debug bool

	cveCmd := &cobra.Command{
		Use:   "cve [config-name]",
		Short: "DEPRECATED (see cves)",
		Long:  `DEPRECATED (see cves)! List CVEs (Common Vulnerabilities and Exposures) of images hosted on the zot registry`,
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
			spin.Prefix = fmt.Sprintf("Fetching from %s..", servURL)
			spin.Suffix = "\n\b"

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
				debug:         &debug,
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
		debug:           &debug,
	}

	setupCveFlags(cveCmd, vars)

	return cveCmd
}

func setupCveFlags(cveCmd *cobra.Command, variables cveFlagVariables) {
	variables.searchCveParams["imageName"] = cveCmd.Flags().StringP("image", "I", "", "List CVEs by IMAGENAME[:TAG]")
	variables.searchCveParams["cveID"] = cveCmd.Flags().StringP("cve-id", "i", "", "List images affected by a CVE")
	variables.searchCveParams["searchedCVE"] = cveCmd.Flags().StringP("search", "s", "", "Search specific CVEs by name/id")

	cveCmd.Flags().StringVar(variables.servURL, "url", "", "Specify zot server URL if config-name is not mentioned")
	cveCmd.Flags().StringVarP(variables.user, "user", "u", "", `User Credentials of `+
		`zot server in USERNAME:PASSWORD format`)
	cveCmd.Flags().StringVarP(variables.outputFormat, "output", "o", "", "Specify output format [text/json/yaml]."+
		" JSON and YAML format return all info for CVEs")

	cveCmd.Flags().BoolVar(variables.fixedFlag, "fixed", false, "List tags which have fixed a CVE")
	cveCmd.Flags().BoolVar(variables.debug, "debug", false, "Show debug output")
}

type cveFlagVariables struct {
	searchCveParams map[string]*string
	servURL         *string
	user            *string
	outputFormat    *string
	fixedFlag       *bool
	debug           *bool
}

func searchCve(searchConfig searchConfig) error {
	var searchers []searcher

	if checkExtEndPoint(searchConfig) {
		searchers = getCveSearchersGQL()
	} else {
		searchers = getCveSearchers()
	}

	for _, searcher := range searchers {
		// there can be CVE DB readiness issues on the server side
		// we need a retry mechanism for that specific type of errors
		maxAttempts := 20

		for i := 0; i < maxAttempts; i++ {
			found, err := searcher.search(searchConfig)
			if !found {
				// searcher does not support this searchConfig
				// exit the attempts loop and try a different searcher
				break
			}

			if err == nil {
				// searcher matcher search config and results are already printed
				return nil
			}

			if i+1 >= maxAttempts {
				// searcher matches search config but there are errors
				// this is the last attempt and we cannot retry
				return err
			}

			if strings.Contains(err.Error(), zerr.ErrCVEDBNotFound.Error()) {
				// searches matches search config but CVE DB is not ready server side
				// wait and retry a few more times
				fmt.Fprintln(searchConfig.resultWriter,
					"[warning] CVE DB is not ready [", i, "] - retry in ", cveDBRetryInterval, " seconds")
				time.Sleep(cveDBRetryInterval * time.Second)

				continue
			}

			// an unrecoverable error occurred
			return err
		}
	}

	return zerr.ErrInvalidFlagsCombination
}
