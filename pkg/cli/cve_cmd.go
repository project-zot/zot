//go:build search
// +build search

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	"gopkg.in/resty.v1"
	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
)

func NewCveCommand(searchService SearchService) *cobra.Command {
	searchCveParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var isSpinner, verifyTLS, fixedFlag, verbose, debug bool

	cveCmd := &cobra.Command{
		Use:   "cve [config-name]",
		Short: "Lookup CVEs in images hosted on the zot registry",
		Long:  `List CVEs (Common Vulnerabilities and Exposures) of images hosted on the zot registry`,
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

type field struct {
	Name string `json:"name"`
}

type schemaList struct {
	Data struct {
		Schema struct {
			QueryType struct {
				Fields []field `json:"fields"`
			} `json:"queryType"` //nolint:tagliatelle // graphQL schema
		} `json:"__schema"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

func containsGQLQuery(queryList []field, query string) bool {
	for _, q := range queryList {
		if q.Name == query {
			return true
		}
	}

	return false
}

func checkExtEndPoint(serverURL string) bool {
	client := resty.New()

	extEndPoint, err := combineServerAndEndpointURL(serverURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtOciDiscoverPrefix))
	if err != nil {
		return false
	}

	//nolint: gosec
	resp, err := client.R().Get(extEndPoint)
	if err != nil || resp.StatusCode() != http.StatusOK {
		return false
	}

	searchEndPoint, _ := combineServerAndEndpointURL(serverURL, constants.ExtSearchPrefix)

	query := `
        {
            __schema() {
                queryType {
                    fields {
                        name
                    }
                }
            }
        }`

	resp, err = client.R().Get(searchEndPoint + "?query=" + url.QueryEscape(query))
	if err != nil || resp.StatusCode() != http.StatusOK {
		return false
	}

	queryList := &schemaList{}

	_ = json.Unmarshal(resp.Body(), queryList)

	return containsGQLQuery(queryList.Data.Schema.QueryType.Fields, "ImageList")
}

func searchCve(searchConfig searchConfig) error {
	var searchers []searcher

	if checkExtEndPoint(*searchConfig.servURL) {
		searchers = getCveSearchersGQL()
	} else {
		searchers = getCveSearchers()
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
