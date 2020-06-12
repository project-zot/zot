package cli

import (
	"fmt"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

func NewCveCommand(searchService CveSearchService) *cobra.Command {
	searchCveParams := make(map[string]*string)

	var servURL string

	var user string

	var cveCmd = &cobra.Command{
		Use:   "cve",
		Short: "Find CVEs",
		Long:  `Find CVEs (Common Vulnerabilities and Exposures)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			spin := spinner.New(spinner.CharSets[39], spinnerDuration, spinner.WithWriter(cmd.ErrOrStderr()))
			spin.Prefix = "Searching... "

			if cmd.Flags().NFlag() == 1 {
				return zotErrors.ErrInvalidArgs
			}

			spin.Start()

			result, err := searchCve(searchCveParams, searchService, &servURL, &user)

			spin.Stop()

			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), result)

			return nil
		},
	}

	setupCmdFlags(cveCmd, searchCveParams)
	setupCommonFlags(cveCmd, &servURL, &user)
	cveCmd.SetUsageTemplate(cveCmd.UsageTemplate() + allowedCombinations)

	return cveCmd
}

func NewImageCommand(searchService CveSearchService) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL string

	var user string

	var imageCmd = &cobra.Command{
		Use:   "image",
		Short: "Find images",
		Long:  `Find images in zot repository`,
		RunE: func(cmd *cobra.Command, args []string) error {
			spin := spinner.New(spinner.CharSets[39], spinnerDuration, spinner.WithWriter(cmd.ErrOrStderr()))
			spin.Prefix = "Searching... "

			if cmd.Flags().NFlag() == 1 {
				return zotErrors.ErrInvalidArgs
			}

			spin.Start()

			result, err := searchCve(searchImageParams, searchService, &servURL, &user)

			spin.Stop()

			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), result)

			return nil
		},
	}

	searchImageParams = make(map[string]*string)

	setupImageFlags(imageCmd, searchImageParams)
	setupCommonFlags(imageCmd, &servURL, &user)

	return imageCmd
}

func setupCommonFlags(cmd *cobra.Command, servURL *string, user *string) {
	cmd.Flags().StringVar(servURL, "url", "", "Specify zot server URL [required]")
	_ = cmd.MarkFlagRequired("url")
	cmd.Flags().StringVarP(user, "user", "u", "", `User Credentials of zot server in "username:password" format`)
}

func setupCmdFlags(cveCmd *cobra.Command, searchCveParams map[string]*string) {
	searchCveParams["imageName"] = cveCmd.Flags().StringP("image-name", "I", "", "Specify image name")
	searchCveParams["tag"] = cveCmd.Flags().StringP("tag", "t", "", "Specify tag")
	searchCveParams["packageName"] = cveCmd.Flags().StringP("package-name", "p", "", "Specify package name")
	searchCveParams["packageVersion"] = cveCmd.Flags().StringP("package-version", "V", "", "Specify package version")
	searchCveParams["packageVendor"] = cveCmd.Flags().StringP("package-vendor", "d", "", "Specify package vendor")
	searchCveParams["cveID"] = cveCmd.Flags().StringP("cve-id", "i", "", "Find by CVE-ID")
}

func setupImageFlags(imageCmd *cobra.Command, searchImageParams map[string]*string) {
	searchImageParams["cveIDForImage"] = imageCmd.Flags().StringP("cve-id", "c", "", "Find by CVE-ID")
}

func searchCve(params map[string]*string, service CveSearchService, servURL, user *string) (string, error) {
	for _, searcher := range getSearchers() {
		results, err := searcher.search(params, service, servURL, user)
		if err != nil {
			if err == ErrCannotSearch {
				continue
			} else {
				return "", err
			}
		} else {
			return results, nil
		}
	}

	return "", zotErrors.ErrInvalidFlagsCombination
}

const (
	spinnerDuration = 150 * time.Millisecond
)
