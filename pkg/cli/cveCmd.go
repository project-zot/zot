package cli

import (
	"fmt"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

var searchCveParams map[string]*string
var searchImageParams map[string]*string
var service CveSearchService
var servURL string

func NewCveCommand(searchService CveSearchService) *cobra.Command {
	var cveCmd = &cobra.Command{
		Use:   "cve",
		Short: "Find CVEs",
		Long:  `Find CVEs (Common Vulnerabilities and Exposures)`,
		RunE:  runCveE,
	}
	searchCveParams = make(map[string]*string)
	setupFlags(cveCmd)
	cveCmd.SetUsageTemplate(cveCmd.UsageTemplate() + allowedCombinations)
	service = searchService
	return cveCmd
}

func NewImageCommand(searchService CveSearchService) *cobra.Command {
	var imageCmd = &cobra.Command{
		Use:   "image",
		Short: "Find images",
		Long:  `Find images in zot repository`,
		RunE:  runImageE,
	}
	searchImageParams = make(map[string]*string)
	setupImageFlags(imageCmd)
	service = searchService
	return imageCmd
}

func runCveE(cmd *cobra.Command, args []string) error {
	spin := spinner.New(spinner.CharSets[39], 150*time.Millisecond, spinner.WithWriter(cmd.ErrOrStderr()))
	spin.Prefix = "Searching... "
	if cmd.Flags().NFlag() == 1 {
		spin.Stop()
		return zotErrors.ErrInvalidArgs
	}
	spin.Start()
	result, err := searchCve(searchCveParams)
	spin.Stop()
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), result)
	return nil
}

func runImageE(cmd *cobra.Command, args []string) error {
	spin := spinner.New(spinner.CharSets[39], 150*time.Millisecond, spinner.WithWriter(cmd.ErrOrStderr()))
	spin.Prefix = "Searching... "
	if cmd.Flags().NFlag() == 1 {
		return zotErrors.ErrInvalidArgs
	}
	spin.Start()
	result, err := searchCve(searchImageParams)
	spin.Stop()
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), result)
	return nil
}

func setupFlags(cveCmd *cobra.Command) {
	searchCveParams["imageName"] = cveCmd.Flags().StringP("image-name", "I", "", "Specify image name")
	searchCveParams["tag"] = cveCmd.Flags().StringP("tag", "t", "", "Specify tag")
	searchCveParams["packageName"] = cveCmd.Flags().StringP("package-name", "p", "", "Specify package name")
	searchCveParams["packageVersion"] = cveCmd.Flags().StringP("package-version", "V", "", "Specify package version")
	searchCveParams["packageVendor"] = cveCmd.Flags().StringP("package-vendor", "d", "", "Specify package vendor")
	searchCveParams["cveID"] = cveCmd.Flags().StringP("cve-id", "i", "", "Find by CVE-ID")
	cveCmd.Flags().StringVar(&servURL, "url", "", "Specify zot server URL [required]")
	_ = cveCmd.MarkFlagRequired("url")
}

func setupImageFlags(imageCmd *cobra.Command) {
	searchImageParams["cveIDForImage"] = imageCmd.Flags().StringP("cve-id", "c", "", "Find by CVE-ID")
	imageCmd.Flags().StringVar(&servURL, "url", "", "Specify zot server URL [required]")
	_ = imageCmd.MarkFlagRequired("url")

}

func searchCve(params map[string]*string) (string, error) {
	for _, searcher := range getSearchers() {
		results, err := searcher.search(params, service)
		if err != nil {
			if err == cannotSearchError {
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
