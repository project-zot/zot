package cli

import (
	zotErrors "github.com/anuvu/zot/errors"

	"github.com/spf13/cobra"
)

var searchParams = make(map[string]*string)

func NewCveCommand() *cobra.Command {
	var cveCmd = &cobra.Command{
		Use:   "cve",
		Short: "Find CVEs",
		Long:  `Find CVEs (Common Vulnerabilities and Exposures)`,
		RunE:  runE,
	}

	setupFlags(cveCmd)
	cveCmd.SetUsageTemplate(cveCmd.UsageTemplate() + allowedCombinations)

	return cveCmd
}

func NewImageCommand() *cobra.Command {
	var imageCmd = &cobra.Command{
		Use:   "image",
		Short: "Find images",
		Long:  `Find images`,
		RunE:  runE,
	}
	setupImageFlags(imageCmd)
	return imageCmd
}

func runE(cmd *cobra.Command, args []string) error {
	if cmd.Flags().NFlag() == 0 {
		return zotErrors.ErrInvalidArgs
	}
	result, err := searchCve(searchParams)
	if err != nil {
		return err
	}
	cmd.Println(result)
	return nil
}

func setupFlags(cveCmd *cobra.Command) {
	searchParams["imageName"] = cveCmd.Flags().StringP("image-name", "I", "", "Specify image name")
	searchParams["tag"] = cveCmd.Flags().StringP("tag", "t", "", "Specify tag")
	searchParams["packageName"] = cveCmd.Flags().StringP("package-name", "p", "", "Specify package name")
	searchParams["packageVersion"] = cveCmd.Flags().StringP("package-version", "V", "", "Specify package version")
	searchParams["packageVendor"] = cveCmd.Flags().StringP("package-vendor", "d", "", "Specify package vendor")
	searchParams["cveID"] = cveCmd.Flags().StringP("cve-id", "i", "", "Find by CVE-ID")
}

func setupImageFlags(imageCmd *cobra.Command) {
	searchParams["cveIDForImage"] = imageCmd.Flags().StringP("cve-id", "c", "", "Find by CVE-ID")
}

func searchCve(params map[string]*string) (string, error) {
	for _, searcher := range getSearchers() {
		results, err := searcher.search(params)
		if err == nil {
			return results, nil
		}
	}

	return "", zotErrors.ErrInvalidFlagsCombination

}
