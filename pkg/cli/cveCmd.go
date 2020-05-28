package cli

import (
	"errors"
	"fmt"

	zotErrors "github.com/anuvu/zot/errors"

	"github.com/spf13/cobra"
)

var searchParams = make(map[string]*string)

func init() {
	searchCmd.AddCommand(cveCmd)
	searchCmd.AddCommand(imageCmd)
	setupFlags()

	cveCmd.SetUsageTemplate(cveCmd.UsageTemplate() + allowedCombinations)
}

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "Find CVEs",
	Long:  `Find CVEs (Common Vulnerabilities and Exposures)`,
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.Flags().NFlag() == 0 {
			if err := cmd.Usage(); err != nil {
				panic(err)
			}
			panic(zotErrors.ErrInvalidArgs) //TODO to panic or not to panic
		}
		err := searchCve(searchParams)
		if err != nil {
			cmd.PrintErrln(err.Error())
			cmd.PrintErrln()
			if err := cmd.Usage(); err != nil {
				panic(err)
			}
		}

	},
}

func setupFlags() {
	searchParams["imageName"] = cveCmd.Flags().StringP("image-name", "I", "", "Specify image name")
	searchParams["tag"] = cveCmd.Flags().StringP("tag", "t", "", "Specify tag")
	searchParams["packageName"] = cveCmd.Flags().StringP("package-name", "p", "", "Specify package name")
	searchParams["packageVersion"] = cveCmd.Flags().StringP("package-version", "V", "", "Specify package version")
	searchParams["packageVendor"] = cveCmd.Flags().StringP("package-vendor", "d", "", "Specify package vendor")
	searchParams["cveID"] = cveCmd.Flags().StringP("cve-id", "i", "", "Find by CVE-ID")
	searchParams["cveIDForImage"] = imageCmd.Flags().StringP("cve-id", "c", "", "Find by CVE-ID")
}

func searchCve(params map[string]*string) error {
	foundResults := false
	for _, searcher := range getSearchers() {
		results, err := searcher.search(params)
		if err == nil {
			foundResults = true
			fmt.Println(results)
			break
		}
	}

	if !foundResults {
		return errors.New("Invalid combination of arguments") // TODO error handling and printing updated help/usage
	}
	return nil
}

var imageCmd = &cobra.Command{
	Use:   "image",
	Short: "Find images",
	Long:  `Find images`,
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.Flags().NFlag() == 0 {
			if err := cmd.Usage(); err != nil {
				panic(err)
			}
			panic(zotErrors.ErrInvalidArgs)
		}
		err := searchCve(searchParams)
		if err != nil {
			cmd.PrintErrln(err.Error())
			cmd.PrintErrln()
			if err := cmd.Usage(); err != nil {
				panic(err)
			}
		}
	},
}
