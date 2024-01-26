package main

import (
	"os"

	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"zotregistry.dev/zot/pkg/api/config"
)

// "zb" - performance benchmark and stress.
func NewPerfRootCmd() *cobra.Command {
	showVersion := false

	var auth, workdir, repo, outFmt, srcIPs, srcCIDR string

	var concurrency, requests int

	var skipCleanup bool

	rootCmd := &cobra.Command{
		Use:   "zb <url>",
		Short: "`zb`",
		Long:  "`zb`",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				log.Info().Str("distribution-spec", distspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Str("go version", config.GoVersion).Msg("version")
			}

			if len(args) == 0 {
				_ = cmd.Usage()
				cmd.SilenceErrors = false

				return
			}

			url := ""
			if len(args) > 0 {
				url = args[0]
			}

			if requests < concurrency {
				panic("requests cannot be less than concurrency")
			}

			requests = concurrency * (requests / concurrency)

			Perf(workdir, url, auth, repo, concurrency, requests, outFmt, srcIPs, srcCIDR, skipCleanup)
		},
	}

	rootCmd.Flags().StringVarP(&auth, "auth-creds", "A", "",
		"Use colon-separated BASIC auth creds")
	rootCmd.Flags().StringVarP(&srcIPs, "src-ips", "i", "",
		"Use colon-separated ips to make requests from, src-ips and src-cidr are mutually exclusive")
	rootCmd.Flags().StringVarP(&srcCIDR, "src-cidr", "s", "",
		"Use specified cidr to obtain ips to make requests from, src-ips and src-cidr are mutually exclusive")
	rootCmd.Flags().StringVarP(&workdir, "working-dir", "d", "",
		"Use specified directory to store test data")
	rootCmd.Flags().StringVarP(&repo, "repo", "r", "",
		"Use specified repo on remote registry for test data")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 1,
		"Number of multiple requests to make at a time")
	rootCmd.Flags().IntVarP(&requests, "requests", "n", 1,
		"Number of requests to perform")
	rootCmd.Flags().StringVarP(&outFmt, "output-format", "o", "",
		"Output format of test results: stdout (default), json, ci-cd")
	rootCmd.Flags().BoolVar(&skipCleanup, "skip-cleanup", false,
		"Clean up pushed repos from remote registry after running benchmark (default true)")

	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show the version and exit")

	return rootCmd
}

func main() {
	if err := NewPerfRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
