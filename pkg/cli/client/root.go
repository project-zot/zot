//go:build search

package client

import (
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/spf13/cobra"

	"zotregistry.dev/zot/v2/pkg/buildinfo"
	"zotregistry.dev/zot/v2/pkg/log"
)

// NewCliRootCmd creates the root command for "zli" - client-side cli.
func NewCliRootCmd() *cobra.Command {
	showVersion := false

	rootCmd := &cobra.Command{
		Use:   "zli",
		Short: "`zli`",
		Long:  "`zli`",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				logger := log.NewLogger("info", "")
				logger.Info().Str("distribution-spec", distspec.Version).Str("commit", buildinfo.Commit).
					Str("binary-type", buildinfo.BinaryType).Str("go version", buildinfo.GoVersion).Msg("version")
			} else {
				_ = cmd.Usage()
				cmd.SilenceErrors = false
			}
		},
	}

	rootCmd.SilenceUsage = true

	// additional cmds
	enableCli(rootCmd)
	// "version"
	rootCmd.Flags().BoolVarP(&showVersion, VersionFlag, "v", false, "show the version and exit")

	return rootCmd
}
