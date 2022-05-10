//go:build (minimal || sync || scrub || metrics) && !search && !ui_base
// +build minimal sync scrub metrics
// +build !search
// +build !ui_base

package cli

import "github.com/spf13/cobra"

func enableCli(rootCmd *cobra.Command) {
}
