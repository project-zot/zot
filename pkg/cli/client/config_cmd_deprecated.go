//go:build search

package client

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/v2/errors"
)

// runLegacyConfig handles deprecated positional syntax and --list/--reset on the parent command.
// Prefer subcommands (list, show, get, set, reset); this file emits deprecation warnings to stderr.
func runLegacyConfig(cmd *cobra.Command, args []string, configPath string, isListing, isReset bool) error {
	switch len(args) {
	case noArgs:
		if isListing { // zli config -l
			warnLegacyDeprecatedInvocation(cmd.ErrOrStderr(), "`zli config --list`", "`zli config list`")

			res, err := getConfigNames(configPath)
			if err != nil {
				return err
			}

			fmt.Fprint(cmd.OutOrStdout(), res)

			return nil
		}

		return zerr.ErrInvalidArgs
	case oneArg:
		// zli config <name> -l
		if isListing {
			warnLegacyDeprecatedInvocation(cmd.ErrOrStderr(), "`zli config <name> --list`", "`zli config show <name>`")

			res, err := getAllConfig(configPath, args[0])
			if err != nil {
				return err
			}

			fmt.Fprint(cmd.OutOrStdout(), res)

			return nil
		}

		return zerr.ErrInvalidArgs
	case twoArgs:
		if isReset { // zli config <name> <key> --reset
			warnLegacyDeprecatedInvocation(
				cmd.ErrOrStderr(),
				"`zli config <name> <key> --reset`",
				"`zli config reset <name> <key>`",
			)

			return resetConfigValue(configPath, args[0], args[1])
		}

		warnLegacyDeprecatedInvocation(cmd.ErrOrStderr(), "`zli config <name> <key>`", "`zli config get <name> <key>`")

		res, err := getConfigValue(configPath, args[0], args[1])
		if err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), res)

	case threeArgs:
		warnLegacyDeprecatedInvocation(
			cmd.ErrOrStderr(),
			"`zli config <name> <key> <value>`",
			"`zli config set <name> <key> <value>`",
		)

		if err := setConfigValue(configPath, args[0], args[1], args[2]); err != nil {
			return err
		}

	default:
		return zerr.ErrInvalidArgs
	}

	return nil
}

func warnLegacyDeprecatedInvocation(w io.Writer, invoked, replacement string) {
	fmt.Fprintf(w, "Warning: deprecated invocation %s; use %s instead.\n", invoked, replacement)
}
