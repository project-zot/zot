//go:build search

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/v2/errors"
)

func NewConfigCommand() *cobra.Command {
	var isListing bool

	var isReset bool

	configCmd := &cobra.Command{
		Use:     "config",
		Example: examples,
		Short:   "Configure zot registry parameters for CLI",
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !isListing && !isReset {
				_ = cmd.Help()

				return nil
			}

			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			return runLegacyConfig(cmd, args, configPath, isListing, isReset)
		},
	}

	configCmd.Flags().BoolVarP(&isListing, "list", "l", false,
		"[deprecated: use \"config list\" or \"config show <name>\"] List configurations")

	configCmd.Flags().BoolVar(&isReset, "reset", false,
		"[deprecated: use \"config reset\"] Reset a variable value")

	configCmd.SetUsageTemplate(configCmd.UsageTemplate() + supportedOptions)
	configCmd.AddCommand(NewConfigAddCommand())
	configCmd.AddCommand(NewConfigRemoveCommand())
	configCmd.AddCommand(NewConfigListCommand())
	configCmd.AddCommand(NewConfigShowCommand())
	configCmd.AddCommand(NewConfigGetCommand())
	configCmd.AddCommand(NewConfigSetCommand())
	configCmd.AddCommand(NewConfigResetCommand())
	configCmd.AddCommand(NewConfigSetDefaultCommand())
	configCmd.AddCommand(NewConfigClearDefaultCommand())

	// Build this from actual subcommands to avoid drift.
	reserved := strings.Join(reservedProfileNames(configCmd), ", ")
	configCmd.Long = fmt.Sprintf(`Configure zot registry parameters for CLI.

Use the list, show, get, set, reset, set-default, and clear-default subcommands for inspecting and editing profiles.
Profile names must not collide with subcommand names (%s).

Older positional syntax on this command is deprecated and will soon be removed.`, reserved)

	return configCmd
}

func exactArgsOrHelp(expected int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != expected {
			_ = cmd.Help()

			return zerr.ErrInvalidArgs
		}

		return nil
	}
}

func zliUserConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".zot"), nil
}

// validateProfileNameForCreation prevents creating profiles that shadow subcommand names.
// We intentionally allow interacting with pre-existing profiles that collide with subcommand names
// so users can migrate/rename/remove them without editing ~/.zot by hand.
func validateProfileNameForCreation(configCmd *cobra.Command, name string) error {
	if slices.Contains(reservedProfileNames(configCmd), name) {
		return fmt.Errorf("%w: %q", zerr.ErrReservedConfigName, name)
	}

	return nil
}

func reservedProfileNames(configCmd *cobra.Command) []string {
	seen := make(map[string]struct{})

	for _, sub := range configCmd.Commands() {
		name := sub.Name()
		if name == "" {
			continue
		}

		seen[name] = struct{}{}
	}

	reserved := make([]string, 0, len(seen))
	for name := range seen {
		reserved = append(reserved, name)
	}

	sort.Strings(reserved)

	return reserved
}

func NewConfigAddCommand() *cobra.Command {
	configAddCmd := &cobra.Command{
		Use:          "add <config-name> <url>",
		Example:      "  zli config add main https://zot-foo.com:8080",
		Short:        "Add configuration for a zot registry",
		Long:         "Add configuration for a zot registry",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(twoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			configRoot := cmd.Parent()
			if configRoot == nil {
				configRoot = cmd
			}

			if err := validateProfileNameForCreation(configRoot, args[0]); err != nil {
				return err
			}

			err = addConfig(configPath, args[0], args[1])
			if err != nil {
				return err
			}

			return nil
		},
	}

	// Prevent parent template from overwriting default template
	configAddCmd.SetUsageTemplate(configAddCmd.UsageTemplate())

	return configAddCmd
}

func NewConfigRemoveCommand() *cobra.Command {
	configRemoveCmd := &cobra.Command{
		Use:          "remove <config-name>",
		Example:      "  zli config remove main",
		Short:        "Remove configuration for a zot registry",
		Long:         "Remove configuration for a zot registry. Removing the default profile also clears the default.",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(oneArg),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			err = removeConfig(configPath, args[0])
			if err != nil {
				return err
			}

			return nil
		},
	}

	// Prevent parent template from overwriting default template
	configRemoveCmd.SetUsageTemplate(configRemoveCmd.UsageTemplate())

	return configRemoveCmd
}

func NewConfigListCommand() *cobra.Command {
	listCmd := &cobra.Command{
		Use:     "list",
		Example: "  zli config list",
		Short:   "List all configuration profile names",
		Long:    "Print every configured CLI profile name (and URLs where applicable).",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			res, err := getConfigNames(configPath)
			if err != nil {
				return err
			}

			fmt.Fprint(cmd.OutOrStdout(), res)

			return nil
		},
	}

	listCmd.SetUsageTemplate(listCmd.UsageTemplate())

	return listCmd
}

func NewConfigShowCommand() *cobra.Command {
	showCmd := &cobra.Command{
		Use:          "show <name>",
		Example:      "  zli config show main",
		Short:        "Show all variables for one profile",
		Long:         "Print every variable set for the named CLI profile.",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(oneArg),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			res, err := getAllConfig(configPath, args[0])
			if err != nil {
				return err
			}

			fmt.Fprint(cmd.OutOrStdout(), res)

			return nil
		},
	}

	showCmd.SetUsageTemplate(showCmd.UsageTemplate())

	return showCmd
}

func NewConfigGetCommand() *cobra.Command {
	getCmd := &cobra.Command{
		Use:          "get <name> <key>",
		Example:      "  zli config get main url",
		Short:        "Print one configuration variable",
		Long:         "Print the value of a single key for the named profile.",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(twoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			res, err := getConfigValue(configPath, args[0], args[1])
			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), res)

			return nil
		},
	}

	getCmd.SetUsageTemplate(getCmd.UsageTemplate())

	return getCmd
}

func NewConfigSetCommand() *cobra.Command {
	setCmd := &cobra.Command{
		Use:          "set <name> <key> <value>",
		Example:      "  zli config set main showspinner false",
		Short:        "Set a configuration variable",
		Long:         "Set a single key for the named profile and persist ~/.zot.",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(threeArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			return setConfigValue(configPath, args[0], args[1], args[2])
		},
	}

	setCmd.SetUsageTemplate(setCmd.UsageTemplate())

	return setCmd
}

func NewConfigResetCommand() *cobra.Command {
	resetCmd := &cobra.Command{
		Use:          "reset <name> <key>",
		Example:      "  zli config reset main showspinner",
		Short:        "Reset a configuration variable to its default",
		Long:         "Remove a non-default key from the named profile (URL and profile name cannot be reset).",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(twoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			return resetConfigValue(configPath, args[0], args[1])
		},
	}

	resetCmd.SetUsageTemplate(resetCmd.UsageTemplate())

	return resetCmd
}

func NewConfigSetDefaultCommand() *cobra.Command {
	setDefaultCmd := &cobra.Command{
		Use:          "set-default <name>",
		Example:      "  zli config set-default main",
		Short:        "Set the default configuration profile",
		Long:         "Set the default profile used when neither --url nor --config is provided.",
		SilenceUsage: true,
		Args:         exactArgsOrHelp(oneArg),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			return setDefaultConfig(configPath, args[0])
		},
	}

	setDefaultCmd.SetUsageTemplate(setDefaultCmd.UsageTemplate())

	return setDefaultCmd
}

func NewConfigClearDefaultCommand() *cobra.Command {
	clearDefaultCmd := &cobra.Command{
		Use:          "clear-default",
		Example:      "  zli config clear-default",
		Short:        "Clear the default configuration profile",
		Long:         "Clear the default profile. Commands will again require --url or --config.",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := zliUserConfigPath()
			if err != nil {
				return err
			}

			return clearDefaultConfig(configPath)
		},
	}

	clearDefaultCmd.SetUsageTemplate(clearDefaultCmd.UsageTemplate())

	return clearDefaultCmd
}

func getConfigNames(configPath string) (string, error) {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return "", nil
		}

		return "", err
	}

	return cfg.FormatNames()
}

func addConfig(configPath, configName, url string) error {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if !isConfigUnavailable(err) {
			return err
		}

		cfg = &ZliConfigFile{}
	}

	if err := cfg.AddEntry(configName, url); err != nil {
		return err
	}

	return cfg.WriteFile(configPath)
}

func removeConfig(configPath, configName string) error {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return zerr.ErrConfigNotFound
		}

		return err
	}

	if err := cfg.RemoveEntry(configName); err != nil {
		return err
	}

	return cfg.WriteFile(configPath)
}

func setDefaultConfig(configPath, configName string) error {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return zerr.ErrConfigNotFound
		}

		return err
	}

	if err := cfg.SetDefault(configName); err != nil {
		return err
	}

	return cfg.WriteFile(configPath)
}

func clearDefaultConfig(configPath string) error {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return nil
		}

		return err
	}

	cfg.ClearDefault()

	return cfg.WriteFile(configPath)
}

func getConfigValue(configPath, configName, key string) (string, error) {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return "", zerr.ErrConfigNotFound
		}

		return "", err
	}

	c, err := cfg.Find(configName)
	if err != nil {
		return "", err
	}

	return c.GetVar(key)
}

func resetConfigValue(configPath, configName, key string) error {
	if key == URLFlag || key == nameKey {
		return zerr.ErrCannotResetConfigKey
	}

	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return zerr.ErrConfigNotFound
		}

		return err
	}

	c, err := cfg.Find(configName)
	if err != nil {
		return err
	}

	if err := c.ResetVar(key); err != nil {
		return err
	}

	return cfg.WriteFile(configPath)
}

func setConfigValue(configPath, configName, key, value string) error {
	if key == nameKey {
		return zerr.ErrIllegalConfigKey
	}

	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return zerr.ErrConfigNotFound
		}

		return err
	}

	c, err := cfg.Find(configName)
	if err != nil {
		return err
	}

	if err := c.SetVar(key, value); err != nil {
		return err
	}

	return cfg.WriteFile(configPath)
}

func getAllConfig(configPath, configName string) (string, error) {
	cfg, err := ReadZliConfigFile(configPath)
	if err != nil {
		if isConfigUnavailable(err) {
			return "", nil
		}

		return "", err
	}

	profile, err := cfg.Find(configName)
	if err != nil {
		return "", err
	}

	defaultName, err := cfg.DefaultName()
	if err != nil {
		return "", err
	}

	return profile.formatListedVars(defaultName == configName), nil
}

const (
	examples = `  zli config add main https://zot-foo.com:8080
  zli config list
  zli config show main
  zli config get main url
  zli config set main showspinner false
  zli config reset main showspinner
  zli config set-default main
  zli config clear-default
  zli config remove main`

	supportedOptions = `
Useful variables:
  url		zot server URL
  showspinner	show spinner while loading data [true/false]
  verify-tls	enable TLS certificate verification of the server [default: true]
`

	noArgs    = 0
	oneArg    = 1
	twoArgs   = 2
	threeArgs = 3
)
