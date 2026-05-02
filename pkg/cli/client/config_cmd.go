//go:build search

package client

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/v2/errors"
)

func NewConfigCommand() *cobra.Command {
	var isListing bool

	var isReset bool

	configCmd := &cobra.Command{
		Use:     "config <config-name> [variable] [value]",
		Example: examples,
		Short:   "Configure zot registry parameters for CLI",
		Long:    `Configure zot registry parameters for CLI`,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			configPath := filepath.Join(home, ".zot")

			switch len(args) {
			case noArgs:
				if isListing { // zli config -l
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
					return resetConfigValue(configPath, args[0], args[1])
				}
				// zli config <name> <key>
				res, err := getConfigValue(configPath, args[0], args[1])
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), res)
			case threeArgs:
				// zli config <name> <key> <value>
				if err := setConfigValue(configPath, args[0], args[1], args[2]); err != nil {
					return err
				}

			default:
				return zerr.ErrInvalidArgs
			}

			return nil
		},
	}

	configCmd.Flags().BoolVarP(&isListing, "list", "l", false, "List configurations")
	configCmd.Flags().BoolVar(&isReset, "reset", false, "Reset a variable value")
	configCmd.SetUsageTemplate(configCmd.UsageTemplate() + supportedOptions)
	configCmd.AddCommand(NewConfigAddCommand())
	configCmd.AddCommand(NewConfigRemoveCommand())

	return configCmd
}

func NewConfigAddCommand() *cobra.Command {
	configAddCmd := &cobra.Command{
		Use:     "add <config-name> <url>",
		Example: "  zli config add main https://zot-foo.com:8080",
		Short:   "Add configuration for a zot registry",
		Long:    "Add configuration for a zot registry",
		Args:    cobra.ExactArgs(twoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			configPath := filepath.Join(home, ".zot")
			// zli config add <config-name> <url>
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
		Use:     "remove <config-name>",
		Example: "  zli config remove main",
		Short:   "Remove configuration for a zot registry",
		Long:    "Remove configuration for a zot registry",
		Args:    cobra.ExactArgs(oneArg),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			configPath := filepath.Join(home, ".zot")
			// zli config remove <config-name>
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

	c, err := cfg.Find(configName)
	if err != nil {
		return "", err
	}

	return c.FormatListedVars(), nil
}

const (
	examples = `  zli config add main https://zot-foo.com:8080
  zli config --list
  zli config main url
  zli config main --list
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
