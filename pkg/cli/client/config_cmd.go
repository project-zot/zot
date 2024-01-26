//go:build search
// +build search

package client

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"

	jsoniter "github.com/json-iterator/go"
	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
)

const (
	defaultConfigPerms = 0o644
	defaultFilePerms   = 0o600
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

			configPath := path.Join(home, "/.zot")
			switch len(args) {
			case noArgs:
				if isListing { // zot config -l
					res, err := getConfigNames(configPath)
					if err != nil {
						return err
					}

					fmt.Fprint(cmd.OutOrStdout(), res)

					return nil
				}

				return zerr.ErrInvalidArgs
			case oneArg:
				// zot config <name> -l
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
				if isReset { // zot config <name> <key> --reset
					return resetConfigValue(configPath, args[0], args[1])
				}
				// zot config <name> <key>
				res, err := getConfigValue(configPath, args[0], args[1])
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), res)
			case threeArgs:
				// zot config <name> <key> <value>
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

			configPath := path.Join(home, "/.zot")
			// zot config add <config-name> <url>
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

			configPath := path.Join(home, "/.zot")
			// zot config add <config-name> <url>
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

func getConfigMapFromFile(filePath string) ([]interface{}, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, defaultConfigPerms)
	if err != nil {
		return nil, err
	}

	file.Close()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var jsonMap map[string]interface{}

	json := jsoniter.ConfigCompatibleWithStandardLibrary

	_ = json.Unmarshal(data, &jsonMap)

	if jsonMap["configs"] == nil {
		return nil, zerr.ErrEmptyJSON
	}

	configs, ok := jsonMap["configs"].([]interface{})
	if !ok {
		return nil, zerr.ErrCliBadConfig
	}

	return configs, nil
}

func saveConfigMapToFile(filePath string, configMap []interface{}) error {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	listMap := make(map[string]interface{})
	listMap["configs"] = configMap

	marshalled, err := json.MarshalIndent(&listMap, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, marshalled, defaultFilePerms); err != nil {
		return err
	}

	return nil
}

func getConfigNames(configPath string) (string, error) {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, zerr.ErrEmptyJSON) {
			return "", nil
		}

		return "", err
	}

	var builder strings.Builder

	writer := tabwriter.NewWriter(&builder, 0, 8, 1, '\t', tabwriter.AlignRight) //nolint:gomnd

	for _, val := range configs {
		configMap, ok := val.(map[string]interface{})
		if !ok {
			return "", zerr.ErrBadConfig
		}

		fmt.Fprintf(writer, "%s\t%s\n", configMap[nameKey], configMap["url"])
	}

	err = writer.Flush()
	if err != nil {
		return "", err
	}

	return builder.String(), nil
}

func addConfig(configPath, configName, url string) error {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil && !errors.Is(err, zerr.ErrEmptyJSON) {
		return err
	}

	if err := validateURL(url); err != nil {
		return err
	}

	if configNameExists(configs, configName) {
		return zerr.ErrDuplicateConfigName
	}

	configMap := make(map[string]interface{})
	configMap["url"] = url
	configMap[nameKey] = configName
	addDefaultConfigs(configMap)
	configs = append(configs, configMap)

	err = saveConfigMapToFile(configPath, configs)
	if err != nil {
		return err
	}

	return nil
}

func removeConfig(configPath, configName string) error {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		return err
	}

	for i, val := range configs {
		configMap, ok := val.(map[string]interface{})
		if !ok {
			return zerr.ErrBadConfig
		}

		name := configMap[nameKey]
		if name != configName {
			continue
		}

		// Remove config from the config list before saving
		newConfigs := configs[:i]
		newConfigs = append(newConfigs, configs[i+1:]...)

		err = saveConfigMapToFile(configPath, newConfigs)
		if err != nil {
			return err
		}

		return nil
	}

	return zerr.ErrConfigNotFound
}

func addDefaultConfigs(config map[string]interface{}) {
	if _, ok := config[showspinnerConfig]; !ok {
		config[showspinnerConfig] = true
	}

	if _, ok := config[verifyTLSConfig]; !ok {
		config[verifyTLSConfig] = true
	}
}

func getConfigValue(configPath, configName, key string) (string, error) {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, zerr.ErrEmptyJSON) {
			return "", zerr.ErrConfigNotFound
		}

		return "", err
	}

	for _, val := range configs {
		configMap, ok := val.(map[string]interface{})
		if !ok {
			return "", zerr.ErrBadConfig
		}

		addDefaultConfigs(configMap)

		name := configMap[nameKey]
		if name == configName {
			if configMap[key] == nil {
				return "", nil
			}

			return fmt.Sprintf("%v", configMap[key]), nil
		}
	}

	return "", zerr.ErrConfigNotFound
}

func resetConfigValue(configPath, configName, key string) error {
	if key == "url" || key == nameKey {
		return zerr.ErrCannotResetConfigKey
	}

	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, zerr.ErrEmptyJSON) {
			return zerr.ErrConfigNotFound
		}

		return err
	}

	for _, val := range configs {
		configMap, ok := val.(map[string]interface{})
		if !ok {
			return zerr.ErrBadConfig
		}

		addDefaultConfigs(configMap)

		name := configMap[nameKey]
		if name == configName {
			delete(configMap, key)

			err = saveConfigMapToFile(configPath, configs)
			if err != nil {
				return err
			}

			return nil
		}
	}

	return zerr.ErrConfigNotFound
}

func setConfigValue(configPath, configName, key, value string) error {
	if key == nameKey {
		return zerr.ErrIllegalConfigKey
	}

	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, zerr.ErrEmptyJSON) {
			return zerr.ErrConfigNotFound
		}

		return err
	}

	for _, val := range configs {
		configMap, ok := val.(map[string]interface{})
		if !ok {
			return zerr.ErrBadConfig
		}

		addDefaultConfigs(configMap)

		name := configMap[nameKey]
		if name == configName {
			boolVal, err := strconv.ParseBool(value)
			if err == nil {
				configMap[key] = boolVal
			} else {
				configMap[key] = value
			}

			err = saveConfigMapToFile(configPath, configs)
			if err != nil {
				return err
			}

			return nil
		}
	}

	return zerr.ErrConfigNotFound
}

func getAllConfig(configPath, configName string) (string, error) {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, zerr.ErrEmptyJSON) {
			return "", nil
		}

		return "", err
	}

	var builder strings.Builder

	for _, value := range configs {
		configMap, ok := value.(map[string]interface{})
		if !ok {
			return "", zerr.ErrBadConfig
		}

		addDefaultConfigs(configMap)

		name := configMap[nameKey]
		if name == configName {
			for key, val := range configMap {
				if key == nameKey {
					continue
				}

				fmt.Fprintf(&builder, "%s = %v\n", key, val)
			}

			return builder.String(), nil
		}
	}

	return "", zerr.ErrConfigNotFound
}

func configNameExists(configs []interface{}, configName string) bool {
	for _, val := range configs {
		configMap, ok := val.(map[string]interface{})
		if !ok {
			return false
		}

		if configMap[nameKey] == configName {
			return true
		}
	}

	return false
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

	nameKey = "_name"

	noArgs    = 0
	oneArg    = 1
	twoArgs   = 2
	threeArgs = 3

	showspinnerConfig = "showspinner"
	verifyTLSConfig   = "verify-tls"
)
