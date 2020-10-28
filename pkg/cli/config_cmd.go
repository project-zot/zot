// +build extended

package cli

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"

	jsoniter "github.com/json-iterator/go"

	zotErrors "github.com/anuvu/zot/errors"

	"github.com/spf13/cobra"
)

func NewConfigCommand() *cobra.Command {
	var isListing bool

	var isReset bool

	var configCmd = &cobra.Command{
		Use:     "config <config-name> [variable] [value]",
		Example: examples,
		Short:   "Configure zot CLI",
		Long:    `Configure default parameters for CLI`,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}

			configPath := path.Join(home + "/.zot")
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

				return zotErrors.ErrInvalidArgs
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

				return zotErrors.ErrInvalidArgs
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
				//zot config <name> <key> <value>
				if err := setConfigValue(configPath, args[0], args[1], args[2]); err != nil {
					return err
				}

			default:
				return zotErrors.ErrInvalidArgs
			}

			return nil
		},
	}

	configCmd.Flags().BoolVarP(&isListing, "list", "l", false, "List configurations")
	configCmd.Flags().BoolVar(&isReset, "reset", false, "Reset a variable value")
	configCmd.SetUsageTemplate(configCmd.UsageTemplate() + supportedOptions)
	configCmd.AddCommand(NewConfigAddCommand())

	return configCmd
}

func NewConfigAddCommand() *cobra.Command {
	var configAddCmd = &cobra.Command{
		Use:   "add <config-name> <url>",
		Short: "Add configuration for a zot URL",
		Long:  `Configure CLI for interaction with a zot server`,
		Args:  cobra.ExactArgs(twoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}

			configPath := path.Join(home + "/.zot")
			// zot config add <config-name> <url>
			err = addConfig(configPath, args[0], args[1])
			if err != nil {
				return err
			}

			return nil
		},
	}

	return configAddCmd
}

func getConfigMapFromFile(filePath string) ([]interface{}, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	file.Close()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var jsonMap map[string]interface{}

	var json = jsoniter.ConfigCompatibleWithStandardLibrary

	_ = json.Unmarshal(data, &jsonMap)

	if jsonMap["configs"] == nil {
		return nil, ErrEmptyJSON
	}

	return jsonMap["configs"].([]interface{}), nil
}

func saveConfigMapToFile(filePath string, configMap []interface{}) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary

	listMap := make(map[string]interface{})
	listMap["configs"] = configMap
	marshalled, err := json.Marshal(&listMap)

	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, marshalled, 0600); err != nil {
		return err
	}

	return nil
}

func getConfigNames(configPath string) (string, error) {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, ErrEmptyJSON) {
			return "", nil
		}

		return "", err
	}

	var builder strings.Builder

	writer := tabwriter.NewWriter(&builder, 0, 8, 1, '\t', tabwriter.AlignRight)

	for _, val := range configs {
		configMap := val.(map[string]interface{})
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
	if err != nil && !errors.Is(err, ErrEmptyJSON) {
		return err
	}

	if !isURL(url) {
		return zotErrors.ErrInvalidURL
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
		if errors.Is(err, ErrEmptyJSON) {
			return "", zotErrors.ErrConfigNotFound
		}

		return "", err
	}

	for _, val := range configs {
		configMap := val.(map[string]interface{})
		addDefaultConfigs(configMap)

		name := configMap[nameKey]
		if name == configName {
			if configMap[key] == nil {
				return "", nil
			}

			return fmt.Sprintf("%v", configMap[key]), nil
		}
	}

	return "", zotErrors.ErrConfigNotFound
}

func resetConfigValue(configPath, configName, key string) error {
	if key == "url" || key == nameKey {
		return zotErrors.ErrCannotResetConfigKey
	}

	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, ErrEmptyJSON) {
			return zotErrors.ErrConfigNotFound
		}

		return err
	}

	for _, val := range configs {
		configMap := val.(map[string]interface{})
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

	return zotErrors.ErrConfigNotFound
}

func setConfigValue(configPath, configName, key, value string) error {
	if key == nameKey {
		return zotErrors.ErrIllegalConfigKey
	}

	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, ErrEmptyJSON) {
			return zotErrors.ErrConfigNotFound
		}

		return err
	}

	for _, val := range configs {
		configMap := val.(map[string]interface{})
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

	return zotErrors.ErrConfigNotFound
}

func getAllConfig(configPath, configName string) (string, error) {
	configs, err := getConfigMapFromFile(configPath)
	if err != nil {
		if errors.Is(err, ErrEmptyJSON) {
			return "", nil
		}

		return "", err
	}

	var builder strings.Builder

	for _, value := range configs {
		configMap := value.(map[string]interface{})
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

	return "", zotErrors.ErrConfigNotFound
}

const (
	examples = `  zot config add main https://zot-foo.com:8080
  zot config main url
  zot config main --list
  zot config --list`

	supportedOptions = `
Useful variables:
  url		zot server URL
  showspinner	show spinner while loading data [true/false]
  verify-tls	verify TLS Certificate verification of the server [default: true]`

	nameKey = "_name"

	noArgs    = 0
	oneArg    = 1
	twoArgs   = 2
	threeArgs = 3

	showspinnerConfig = "showspinner"
	verifyTLSConfig   = "verify-tls"
)

var (
	ErrEmptyJSON = errors.New("cli: config json is empty")
)
