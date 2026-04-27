package server

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	zerr "zotregistry.dev/zot/v2/errors"
	zlog "zotregistry.dev/zot/v2/pkg/log"
)

func readConfigFile(viperInstance *viper.Viper, configPath string, logger zlog.Logger) error {
	ext := filepath.Ext(configPath)
	ext = strings.Replace(ext, ".", "", 1)

	/* if file extension is not supported, try everything
	it's also possible that the filename is starting with a dot eg: ".config". */
	if !slices.Contains(viper.SupportedExts, ext) {
		ext = ""
	}

	viperInstance.SetConfigFile(configPath)

	switch ext {
	case "":
		logger.Info().Str("path", configPath).Msg("config file with no extension, trying all supported config types")

		var readErr error

		for _, configType := range viper.SupportedExts {
			viperInstance.SetConfigType(configType)

			readErr = viperInstance.ReadInConfig()
			if readErr == nil {
				return nil
			}
		}

		return readErr
	default:
		return viperInstance.ReadInConfig()
	}
}

func envSubstitutionDecodeHook() mapstructure.DecodeHookFuncType {
	return func(from reflect.Type, _ reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}

		return expandConfigEnv(data.(string))
	}
}

func expandConfigEnv(configValue string) (string, error) {
	missingEnv := map[string]struct{}{}
	var expandedConfig strings.Builder

	for index := 0; index < len(configValue); {
		if configValue[index] != '$' {
			expandedConfig.WriteByte(configValue[index])
			index++

			continue
		}

		if index+1 >= len(configValue) {
			expandedConfig.WriteByte(configValue[index])
			index++

			continue
		}

		next := configValue[index+1]

		switch {
		case next == '{':
			envNameEnd := strings.IndexByte(configValue[index+2:], '}')
			if envNameEnd == -1 {
				expandedConfig.WriteByte(configValue[index])
				index++

				continue
			}

			envName := configValue[index+2 : index+2+envNameEnd]
			if !isConfigEnvName(envName) {
				expandedConfig.WriteString(configValue[index : index+envNameEnd+3])
				index += envNameEnd + 3

				continue
			}

			expandedConfig.WriteString(lookupConfigEnv(envName, missingEnv))
			index += envNameEnd + 3
		case isConfigEnvNameStart(next):
			envNameStart := index + 1
			envNameEnd := envNameStart + 1

			for envNameEnd < len(configValue) && isConfigEnvNameChar(configValue[envNameEnd]) {
				envNameEnd++
			}

			envName := configValue[envNameStart:envNameEnd]

			expandedConfig.WriteString(lookupConfigEnv(envName, missingEnv))
			index = envNameEnd
		default:
			expandedConfig.WriteByte(configValue[index])
			index++
		}
	}

	if len(missingEnv) > 0 {
		names := make([]string, 0, len(missingEnv))
		for name := range missingEnv {
			names = append(names, name)
		}

		sort.Strings(names)

		return "", fmt.Errorf("%w: environment variable(s) not set: %s", zerr.ErrBadConfig, strings.Join(names, ", "))
	}

	return expandedConfig.String(), nil
}

func lookupConfigEnv(name string, missingEnv map[string]struct{}) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		missingEnv[name] = struct{}{}
	}

	return value
}

func isConfigEnvName(name string) bool {
	if name == "" || !isConfigEnvNameStart(name[0]) {
		return false
	}

	for index := 1; index < len(name); index++ {
		if !isConfigEnvNameChar(name[index]) {
			return false
		}
	}

	return true
}

func isConfigEnvNameStart(char byte) bool {
	return char == '_' || (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')
}

func isConfigEnvNameChar(char byte) bool {
	return isConfigEnvNameStart(char) || (char >= '0' && char <= '9')
}
