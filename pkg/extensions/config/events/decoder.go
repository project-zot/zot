package events

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	zerr "zotregistry.dev/zot/errors"
)

// SinkConfigDecoderHook provides a mapstructure hook for decoding SinkConfig interfaces.
func SinkConfigDecoderHook() mapstructure.DecodeHookFunc {
	return func(_ reflect.Type, target reflect.Type, data interface{}) (interface{}, error) {
		// Only apply this hook when converting to SinkConfig
		if target.Name() != "SinkConfig" {
			return data, nil
		}

		if target != reflect.TypeOf((*SinkConfig)(nil)).Elem() {
			return data, nil
		}

		dataMap, ok := data.(map[string]interface{})
		if !ok {
			return data, nil
		}

		config := &SinkConfig{}

		decoderConfig := &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
			Result:           config,
			WeaklyTypedInput: true,
			TagName:          "mapstructure",
		}

		decoder, err := mapstructure.NewDecoder(decoderConfig)
		if err != nil {
			return nil, err
		}

		if err := decoder.Decode(dataMap); err != nil {
			return nil, err
		}

		if !IsSupportedSink(config.Type) {
			return nil, zerr.ErrUnsupportedEventSink
		}

		return config, nil
	}
}
