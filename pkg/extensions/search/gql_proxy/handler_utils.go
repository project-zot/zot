package gqlproxy

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"

	"zotregistry.dev/zot/errors"
)

// Formats the response and sends it back to the client.
func prepareAndWriteResponse(data map[string]any, response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/json")

	responseBody, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		http.Error(response, "failed to marshal response data", http.StatusInternalServerError)

		return
	}

	_, err = response.Write(responseBody)
	if err != nil {
		http.Error(response, "failed to write response", http.StatusInternalServerError)

		return
	}
}

// This function deep merges maps with some specific handling for known types.
// The primary usage of this is to dynamically merge the GQL responses coming
// from each of the cluster members.
func deepMergeMaps(a, b map[string]any) (map[string]any, error) {
	result := make(map[string]any, len(a))

	maps.Copy(result, a)

	for key, bValue := range b {
		currentValue, keyCurrentlyPresentInResult := result[key]

		if !keyCurrentlyPresentInResult {
			// it doesn't exist yet, directly add to result
			result[key] = bValue

			continue
		}

		switch bValue := bValue.(type) {
		case map[string]any:
			if currentValueMap, ok := currentValue.(map[string]any); ok {
				// currentValue is also a map, recursively merge
				recursiveMergeResult, err := deepMergeMaps(currentValueMap, bValue)
				if err != nil {
					return map[string]any{}, err
				}
				result[key] = recursiveMergeResult

				continue
			}
			// else force update
			result[key] = bValue
		case float64:
			// numeric aggregation - json library assumes float64 for numeric types
			if currentValueNum, ok := currentValue.(float64); ok {
				result[key] = currentValueNum + bValue
			}
		case []any:
			// if it is an array, combine the 2 arrays' elements into one array
			if currentValue, ok := currentValue.([]any); ok {
				result[key] = append(currentValue, bValue...)
			}
		case nil:
			// do nothing
		default:
			return map[string]any{}, fmt.Errorf("%w. type=%T", errors.ErrGQLProxyUnsupportedTypeForMapMerge, bValue)
		}
	}

	return result, nil
}
