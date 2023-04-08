//go:build search
// +build search

package cli

import (
	"context"
	"fmt"

	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"

	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
)

type field struct {
	Name string `json:"name"`
}

type schemaList struct {
	Data struct {
		Schema struct {
			QueryType struct {
				Fields []field `json:"fields"`
			} `json:"queryType"` //nolint:tagliatelle // graphQL schema
		} `json:"__schema"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
	Errors []common.ErrorGraphQL `json:"errors"`
}

func containsGQLQuery(queryList []field, query string) bool {
	for _, q := range queryList {
		if q.Name == query {
			return true
		}
	}

	return false
}

func checkExtEndPoint(config searchConfig) bool {
	username, password := getUsernameAndPassword(*config.user)
	ctx := context.Background()

	discoverEndPoint, err := combineServerAndEndpointURL(*config.servURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtOciDiscoverPrefix))
	if err != nil {
		return false
	}

	discoverResponse := &distext.ExtensionList{}

	_, err = makeGETRequest(ctx, discoverEndPoint, username, password, *config.verifyTLS,
		*config.debug, &discoverResponse, config.resultWriter)
	if err != nil {
		return false
	}

	searchEnabled := false

	for _, extension := range discoverResponse.Extensions {
		if extension.Name == "_zot" {
			for _, endpoint := range extension.Endpoints {
				if endpoint == constants.FullSearchPrefix {
					searchEnabled = true
				}
			}
		}
	}

	if !searchEnabled {
		return false
	}

	searchEndPoint, _ := combineServerAndEndpointURL(*config.servURL, constants.FullSearchPrefix)

	query := `
        {
            __schema() {
                queryType {
                    fields {
                        name
                    }
                }
            }
        }`

	queryResponse := &schemaList{}

	err = makeGraphQLRequest(ctx, searchEndPoint, query, username, password, *config.verifyTLS,
		*config.debug, queryResponse, config.resultWriter)
	if err != nil {
		return false
	}

	if err = checkResultGraphQLQuery(ctx, err, queryResponse.Errors); err != nil {
		return false
	}

	return containsGQLQuery(queryResponse.Data.Schema.QueryType.Fields, "ImageList")
}
