//go:build search
// +build search

package cli

import (
	"context"
	"fmt"

	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
)

type field struct {
	Name string `json:"name"`
	Args []struct {
		Name string `json:"name"`
	} `json:"args"`
}

type schemaList struct {
	Data struct {
		Schema struct {
			QueryType struct {
				Fields []field `json:"fields"`
			} `json:"queryType"` //nolint:tagliatelle // graphQL schema
			Types []typeInfo `json:"types"`
		} `json:"__schema"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
	Errors []zcommon.ErrorGQL `json:"errors"`
}

type typeInfo struct {
	Name   string      `json:"name"`
	Fields []typeField `json:"fields"`
}

type typeField struct {
	Name string `json:"name"`
}

func containsGQLQuery(queryList []field, query string) bool {
	for _, q := range queryList {
		if q.Name == query {
			return true
		}
	}

	return false
}

func containsGQLQueryWithParams(queryList []field, serverGQLTypesList []typeInfo, requiredQueries ...GQLQuery) error {
	serverGQLTypes := map[string][]typeField{}

	for _, typeInfo := range serverGQLTypesList {
		serverGQLTypes[typeInfo.Name] = typeInfo.Fields
	}

	for _, reqQuery := range requiredQueries {
		foundQuery := false

		for _, query := range queryList {
			if query.Name == reqQuery.Name && haveSameArgs(query, reqQuery) {
				foundQuery = true
			}
		}

		if !foundQuery {
			return fmt.Errorf("%w: %s", zerr.ErrGQLQueryNotSupported, reqQuery.Name)
		}

		// let's check just the name of the returned type
		returnType := reqQuery.ReturnType.Name

		// we can next define fields of the returned types and check them recursively
		// for now we will just check the name of the returned type to be known by the server
		_, ok := serverGQLTypes[returnType]
		if !ok {
			return fmt.Errorf("%w: server doesn't support needed type '%s'", zerr.ErrGQLQueryNotSupported, returnType)
		}
	}

	return nil
}

func haveSameArgs(query field, reqQuery GQLQuery) bool {
	if len(query.Args) != len(reqQuery.Args) {
		return false
	}

	for i := range query.Args {
		if query.Args[i].Name != reqQuery.Args[i] {
			return false
		}
	}

	return true
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
		if extension.Name == constants.BaseExtension {
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

func CheckExtEndPointQuery(config searchConfig, requiredQueries ...GQLQuery) error {
	username, password := getUsernameAndPassword(*config.user)
	ctx := context.Background()

	discoverEndPoint, err := combineServerAndEndpointURL(*config.servURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtOciDiscoverPrefix))
	if err != nil {
		return err
	}

	discoverResponse := &distext.ExtensionList{}

	_, err = makeGETRequest(ctx, discoverEndPoint, username, password, *config.verifyTLS,
		*config.debug, &discoverResponse, config.resultWriter)
	if err != nil {
		return err
	}

	searchEnabled := false

	for _, extension := range discoverResponse.Extensions {
		if extension.Name == constants.BaseExtension {
			for _, endpoint := range extension.Endpoints {
				if endpoint == constants.FullSearchPrefix {
					searchEnabled = true
				}
			}
		}
	}

	if !searchEnabled {
		return fmt.Errorf("%w: search extension gql endpoints not found", zerr.ErrExtensionNotEnabled)
	}

	searchEndPoint, _ := combineServerAndEndpointURL(*config.servURL, constants.FullSearchPrefix)

	schemaQuery := `
		{
			__schema() {
				queryType {
					fields {
						name
						args {
							name
						}
						type {
							name
							kind
						}
					}
					__typename
				}
				types {
					name
					fields {
						name
					}
				}
			}
		}`

	queryResponse := &schemaList{}

	err = makeGraphQLRequest(ctx, searchEndPoint, schemaQuery, username, password, *config.verifyTLS,
		*config.debug, queryResponse, config.resultWriter)
	if err != nil {
		return fmt.Errorf("gql query failed: %w", err)
	}

	if err = checkResultGraphQLQuery(ctx, err, queryResponse.Errors); err != nil {
		return fmt.Errorf("gql query failed: %w", err)
	}

	return containsGQLQueryWithParams(queryResponse.Data.Schema.QueryType.Fields,
		queryResponse.Data.Schema.Types, requiredQueries...)
}
