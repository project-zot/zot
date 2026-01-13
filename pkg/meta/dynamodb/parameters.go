package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type DBDriverParameters struct {
	Endpoint, Region, RepoMetaTablename, RepoBlobsInfoTablename, ImageMetaTablename,
	UserDataTablename, APIKeyTablename, VersionTablename string
}

func GetDynamoClient(params DBDriverParameters) (*dynamodb.Client, error) {
	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(params.Region))
	if err != nil {
		return nil, err
	}

	// Create DynamoDB client with custom base endpoint if provided
	var clientOptions []func(*dynamodb.Options)
	if params.Endpoint != "" {
		clientOptions = append(clientOptions, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(params.Endpoint)
		})
	}

	return dynamodb.NewFromConfig(cfg, clientOptions...), nil
}
