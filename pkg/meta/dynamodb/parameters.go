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
	customResolver := aws.EndpointResolverWithOptionsFunc( //nolint: staticcheck
		func(service, region string, options ...any) (aws.Endpoint, error) {
			return aws.Endpoint{ //nolint: staticcheck
				PartitionID:   "aws",
				URL:           params.Endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(params.Region),
		config.WithEndpointResolverWithOptions(customResolver)) //nolint: staticcheck
	if err != nil {
		return nil, err
	}

	return dynamodb.NewFromConfig(cfg), nil
}
