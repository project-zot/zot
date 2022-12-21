package cache

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
)

type DynamoDBDriver struct {
	client *dynamodb.Client
	log    zlog.Logger
}

type DynamoDBDriverParameters struct {
	Endpoint, Region, TableNamePrefix string
}

type Blob struct {
	Digest   string   `dynamodbav:"Digest,string"`
	BlobPath []string `dynamodbav:"BlobPath,stringset"`
}

func (d *DynamoDBDriver) CreateBucket(tableName string) error {
	//nolint:gomnd
	_, err := d.client.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: &tableName,
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Digest"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Digest"),
				KeyType:       types.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(5),
		},
	})
	if err != nil && !strings.Contains(err.Error(), "Table already exists") {
		d.log.Error().Err(err).Msgf("failed to create table %s", tableName)

		return err
	}

	return nil
}

func NewDynamoDBCache(parameters interface{}, log zlog.Logger) (Cache, error) {
	properParameters, ok := parameters.(DynamoDBDriverParameters)
	if !ok {
		log.Error().Err(zerr.ErrTypeAssertionFailed).Msg("failed type assertion for dynamodb")

		return nil, zerr.ErrTypeAssertionFailed
	}

	// custom endpoint resolver to point to localhost
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           properParameters.Endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(properParameters.Region),
		config.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		log.Error().Msgf("unable to load AWS SDK config for dynamodb, %v", err)

		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return &DynamoDBDriver{client: dynamodb.NewFromConfig(cfg), log: log}, nil
}

func (d *DynamoDBDriver) Name() string {
	return "dynamodb"
}

// Returns the first path of the blob if it exists.
func (d *DynamoDBDriver) GetBlob(tableName string, digest godigest.Digest) (string, error) {
	if tableName == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("empty bucket provided")

		return "", zerr.ErrEmptyValue
	}

	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Msgf("failed to get blob %v, %v", tableName, err)

		return "", err
	}

	out := Blob{}

	if resp.Item == nil {
		return "", zerr.ErrCacheMiss
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	if len(out.BlobPath) == 0 {
		return "", nil
	}

	return out.BlobPath[0], nil
}

func (d *DynamoDBDriver) PutBlob(tableName string, digest godigest.Digest, path string) error {
	if path == "" || tableName == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("empty path or table provided")

		return zerr.ErrEmptyValue
	}

	marshaledKey, _ := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest.String()})
	expression := "ADD BlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if _, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: map[string]types.AttributeValue{":i": &attrPath},
	}); err != nil {
		d.log.Error().Err(err)

		return err
	}

	return nil
}

func (d *DynamoDBDriver) HasBlob(tableName string, digest godigest.Digest, path string) bool {
	if tableName == "" || path == "" {
		d.log.Warn().Str("digest", digest.String()).Msg("empty path or bucket provided")

		return false
	}

	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Msgf("failed to get blob %v, %v", tableName, err)

		return false
	}

	out := Blob{}

	if resp.Item == nil {
		d.log.Error().Err(zerr.ErrCacheMiss)

		return false
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	for _, item := range out.BlobPath {
		if item == path {
			return true
		}
	}

	d.log.Error().Err(zerr.ErrCacheMiss)

	return false
}

func (d *DynamoDBDriver) DeleteBlob(tableName string, digest godigest.Digest, path string) error {
	if tableName == "" || path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("empty path or bucket provided")

		return zerr.ErrEmptyValue
	}

	marshaledKey, _ := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest.String()})

	expression := "DELETE BlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: map[string]types.AttributeValue{":i": &attrPath},
	})
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("unable to delete")

		return err
	}

	result, _ := d.GetBlob(tableName, digest)

	if result == "" {
		d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")

		_, _ = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			Key:       marshaledKey,
			TableName: &tableName,
		})
	}

	return nil
}

func (d *DynamoDBDriver) Close() error {
	return nil
}
