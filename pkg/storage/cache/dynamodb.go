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
	client    *dynamodb.Client
	log       zlog.Logger
	tableName string
}

type DynamoDBDriverParameters struct {
	Endpoint, Region, TableName string
}

type Blob struct {
	Digest   string   `dynamodbav:"Digest,string"`
	BlobPath []string `dynamodbav:"BlobPath,stringset"`
}

// Use ONLY for tests.
func (d *DynamoDBDriver) NewTable(tableName string) error {
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
		return err
	}

	d.tableName = tableName

	return nil
}

func NewDynamoDBCache(parameters interface{}, log zlog.Logger) Cache {
	properParameters, ok := parameters.(DynamoDBDriverParameters)
	if !ok {
		panic("Failed type assertion!")
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

		return nil
	}

	driver := &DynamoDBDriver{client: dynamodb.NewFromConfig(cfg), tableName: properParameters.TableName, log: log}

	err = driver.NewTable(driver.tableName)
	if err != nil {
		log.Error().Err(err).Msgf("unable to create table for cache '%s'", driver.tableName)
	}

	// Using the Config value, create the DynamoDB client
	return driver
}

func (d *DynamoDBDriver) Name() string {
	return "dynamodb"
}

// Returns the first path of the blob if it exists.
func (d *DynamoDBDriver) GetBlob(digest godigest.Digest) (string, error) {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Msgf("failed to get blob %v, %v", d.tableName, err)

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

func (d *DynamoDBDriver) PutBlob(digest godigest.Digest, path string) error {
	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("empty path provided")

		return zerr.ErrEmptyValue
	}

	marshaledKey, _ := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest.String()})
	expression := "ADD BlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if _, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: map[string]types.AttributeValue{":i": &attrPath},
	}); err != nil {
		d.log.Error().Err(err)

		return err
	}

	return nil
}

func (d *DynamoDBDriver) HasBlob(digest godigest.Digest, path string) bool {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Msgf("failed to get blob %v, %v", d.tableName, err)

		return false
	}

	out := Blob{}

	if resp.Item == nil {
		d.log.Debug().Err(zerr.ErrCacheMiss).Str("digest", string(digest)).Msg("unable to find blob in cache")

		return false
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	for _, item := range out.BlobPath {
		if item == path {
			return true
		}
	}

	d.log.Debug().Err(zerr.ErrCacheMiss).Str("digest", string(digest)).Msg("unable to find blob in cache")

	return false
}

func (d *DynamoDBDriver) DeleteBlob(digest godigest.Digest, path string) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest.String()})

	expression := "DELETE BlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: map[string]types.AttributeValue{":i": &attrPath},
	})
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("unable to delete")

		return err
	}

	result, _ := d.GetBlob(digest)

	if result == "" {
		d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")

		_, _ = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			Key:       marshaledKey,
			TableName: &d.tableName,
		})
	}

	return nil
}
