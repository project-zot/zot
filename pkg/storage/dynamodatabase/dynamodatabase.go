package dynamodatabase

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	zerr "zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/database"
)

const (
	driverName       = "dynamodb"
	defaultEndpoint  = "http://localhost:4566"
	defaultRegion    = "us-east-2"
	defaultTableName = "BlobTable"
)

type DynamoDBDriverParameters struct {
	Endpoint, Region, TableName string
}

type Driver struct {
	client    *dynamodb.Client
	log       zlog.Logger
	tableName string
}

// Implements the storage.DatabaseDriverFactory interface.
type dynamodbDriverFactory struct{}

func (factory *dynamodbDriverFactory) Create(parameters interface{}, log zlog.Logger) (database.Driver, error) {
	properParameters, ok := parameters.(DynamoDBDriverParameters)
	if !ok {
		panic("Failed type assertion!")
	}

	return FromParameters(properParameters, log)
}

func FromParameters(parameters DynamoDBDriverParameters, log zlog.Logger) (*Driver, error) {
	params := &DynamoDBDriverParameters{
		Endpoint:  defaultEndpoint,
		Region:    defaultRegion,
		TableName: defaultTableName,
	}

	if parameters.Endpoint != "" {
		params.Endpoint = parameters.Endpoint
	}

	if parameters.Region != "" {
		params.Region = parameters.Region
	}

	if parameters.TableName != "" {
		params.TableName = parameters.TableName
	}

	return New(*params, log), nil
}

// nolint:gochecknoinits
func init() {
	database.Register(driverName, &dynamodbDriverFactory{})
}

// Create dynamodb client pointing to the URL and region specified in the args.
func New(parameters DynamoDBDriverParameters, log zlog.Logger) *Driver {
	// custom endpoint resolver to point to localhost
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if service == dynamodb.ServiceID {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           parameters.Endpoint,
					SigningRegion: region,
				}, nil
			}

			return aws.Endpoint{}, zerr.ErrInvalidDynamoDBEndpoint
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(parameters.Region),
		config.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		log.Error().Msgf("unable to load AWS SDK config for dynamodb, %v", err)

		return nil
	}

	// Using the Config value, create the DynamoDB client
	return &Driver{client: dynamodb.NewFromConfig(cfg), tableName: parameters.TableName, log: log}
}

func (d *Driver) Name() string {
	return "dynamodb"
}

// Returns the first path of the blob if it exists.
func (d *Driver) GetBlob(digest string) (string, error) {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest},
		},
	})
	if err != nil {
		d.log.Error().Msgf("failed to get blob %v, %v", d.tableName, err)

		return "", err
	}

	out := database.Blob{}

	if resp.Item == nil {
		return "", zerr.ErrBlobNotFound
	}

	err = attributevalue.UnmarshalMap(resp.Item, &out)
	if err != nil {
		d.log.Error().Err(err)

		return "", err
	}

	if len(out.BlobPath) == 0 {
		return "", nil
	}

	for _, k := range out.BlobPath {
		return k, nil
	}

	// Placeholder, so compiler doesn't cry
	return "", nil
}

func (d *Driver) PutBlob(digest, path string) error {
	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest).Msg("empty path provided")

		return zerr.ErrEmptyValue
	}

	marshaledKey, err := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest})
	if err != nil {
		d.log.Error().Err(err)

		return err
	}

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

func (d *Driver) HasBlob(digest, path string) bool {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest},
		},
	})
	if err != nil {
		d.log.Error().Msgf("failed to get blob %v, %v", d.tableName, err)

		return false
	}

	out := database.Blob{}

	if resp.Item == nil {
		d.log.Error().Err(zerr.ErrCacheMiss)

		return false
	}

	err = attributevalue.UnmarshalMap(resp.Item, &out)
	if err != nil {
		d.log.Error().Err(err)

		return false
	}

	for _, item := range out.BlobPath {
		if item == path {
			return true
		}
	}

	d.log.Error().Err(zerr.ErrCacheMiss)

	return false
}

func (d *Driver) DeleteBlob(digest, path string) error {
	marshaledKey, err := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest})
	if err != nil {
		d.log.Error().Err(err)

		return err
	}

	expression := "DELETE BlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	_, err = d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: map[string]types.AttributeValue{":i": &attrPath},
	})

	if err != nil {
		d.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")

		return err
	}

	result, err := d.GetBlob(digest)
	if err != nil {
		d.log.Error().Err(err)

		return err
	}

	if result == "" {
		d.log.Debug().Str("digest", digest).Str("path", path).Msg("deleting empty bucket")

		_, err := d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			Key:       marshaledKey,
			TableName: &d.tableName,
		})
		if err != nil {
			d.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")

			return err
		}
	}

	return nil
}
