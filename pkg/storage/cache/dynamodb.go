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

	zerr "zotregistry.dev/zot/errors"
	zlog "zotregistry.dev/zot/pkg/log"
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
	Digest            string   `dynamodbav:"Digest,string"`
	DuplicateBlobPath []string `dynamodbav:"DuplicateBlobPath,stringset"`
	OriginalBlobPath  string   `dynamodbav:"OriginalBlobPath,string"`
}

func (d *DynamoDBDriver) NewTable(tableName string) error {
	//nolint:mnd
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

func NewDynamoDBCache(parameters interface{}, log zlog.Logger) (*DynamoDBDriver, error) {
	properParameters, ok := parameters.(DynamoDBDriverParameters)
	if !ok {
		log.Error().Err(zerr.ErrTypeAssertionFailed).Msgf("failed to cast type, expected type '%T' but got '%T'",
			BoltDBDriverParameters{}, parameters)

		return nil, zerr.ErrTypeAssertionFailed
	}

	// custom endpoint resolver to point to localhost
	customResolver := aws.EndpointResolverWithOptionsFunc( //nolint: staticcheck
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{ //nolint: staticcheck
				PartitionID:   "aws",
				URL:           properParameters.Endpoint,
				SigningRegion: region,
			}, nil
		})

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(properParameters.Region),
		config.WithEndpointResolverWithOptions(customResolver)) //nolint: staticcheck
	if err != nil {
		log.Error().Err(err).Msg("failed to load AWS SDK config for dynamodb")

		return nil, err
	}

	driver := &DynamoDBDriver{client: dynamodb.NewFromConfig(cfg), tableName: properParameters.TableName, log: log}

	err = driver.NewTable(driver.tableName)
	if err != nil {
		log.Error().Err(err).Str("tableName", driver.tableName).Msg("failed to create table for cache")

		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	return driver, nil
}

func (d *DynamoDBDriver) SetTableName(table string) {
	d.tableName = table
}

func (d *DynamoDBDriver) UsesRelativePaths() bool {
	return false
}

func (d *DynamoDBDriver) Name() string {
	return "dynamodb"
}

// Returns the original blob.
func (d *DynamoDBDriver) GetBlob(digest godigest.Digest) (string, error) {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob")

		return "", err
	}

	out := Blob{}

	if resp.Item == nil {
		return "", zerr.ErrCacheMiss
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	return out.OriginalBlobPath, nil
}

func (d *DynamoDBDriver) GetAllBlobs(digest godigest.Digest) ([]string, error) {
	blobPaths := []string{}

	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob")

		return nil, err
	}

	out := Blob{}

	if resp.Item == nil {
		d.log.Debug().Err(zerr.ErrCacheMiss).Str("digest", string(digest)).Msg("failed to find blob in cache")

		return nil, zerr.ErrCacheMiss
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	blobPaths = append(blobPaths, out.OriginalBlobPath)

	for _, item := range out.DuplicateBlobPath {
		if item != out.OriginalBlobPath {
			blobPaths = append(blobPaths, item)
		}
	}

	return blobPaths, nil
}

func (d *DynamoDBDriver) PutBlob(digest godigest.Digest, path string) error {
	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).
			Msg("failed to put blob because the path provided is empty")

		return zerr.ErrEmptyValue
	}

	if originBlob, _ := d.GetBlob(digest); originBlob == "" {
		// first entry, so add original blob
		if err := d.putOriginBlob(digest, path); err != nil {
			return err
		}
	}

	expression := "ADD DuplicateBlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put blob")

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
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob")

		return false
	}

	out := Blob{}

	if resp.Item == nil {
		d.log.Debug().Err(zerr.ErrCacheMiss).Str("digest", string(digest)).Msg("failed to find blob in cache")

		return false
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	if out.OriginalBlobPath == path {
		return true
	}

	for _, item := range out.DuplicateBlobPath {
		if item == path {
			return true
		}
	}

	d.log.Debug().Err(zerr.ErrCacheMiss).Str("digest", string(digest)).Msg("failed to find blob in cache")

	return false
}

func (d *DynamoDBDriver) DeleteBlob(digest godigest.Digest, path string) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest.String()})

	expression := "DELETE DuplicateBlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to delete")

		return err
	}

	originBlob, _ := d.GetBlob(digest)
	// if original blob is the one deleted
	if originBlob == path {
		// move duplicate blob to original, storage will move content here
		originBlob, _ = d.GetDuplicateBlob(digest)
		if originBlob != "" {
			if err := d.putOriginBlob(digest, originBlob); err != nil {
				return err
			}
		}
	}

	if originBlob == "" {
		d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")

		_, _ = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			Key:       marshaledKey,
			TableName: &d.tableName,
		})
	}

	return nil
}

func (d *DynamoDBDriver) GetDuplicateBlob(digest godigest.Digest) (string, error) {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
	})
	if err != nil {
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob")

		return "", err
	}

	out := Blob{}

	if resp.Item == nil {
		return "", zerr.ErrCacheMiss
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	if len(out.DuplicateBlobPath) == 0 {
		return "", nil
	}

	return out.DuplicateBlobPath[0], nil
}

func (d *DynamoDBDriver) putOriginBlob(digest godigest.Digest, path string) error {
	expression := "SET OriginalBlobPath = :s"
	attrPath := types.AttributeValueMemberS{Value: path}

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":s": &attrPath}); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put original blob")

		return err
	}

	return nil
}

func (d *DynamoDBDriver) updateItem(digest godigest.Digest, expression string,
	expressionAttVals map[string]types.AttributeValue,
) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]interface{}{"Digest": digest.String()})

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: expressionAttVals,
	})

	return err
}
