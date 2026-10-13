package cache

import (
	"context"
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	zlog "zotregistry.dev/zot/v2/pkg/log"
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

// tableExists checks for the table via DescribeTable rather than attempting CreateTable
// and inspecting the error. This allows callers that have dynamodb:DescribeTable (and read/write item
// permissions) on an existing table, but not dynamodb:CreateTable, to work.
func (d *DynamoDBDriver) tableExists(tableName string) (bool, error) {
	_, err := d.client.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err == nil {
		return true, nil
	}

	if _, ok := errors.AsType[*types.ResourceNotFoundException](err); ok {
		return false, nil
	}

	return false, err
}

// isAccessDenied reports whether err is an AWS AccessDeniedException. This isn't a
// modeled DynamoDB exception type, so it's matched via the generic smithy API error.
func isAccessDenied(err error) bool {
	var apiErr smithy.APIError

	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDeniedException"
}

func (d *DynamoDBDriver) NewTable(tableName string) error {
	exists, err := d.tableExists(tableName)
	if err != nil {
		// DescribeTable may be denied for callers that only have dynamodb:CreateTable (and
		// not dynamodb:DescribeTable); fall back to attempting CreateTable directly below.
		if !isAccessDenied(err) {
			return err
		}

		exists = false
	}

	if !exists {
		//nolint:mnd
		_, err = d.client.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
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
		// tableExists and CreateTable aren't atomic, so still tolerate a benign race where
		// another zot instance created the table between the check above and this call.
		// ResourceInUseException can also occur while a table is being deleted, so confirm
		// the table actually exists before treating the error as benign. If the caller isn't
		// permitted to call DescribeTable either (dynamodb:CreateTable-only IAM policies),
		// there's no way to confirm further, so fall back to treating it as benign.
		if err != nil {
			if _, ok := errors.AsType[*types.ResourceInUseException](err); !ok {
				return err
			}

			confirmedExists, existsErr := d.tableExists(tableName)

			switch {
			case existsErr != nil && !isAccessDenied(existsErr):
				return existsErr
			case existsErr == nil && !confirmedExists:
				return err
			}
		}
	}

	d.tableName = tableName

	return nil
}

func NewDynamoDBCache(parameters any, log zlog.Logger) (*DynamoDBDriver, error) {
	properParameters, ok := parameters.(DynamoDBDriverParameters)
	if !ok {
		log.Error().Err(zerr.ErrTypeAssertionFailed).Msgf("failed to cast type, expected type '%T' but got '%T'",
			DynamoDBDriverParameters{}, parameters)

		return nil, zerr.ErrTypeAssertionFailed
	}

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(properParameters.Region))
	if err != nil {
		log.Error().Err(err).Msg("failed to load AWS SDK config for dynamodb")

		return nil, err
	}

	// Create DynamoDB client with custom base endpoint if provided
	var clientOptions []func(*dynamodb.Options)
	if properParameters.Endpoint != "" {
		clientOptions = append(clientOptions, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(properParameters.Endpoint)
		})
	}

	driver := &DynamoDBDriver{
		client:    dynamodb.NewFromConfig(cfg, clientOptions...),
		tableName: properParameters.TableName,
		log:       log,
	}

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

// GetBlob returns the original blob.
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

	// Only a miss, or an item without an origin, means there is no origin yet. Any other
	// read failure says nothing about the record, and must not be answered by writing one.
	originBlob, err := d.GetBlob(digest)
	if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		return err
	}

	if originBlob == "" {
		// first entry, so add original blob. Another writer may record its own path as the
		// origin between the read above and this write; the write is conditional so that the
		// first origin stands, and path is then added as a duplicate of it below.
		if err := d.putOriginBlob(digest, path); err != nil && !isConditionalCheckFailed(err) {
			return err
		}
	}

	expression := "ADD DuplicateBlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}, nil); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put blob")

		return err
	}

	return nil
}

func (d *DynamoDBDriver) SetOrigin(digest godigest.Digest, originPath string) error {
	if originPath == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).
			Msg("failed to set origin because the path provided is empty")

		return zerr.ErrEmptyValue
	}

	// Single UpdateItem with a strongly consistent condition: write only when the
	// origin or set membership needs repair. Avoids eventually-consistent GetBlob
	// no-ops and skips WCU burn when rebuild already points at the right path.
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})
	expression := "SET OriginalBlobPath = :s ADD DuplicateBlobPath :i"
	condition := "attribute_not_exists(OriginalBlobPath) OR OriginalBlobPath <> :s OR " +
		"NOT contains(DuplicateBlobPath, :p)"
	attrVals := map[string]types.AttributeValue{
		":s": &types.AttributeValueMemberS{Value: originPath},
		":i": &types.AttributeValueMemberSS{Value: []string{originPath}},
		":p": &types.AttributeValueMemberS{Value: originPath},
	}

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		UpdateExpression:          &expression,
		ConditionExpression:       &condition,
		ExpressionAttributeValues: attrVals,
	})
	if err != nil {
		if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
			return nil
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", originPath).Msg("failed to set origin")

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

	if slices.Contains(out.DuplicateBlobPath, path) {
		return true
	}

	d.log.Debug().Err(zerr.ErrCacheMiss).Str("digest", string(digest)).Msg("failed to find blob in cache")

	return false
}

func (d *DynamoDBDriver) DeleteBlob(digest godigest.Digest, path string) error {
	expression := "DELETE DuplicateBlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}, nil); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to delete")

		return err
	}

	// What is left to do depends on a record other writers may be changing, so every write
	// below is conditional on the state it was decided from, and is decided again from a
	// fresh read when that state has moved.
	for {
		blob, err := d.readBlob(digest)
		if err != nil {
			if errors.Is(err, zerr.ErrCacheMiss) {
				return nil
			}

			return err
		}

		switch {
		case blob.OriginalBlobPath == "":
			// a record without an origin tracks nothing; drop it unless it has gained one
			d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")

			err = d.deleteItemWithoutOrigin(digest)
			if isConditionalCheckFailed(err) {
				return nil
			}
		case blob.OriginalBlobPath != path:
			return nil
		default:
			// the original blob is the one deleted: move a duplicate blob to original, storage
			// will move content here, or drop the record when no duplicate is left
			duplicate := ""

			for _, candidate := range blob.DuplicateBlobPath {
				if candidate != path {
					duplicate = candidate

					break
				}
			}

			err = d.replaceOrigin(digest, path, duplicate)
		}

		if err == nil {
			return nil
		}

		if isConditionalCheckFailed(err) {
			continue
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to delete")

		return err
	}
}

// readBlob returns the record for digest, or ErrCacheMiss if there is none. The read is
// strongly consistent: it feeds decisions that are then written conditionally, and a stale
// answer would only make those writes fail their condition again.
func (d *DynamoDBDriver) readBlob(digest godigest.Digest) (Blob, error) {
	out := Blob{}

	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob")

		return out, err
	}

	if resp.Item == nil {
		return out, zerr.ErrCacheMiss
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	return out, nil
}

// replaceOrigin moves the origin of digest from oldOrigin to duplicate, or deletes the
// record when duplicate is empty. Either write goes through only if the record still looks
// the way the caller read it: oldOrigin is the origin, and duplicate is still tracked (or,
// for the delete, nothing else is). Otherwise it fails the condition, and a concurrently
// removed duplicate is not brought back as the origin, nor a concurrently added one lost.
func (d *DynamoDBDriver) replaceOrigin(digest godigest.Digest, oldOrigin, duplicate string) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})
	oldPath := types.AttributeValueMemberS{Value: oldOrigin}

	if duplicate != "" {
		expression := "SET OriginalBlobPath = :new"
		condition := "OriginalBlobPath = :old AND contains(DuplicateBlobPath, :new)"
		newPath := types.AttributeValueMemberS{Value: duplicate}

		return d.updateItem(digest, expression, map[string]types.AttributeValue{
			":new": &newPath,
			":old": &oldPath,
		}, &condition)
	}

	condition := "OriginalBlobPath = :old AND " +
		"(attribute_not_exists(DuplicateBlobPath) OR size(DuplicateBlobPath) = :zero)"
	zero := types.AttributeValueMemberN{Value: "0"}

	_, err := d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
		Key:                 marshaledKey,
		TableName:           &d.tableName,
		ConditionExpression: &condition,
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":old":  &oldPath,
			":zero": &zero,
		},
	})

	return err
}

// deleteItemWithoutOrigin deletes the record for digest as long as it still has no origin.
func (d *DynamoDBDriver) deleteItemWithoutOrigin(digest godigest.Digest) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})
	condition := "attribute_not_exists(OriginalBlobPath) OR OriginalBlobPath = :empty"
	emptyPath := types.AttributeValueMemberS{Value: ""}

	_, err := d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		ConditionExpression:       &condition,
		ExpressionAttributeValues: map[string]types.AttributeValue{":empty": &emptyPath},
	})

	return err
}

func isConditionalCheckFailed(err error) bool {
	_, ok := errors.AsType[*types.ConditionalCheckFailedException](err)

	return ok
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

// putOriginBlob records path as the origin of digest, unless an origin is already recorded,
// in which case it fails with a ConditionalCheckFailedException and leaves that origin alone.
func (d *DynamoDBDriver) putOriginBlob(digest godigest.Digest, path string) error {
	expression := "SET OriginalBlobPath = :s"
	condition := "attribute_not_exists(OriginalBlobPath) OR OriginalBlobPath = :empty"
	attrPath := types.AttributeValueMemberS{Value: path}
	emptyPath := types.AttributeValueMemberS{Value: ""}

	err := d.updateItem(digest, expression, map[string]types.AttributeValue{
		":empty": &emptyPath,
		":s":     &attrPath,
	}, &condition)
	if err != nil && !isConditionalCheckFailed(err) {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put original blob")
	}

	return err
}

func (d *DynamoDBDriver) updateItem(digest godigest.Digest, expression string,
	expressionAttVals map[string]types.AttributeValue, conditionExpression *string,
) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		Key:                       marshaledKey,
		TableName:                 &d.tableName,
		UpdateExpression:          &expression,
		ExpressionAttributeValues: expressionAttVals,
		ConditionExpression:       conditionExpression,
	})

	return err
}
