package cache

import (
	"context"
	"errors"
	"fmt"
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

// maxConditionalAttempts bounds how often PutBlob and DeleteBlob decide again after a write
// fails its condition. Each failure means another writer changed the record in between, so
// more than a few in a row is already unusual. The bound is there so that a record no attempt
// can make progress on is reported as an error instead of being retried without end.
const maxConditionalAttempts = 10

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
// GetBlob reads strongly consistently: dedupe and delete decide from the origin it returns, under
// the digest lock, and a stale origin would steer a repair or a hand-off to the wrong copy.
func (d *DynamoDBDriver) GetBlob(digest godigest.Digest) (string, error) {
	out, err := d.readBlob(digest)
	if err != nil {
		return "", err
	}

	return out.OriginalBlobPath, nil
}

// GetAllBlobs reads strongly consistently: deleting a dedupe origin hands its content to a copy
// from this list, and a stale list that leaves out a surviving copy would lose the content.
func (d *DynamoDBDriver) GetAllBlobs(digest godigest.Digest) ([]string, error) {
	blobPaths := []string{}

	out, err := d.readBlob(digest)
	if err != nil {
		if errors.Is(err, zerr.ErrCacheMiss) {
			d.log.Debug().Err(err).Str("digest", string(digest)).Msg("failed to find blob in cache")
		}

		return nil, err
	}

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

	// Whether path becomes the origin or a duplicate of one depends on a record other writers
	// may be changing, so the write is conditional on the origin that was read, and is decided
	// again from a fresh read when that origin has moved or the record is gone.
	var err error

	for range maxConditionalAttempts {
		var blob Blob

		// Only a miss, or an item without an origin, means there is no origin yet. Any other
		// read failure says nothing about the record, and must not be answered by writing one.
		blob, err = d.readBlob(digest)
		if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			return err
		}

		if blob.OriginalBlobPath == "" {
			// first entry, so add original blob
			err = d.putOriginBlob(digest, path)
		} else {
			err = d.putDuplicateBlob(digest, blob.OriginalBlobPath, path)
		}

		if err == nil {
			return nil
		}

		if isConditionalCheckFailed(err) {
			continue
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put blob")

		return err
	}

	return d.conditionalAttemptsExhausted(digest, path, err)
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

	if err := d.decodeBlob(resp.Item, &out); err != nil {
		return false
	}

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
	// An update creates the item it names if there is none, so this one is conditional on the
	// record existing: a digest that is not tracked has nothing to delete, and must not be
	// left with an empty record for that.
	expression := "DELETE DuplicateBlobPath :i"
	condition := "attribute_exists(Digest)"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}, &condition)
	if err != nil {
		if isConditionalCheckFailed(err) {
			return nil
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to delete")

		return err
	}

	// What is left to do depends on a record other writers may be changing, so every write
	// below is conditional on the state it was decided from, and is decided again from a
	// fresh read when that state has moved.
	for range maxConditionalAttempts {
		var blob Blob

		blob, err = d.readBlob(digest)
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
			// path was taken out of the tracked paths above, so finding it there again means
			// another writer has put it back since. That later write stands. Going on would
			// find nothing to promote, and then try to delete a record that still tracks a
			// path, failing that condition against the same record on every retry.
			if slices.Contains(blob.DuplicateBlobPath, path) {
				return nil
			}

			// the original blob is the one deleted: move a duplicate blob to original, storage
			// will move content here, or drop the record when no duplicate is left
			duplicate := ""
			if len(blob.DuplicateBlobPath) > 0 {
				duplicate = blob.DuplicateBlobPath[0]
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

	return d.conditionalAttemptsExhausted(digest, path, err)
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

	if err := d.decodeBlob(resp.Item, &out); err != nil {
		return out, err
	}

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

// decodeBlob decodes a stored record. A record that does not decode is reported, not read as
// an empty one: callers decide from its contents what to overwrite, promote or delete.
func (d *DynamoDBDriver) decodeBlob(item map[string]types.AttributeValue, out *Blob) error {
	if err := attributevalue.UnmarshalMap(item, out); err != nil {
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to decode blob")

		return err
	}

	return nil
}

// conditionalAttemptsExhausted reports a PutBlob or DeleteBlob that lost its conditional write
// maxConditionalAttempts times in a row. The last failure stays in the error chain.
func (d *DynamoDBDriver) conditionalAttemptsExhausted(digest godigest.Digest, path string, err error) error {
	err = fmt.Errorf("record kept changing, gave up after %d attempts: %w", maxConditionalAttempts, err)

	d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).
		Msg("failed to update blob record")

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

	if err := d.decodeBlob(resp.Item, &out); err != nil {
		return "", err
	}

	if len(out.DuplicateBlobPath) == 0 {
		return "", nil
	}

	return out.DuplicateBlobPath[0], nil
}

// putOriginBlob records path as the origin of digest and as one of its tracked paths, in a
// single write, unless an origin is already recorded, in which case it fails with a
// ConditionalCheckFailedException and leaves the record alone.
func (d *DynamoDBDriver) putOriginBlob(digest godigest.Digest, path string) error {
	expression := "SET OriginalBlobPath = :s ADD DuplicateBlobPath :i"
	condition := "attribute_not_exists(OriginalBlobPath) OR OriginalBlobPath = :empty"
	attrPath := types.AttributeValueMemberS{Value: path}
	attrPaths := types.AttributeValueMemberSS{Value: []string{path}}
	emptyPath := types.AttributeValueMemberS{Value: ""}

	return d.updateItem(digest, expression, map[string]types.AttributeValue{
		":empty": &emptyPath,
		":i":     &attrPaths,
		":s":     &attrPath,
	}, &condition)
}

// putDuplicateBlob adds path to the paths tracked for digest, as long as origin is still its
// origin. Without that condition the write would bring back a record deleted since it was
// read, with a tracked path but no origin to find the content by.
func (d *DynamoDBDriver) putDuplicateBlob(digest godigest.Digest, origin, path string) error {
	expression := "ADD DuplicateBlobPath :i"
	condition := "OriginalBlobPath = :origin"
	attrPaths := types.AttributeValueMemberSS{Value: []string{path}}
	originPath := types.AttributeValueMemberS{Value: origin}

	return d.updateItem(digest, expression, map[string]types.AttributeValue{
		":i":      &attrPaths,
		":origin": &originPath,
	}, &condition)
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
