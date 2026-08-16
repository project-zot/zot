package cache

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	guuid "github.com/gofrs/uuid"
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

func (d *DynamoDBDriver) blobRefDigest(digest godigest.Digest) string {
	return "blob_refs:" + digest.String()
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
		ConsistentRead: aws.Bool(true),
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

func (d *DynamoDBDriver) PutBlobRef(digest godigest.Digest, path string) error {
	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).
			Msg("failed to put blob ref because the path provided is empty")

		return zerr.ErrEmptyValue
	}

	refDigest := d.blobRefDigest(digest)

	var originBlob string

	// optimistic-concurrency loop: retry until one writer establishes the origin
	// and this reader observes stable state
	for {
		var err error

		originBlob, err = d.GetBlob(godigest.Digest(refDigest))
		if err != nil {
			if !errors.Is(err, zerr.ErrCacheMiss) {
				return err
			}

			if err := d.putOriginBlob(godigest.Digest(refDigest), path); err != nil {
				if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
					continue
				}

				return err
			}

			return nil
		}

		if originBlob == "" {
			if err := d.putOriginBlob(godigest.Digest(refDigest), path); err != nil {
				if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
					continue
				}

				return err
			}

			return nil
		}

		break
	}

	if originBlob == path {
		return nil
	}

	expression := "ADD DuplicateBlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{path}}

	if err := d.updateItem(
		godigest.Digest(refDigest),
		expression,
		map[string]types.AttributeValue{":i": &attrPath},
		nil,
	); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put blob ref")

		return err
	}

	return nil
}

func (d *DynamoDBDriver) GetBlobRefs(digest godigest.Digest) ([]string, error) {
	refDigest := d.blobRefDigest(digest)

	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: refDigest},
		},
		// blob refs gate global-blob reclamation; a stale read could make live ownership appear absent
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob ref")

		return nil, err
	}

	out := Blob{}

	if resp.Item == nil {
		return nil, zerr.ErrCacheMiss
	}

	_ = attributevalue.UnmarshalMap(resp.Item, &out)

	blobPaths := []string{}

	// skip a missing/empty origin: an "" entry would surface as a phantom blob ref downstream
	if out.OriginalBlobPath != "" {
		blobPaths = append(blobPaths, out.OriginalBlobPath)
	}

	for _, item := range out.DuplicateBlobPath {
		if item != "" && item != out.OriginalBlobPath {
			blobPaths = append(blobPaths, item)
		}
	}

	// No usable path left (e.g. a stale/partial record from a race with DeleteBlobRef):
	// report a miss so callers fall back to the authoritative GetAllBlobs scan instead of
	// treating "no paths" as "definitely unreferenced" and reclaiming a blob still in use.
	if len(blobPaths) == 0 {
		return nil, zerr.ErrCacheMiss
	}

	return blobPaths, nil
}

func (d *DynamoDBDriver) GetAllBlobRefs() (map[godigest.Digest][]string, error) {
	allRefs := map[godigest.Digest][]string{}

	var startKey map[string]types.AttributeValue

	for {
		resp, err := d.client.Scan(context.TODO(), &dynamodb.ScanInput{
			TableName:         aws.String(d.tableName),
			ExclusiveStartKey: startKey,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, err
		}

		for _, item := range resp.Items {
			blob := Blob{}
			if err := attributevalue.UnmarshalMap(item, &blob); err != nil {
				return nil, err
			}

			digestString, ok := strings.CutPrefix(blob.Digest, "blob_refs:")
			if !ok {
				continue
			}

			digest := godigest.Digest(digestString)
			if err := digest.Validate(); err != nil {
				continue
			}

			if blob.OriginalBlobPath != "" {
				allRefs[digest] = append(allRefs[digest], blob.OriginalBlobPath)
			}

			for _, ref := range blob.DuplicateBlobPath {
				if ref != "" && ref != blob.OriginalBlobPath {
					allRefs[digest] = append(allRefs[digest], ref)
				}
			}
		}

		if len(resp.LastEvaluatedKey) == 0 {
			return allRefs, nil
		}

		startKey = resp.LastEvaluatedKey
	}
}

func (d *DynamoDBDriver) DeleteBlobRef(digest godigest.Digest, path string) error {
	refDigest := d.blobRefDigest(digest)
	m_marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": refDigest})

	duplicateBlob, err := d.GetDuplicateBlob(godigest.Digest(refDigest))
	if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		return err
	}

	if duplicateBlob != "" {
		resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
			TableName: aws.String(d.tableName),
			Key: map[string]types.AttributeValue{
				"Digest": &types.AttributeValueMemberS{Value: refDigest},
			},
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return err
		}

		out := Blob{}
		if resp.Item != nil {
			_ = attributevalue.UnmarshalMap(resp.Item, &out)

			if slices.Contains(out.DuplicateBlobPath, path) {
				expression := "DELETE DuplicateBlobPath :i"
				attrPath := types.AttributeValueMemberSS{Value: []string{path}}

				if err := d.updateItem(
					godigest.Digest(refDigest),
					expression,
					map[string]types.AttributeValue{":i": &attrPath},
					nil,
				); err != nil {
					d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to delete blob ref")

					return err
				}

				return nil
			}
		}
	}

	originBlob, err := d.GetBlob(godigest.Digest(refDigest))
	if err != nil {
		return err
	}

	if originBlob == path {
		// promote a duplicate to origin so GetBlobRefs stops reporting this deleted path,
		// or drop the item when no duplicate is left
		return d.removeOrigin(godigest.Digest(refDigest), path)
	}

	if originBlob == "" {
		_, _ = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			Key:       m_marshaledKey,
			TableName: &d.tableName,
		})

		return zerr.ErrCacheMiss
	}

	return zerr.ErrCacheMiss
}

// removeOrigin drops oldOrigin as the origin of digest: a remaining duplicate is promoted
// in its place, or the whole item is deleted when no duplicate is left.
//
// The item is read first, so both writes are conditioned on what that read saw and are
// retried when a concurrent writer got in between:
//   - promotion requires the chosen duplicate to still be in the set. DELETE on a set is a
//     no-op for a missing member, so without this a duplicate removed by a concurrent
//     DeleteBlob/DeleteBlobRef would be resurrected as the origin.
//   - deletion requires the set to still be empty, so a duplicate added by a concurrent
//     PutBlob is promoted on the next pass instead of being dropped with the item.
//
// The loop ends without writing once OriginalBlobPath is no longer oldOrigin (or the item
// is gone): another writer already replaced or removed it.
func (d *DynamoDBDriver) removeOrigin(digest godigest.Digest, oldOrigin string) error {
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})
	oldPath := types.AttributeValueMemberS{Value: oldOrigin}

	for {
		resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
			TableName:      aws.String(d.tableName),
			Key:            marshaledKey,
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			d.log.Error().Err(err).Str("tableName", d.tableName).Msg("failed to get blob")

			return err
		}

		if resp.Item == nil {
			return nil
		}

		out := Blob{}
		_ = attributevalue.UnmarshalMap(resp.Item, &out)

		if out.OriginalBlobPath != oldOrigin {
			return nil
		}

		if len(out.DuplicateBlobPath) > 0 {
			duplicate := out.DuplicateBlobPath[0]
			expression := "SET OriginalBlobPath = :new DELETE DuplicateBlobPath :i"
			conditionExpression := "OriginalBlobPath = :old AND contains(DuplicateBlobPath, :new)"
			newPath := types.AttributeValueMemberS{Value: duplicate}
			removedSet := types.AttributeValueMemberSS{Value: []string{duplicate}}

			_, err = d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
				Key:              marshaledKey,
				TableName:        &d.tableName,
				UpdateExpression: &expression,
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":new": &newPath,
					":i":   &removedSet,
					":old": &oldPath,
				},
				ConditionExpression: &conditionExpression,
			})
		} else {
			conditionExpression := "OriginalBlobPath = :old AND " +
				"(attribute_not_exists(DuplicateBlobPath) OR size(DuplicateBlobPath) = :zero)"
			zero := types.AttributeValueMemberN{Value: "0"}

			_, err = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
				Key:                 marshaledKey,
				TableName:           &d.tableName,
				ConditionExpression: &conditionExpression,
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":old":  &oldPath,
					":zero": &zero,
				},
			})
		}

		if err == nil {
			return nil
		}

		if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
			continue
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", oldOrigin).
			Msg("failed to remove origin blob")

		return err
	}
}

func (d *DynamoDBDriver) PutBlob(digest godigest.Digest, path string) error {
	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).
			Msg("failed to put blob because the path provided is empty")

		return zerr.ErrEmptyValue
	}

	var originBlob string

	for {
		var err error

		originBlob, err = d.GetBlob(digest)
		if err != nil {
			if !errors.Is(err, zerr.ErrCacheMiss) {
				return err
			}

			// first entry, so add original blob only
			if err := d.putOriginBlob(digest, path); err != nil {
				if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
					continue
				}

				return err
			}

			return nil
		}

		if originBlob == "" {
			// item exists but has no origin path (partial/legacy state); repair it
			if err := d.putOriginBlob(digest, path); err != nil {
				if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
					continue
				}

				return err
			}

			return nil
		}

		// Origin exists and is visible; safe to exit retry loop.
		break
	}

	// if same as original, this is idempotent
	if originBlob == path {
		return nil
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

	// OriginalBlobPath and DuplicateBlobPath are disjoint (see PutBlob), so a replaced
	// origin has to be demoted into the duplicate set or it drops out of the cache. The
	// stale path is only known after a (strongly consistent) read, hence the conditional
	// write and the retry when a concurrent writer changed the origin in between.
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})

	for {
		current, err := d.GetBlob(digest)
		if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			return err
		}

		if current == originPath {
			return nil
		}

		expression := "SET OriginalBlobPath = :s"
		condition := "attribute_not_exists(OriginalBlobPath) OR OriginalBlobPath = :cur"
		attrVals := map[string]types.AttributeValue{
			":s":   &types.AttributeValueMemberS{Value: originPath},
			":cur": &types.AttributeValueMemberS{Value: current},
		}

		if current != "" {
			expression += " ADD DuplicateBlobPath :old"
			condition = "OriginalBlobPath = :cur"
			attrVals[":old"] = &types.AttributeValueMemberSS{Value: []string{current}}
		}

		_, err = d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
			Key:                       marshaledKey,
			TableName:                 &d.tableName,
			UpdateExpression:          &expression,
			ConditionExpression:       &condition,
			ExpressionAttributeValues: attrVals,
		})
		if err != nil {
			if _, ok := errors.AsType[*types.ConditionalCheckFailedException](err); ok {
				continue
			}

			d.log.Error().Err(err).Str("digest", digest.String()).Str("path", originPath).Msg("failed to set origin")

			return err
		}

		break
	}

	// The new origin must not stay behind as a duplicate: DeleteBlob checks the set first
	// and would otherwise leave the origin pointing at a deleted path. A separate call
	// because one update expression cannot both ADD to and DELETE from the same attribute.
	expression := "DELETE DuplicateBlobPath :i"
	attrPath := types.AttributeValueMemberSS{Value: []string{originPath}}

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}, nil); err != nil {
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
	marshaledKey, _ := attributevalue.MarshalMap(map[string]any{"Digest": digest.String()})

	duplicateBlob, err := d.GetDuplicateBlob(digest)
	if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		return err
	}

	if duplicateBlob != "" {
		resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
			TableName: aws.String(d.tableName),
			Key: map[string]types.AttributeValue{
				"Digest": &types.AttributeValueMemberS{Value: digest.String()},
			},
		})
		if err != nil {
			return err
		}

		out := Blob{}
		if resp.Item != nil {
			_ = attributevalue.UnmarshalMap(resp.Item, &out)

			if slices.Contains(out.DuplicateBlobPath, path) {
				expression := "DELETE DuplicateBlobPath :i"
				attrPath := types.AttributeValueMemberSS{Value: []string{path}}

				if err := d.updateItem(digest, expression, map[string]types.AttributeValue{":i": &attrPath}, nil); err != nil {
					d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to delete")

					return err
				}

				return nil
			}
		}
	}

	originBlob, err := d.GetBlob(digest)
	if err != nil {
		if errors.Is(err, zerr.ErrCacheMiss) {
			// digest isn't tracked at all - nothing to delete
			return nil
		}

		return err
	}

	// if original blob is the one being deleted
	if originBlob == path {
		// promote a duplicate to origin so GetAllBlobs/HasBlob stop reporting this deleted path,
		// or drop the item when no duplicate is left
		return d.removeOrigin(digest, path)
	}

	// originBlob is empty but record exists (orphaned entry) — clean up
	if originBlob == "" {
		d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")

		_, _ = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			Key:       marshaledKey,
			TableName: &d.tableName,
		})

		return nil
	}

	// path not found in duplicates or original - nothing to delete
	return nil
}

func (d *DynamoDBDriver) GetDuplicateBlob(digest godigest.Digest) (string, error) {
	resp, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: digest.String()},
		},
		ConsistentRead: aws.Bool(true),
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
	emptyPath := types.AttributeValueMemberS{Value: ""}
	conditionExpression := "attribute_not_exists(OriginalBlobPath) OR OriginalBlobPath = :empty"

	if err := d.updateItem(digest, expression, map[string]types.AttributeValue{
		":empty": &emptyPath,
		":s":     &attrPath,
	}, &conditionExpression); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Str("path", path).Msg("failed to put original blob")

		return err
	}

	return nil
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

func (d *DynamoDBDriver) reclaimLockKey(digest godigest.Digest) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Digest": &types.AttributeValueMemberS{Value: "reclaim_lock:" + digest.String()},
	}
}

// TryLockBlobReclaim takes the cross-instance lock a global blob reclaim sweep holds while it
// decides on and deletes digest's payload. It makes one attempt and reports false, not an
// error, if another instance holds the lock.
//
// The lock is an item written only if absent or expired. DynamoDB conditions cannot see the
// server's clock, so expiry is judged by the caller's: ttl must therefore be longer than the
// time the lock is really needed for plus the clock skew between instances. A sweep that
// crashed while holding it only delays that digest's next sweep by ttl.
func (d *DynamoDBDriver) TryLockBlobReclaim(digest godigest.Digest, ttl time.Duration) (func(), bool, error) {
	ownerID, err := guuid.NewV4()
	if err != nil {
		return nil, false, err
	}

	now := time.Now()
	owner := ownerID.String()
	key := d.reclaimLockKey(digest)

	item := d.reclaimLockKey(digest)
	item["LockOwner"] = &types.AttributeValueMemberS{Value: owner}
	item["LockExpiresAt"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Add(ttl).UnixMilli(), 10)}

	_, err = d.client.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName:           &d.tableName,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(Digest) OR LockExpiresAt < :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(now.UnixMilli(), 10)},
		},
	})
	if err != nil {
		if _, held := errors.AsType[*types.ConditionalCheckFailedException](err); held {
			return nil, false, nil
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to acquire blob reclaim lock")

		return nil, false, err
	}

	return func() {
		// Only our own lock: it may have expired and been taken over by another instance.
		_, err := d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
			TableName:           &d.tableName,
			Key:                 key,
			ConditionExpression: aws.String("LockOwner = :owner"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":owner": &types.AttributeValueMemberS{Value: owner},
			},
		})
		if err != nil {
			if _, lost := errors.AsType[*types.ConditionalCheckFailedException](err); lost {
				return
			}

			// Not fatal: the lock expires on its own.
			d.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to release blob reclaim lock")
		}
	}, true, nil
}
