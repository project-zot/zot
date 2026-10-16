package cache

import (
	"context"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// The DynamoDB blob reference index keeps one item per digest in the cache table, keyed
// "blob_refs:<digest>" so it never collides with a blob item: GlobalBlob is set once the
// payload is recorded, RefPaths is the set of owning paths, and ClaimId and ClaimAt (Unix
// milliseconds) hold a sweep's claim. Each operation that depends on the record is one
// conditional write, which DynamoDB applies atomically. Claim times come from the instance's
// clock, so instances must agree on the time to within the lease, less the payload delete's
// deadline.

// SetReclaimClaimLease sets how long a reclaim claim stays live, constants.DefaultReclaimClaimLease
// unless set.
func (d *DynamoDBDriver) SetReclaimClaimLease(lease time.Duration) {
	d.claimLease = lease
}

func blobRefKey(digest godigest.Digest) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Digest": &types.AttributeValueMemberS{Value: constants.BlobRefsBucket + ":" + digest.String()},
	}
}

func millis(at time.Time) *types.AttributeValueMemberN {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(at.UnixMilli(), 10)}
}

// deadClaimBefore is the ClaimAt below which a claim is older than the lease.
func (d *DynamoDBDriver) deadClaimBefore(now time.Time) *types.AttributeValueMemberN {
	return millis(now.Add(-d.claimLease))
}

func (d *DynamoDBDriver) AddReference(digest godigest.Digest, path string) error {
	if path == "" {
		return zerr.ErrEmptyValue
	}

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName:           &d.tableName,
		Key:                 blobRefKey(digest),
		UpdateExpression:    aws.String("ADD RefPaths :path REMOVE ClaimId, ClaimAt"),
		ConditionExpression: aws.String("attribute_not_exists(ClaimId) OR ClaimAt < :dead"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":path": &types.AttributeValueMemberSS{Value: []string{path}},
			":dead": d.deadClaimBefore(time.Now()),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return zerr.ErrDigestClaimed
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to add blob reference")

		return err
	}

	return nil
}

func (d *DynamoDBDriver) RemoveReference(digest godigest.Digest, path string) (bool, error) {
	output, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName:        &d.tableName,
		Key:              blobRefKey(digest),
		UpdateExpression: aws.String("DELETE RefPaths :path"),
		// an update creates a missing item, which an unknown digest must not get
		ConditionExpression: aws.String("attribute_exists(Digest)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":path": &types.AttributeValueMemberSS{Value: []string{path}},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return true, nil
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to remove blob reference")

		return false, err
	}

	// DynamoDB removes a set once it is empty
	if _, owned := output.Attributes["RefPaths"]; owned {
		return false, nil
	}

	// forget a record left with no payload, owner or claim
	_, err = d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
		TableName: &d.tableName,
		Key:       blobRefKey(digest),
		ConditionExpression: aws.String("attribute_not_exists(RefPaths) AND attribute_not_exists(GlobalBlob) " +
			"AND attribute_not_exists(ClaimId)"),
	})
	if err != nil && !isConditionalCheckFailed(err) {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to forget unowned blob reference record")

		return true, err
	}

	return true, nil
}

// getBlobRefRecord reads the record of digest, strongly consistent; nil when there is none.
func (d *DynamoDBDriver) getBlobRefRecord(digest godigest.Digest) (map[string]types.AttributeValue, error) {
	output, err := d.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName:      &d.tableName,
		Key:            blobRefKey(digest),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}

	return output.Item, nil
}

func (d *DynamoDBDriver) GetReferences(digest godigest.Digest) ([]string, error) {
	record, err := d.getBlobRefRecord(digest)
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to get blob references")

		return nil, err
	}

	if record == nil {
		return nil, zerr.ErrCacheMiss
	}

	refs, ok := record["RefPaths"].(*types.AttributeValueMemberSS)
	if !ok {
		return []string{}, nil
	}

	return refs.Value, nil
}

func (d *DynamoDBDriver) RecordGlobal(digest godigest.Digest) error {
	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName:        &d.tableName,
		Key:              blobRefKey(digest),
		UpdateExpression: aws.String("SET GlobalBlob = :recorded"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":recorded": &types.AttributeValueMemberBOOL{Value: true},
		},
	})
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to record global blob")

		return err
	}

	return nil
}

func (d *DynamoDBDriver) ClaimReclaim(digest godigest.Digest) (storageTypes.ReclaimClaim, error) {
	claim := storageTypes.ReclaimClaim{Digest: digest, ID: newClaimID(), At: time.Now()}

	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName:        &d.tableName,
		Key:              blobRefKey(digest),
		UpdateExpression: aws.String("SET ClaimId = :id, ClaimAt = :at"),
		ConditionExpression: aws.String("GlobalBlob = :recorded AND attribute_not_exists(RefPaths) " +
			"AND (attribute_not_exists(ClaimId) OR ClaimAt < :dead)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":id":       &types.AttributeValueMemberS{Value: claim.ID},
			":at":       millis(claim.At),
			":recorded": &types.AttributeValueMemberBOOL{Value: true},
			":dead":     d.deadClaimBefore(claim.At),
		},
	})
	if err == nil {
		return claim, nil
	}

	if !isConditionalCheckFailed(err) {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to claim blob for reclaim")

		return storageTypes.ReclaimClaim{}, err
	}

	// The claim was refused; read the record to say why. It may have changed since, which
	// only affects which refusal is reported.
	record, err := d.getBlobRefRecord(digest)
	if err != nil {
		return storageTypes.ReclaimClaim{}, err
	}

	switch {
	case record["RefPaths"] != nil:
		return storageTypes.ReclaimClaim{}, zerr.ErrDigestReferenced
	case record["GlobalBlob"] == nil: // also when there is no record
		return storageTypes.ReclaimClaim{}, zerr.ErrCacheMiss
	default:
		return storageTypes.ReclaimClaim{}, zerr.ErrDigestClaimed
	}
}

func (d *DynamoDBDriver) FinishReclaim(claim storageTypes.ReclaimClaim) error {
	// a reference is only ever added after breaking the claim, so a held claim means none
	_, err := d.client.DeleteItem(context.TODO(), &dynamodb.DeleteItemInput{
		TableName:           &d.tableName,
		Key:                 blobRefKey(claim.Digest),
		ConditionExpression: aws.String("ClaimId = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":id": &types.AttributeValueMemberS{Value: claim.ID},
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return zerr.ErrReclaimClaimLost
		}

		d.log.Error().Err(err).Str("digest", claim.Digest.String()).Msg("failed to finish blob reclaim")

		return err
	}

	return nil
}

func (d *DynamoDBDriver) AbandonReclaim(claim storageTypes.ReclaimClaim) error {
	_, err := d.client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		TableName:           &d.tableName,
		Key:                 blobRefKey(claim.Digest),
		UpdateExpression:    aws.String("REMOVE ClaimId, ClaimAt"),
		ConditionExpression: aws.String("ClaimId = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":id": &types.AttributeValueMemberS{Value: claim.ID},
		},
	})
	if err != nil && !isConditionalCheckFailed(err) {
		d.log.Error().Err(err).Str("digest", claim.Digest.String()).Msg("failed to abandon blob reclaim")

		return err
	}

	return nil
}
