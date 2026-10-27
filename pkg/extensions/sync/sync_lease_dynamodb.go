//go:build sync

package sync

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// syncLeaseKeyPrefix keeps lease items apart from manifest check items and from the dedupe
// cache's digests in a shared table.
const syncLeaseKeyPrefix = "synclease#"

// dynamoSyncLeaseStore is a syncLeaseStore backed by conditional writes on a DynamoDB table with
// a string partition key named "Digest". Each item holds the owner and an ExpiresAt epoch second.
type dynamoSyncLeaseStore struct {
	client    *dynamodb.Client
	tableName string
	keyPrefix string
	now       func() time.Time
}

func newDynamoSyncLeaseStore(client *dynamodb.Client, tableName, namespace string) *dynamoSyncLeaseStore {
	return &dynamoSyncLeaseStore{
		client:    client,
		tableName: tableName,
		keyPrefix: syncLeaseKeyPrefix + namespace + "#",
		now:       time.Now,
	}
}

func (s *dynamoSyncLeaseStore) itemKey(key string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"Digest": &types.AttributeValueMemberS{Value: s.keyPrefix + key},
	}
}

func (s *dynamoSyncLeaseStore) expiresAt(ttl time.Duration) string {
	return strconv.FormatInt(s.now().Add(ttl).Unix(), 10)
}

func (s *dynamoSyncLeaseStore) nowEpoch() string {
	return strconv.FormatInt(s.now().Unix(), 10)
}

func (s *dynamoSyncLeaseStore) Acquire(ctx context.Context, key, owner string, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, manifestCheckStoreTimeout)
	defer cancel()

	item := s.itemKey(key)
	item["Owner"] = &types.AttributeValueMemberS{Value: owner}
	item["ExpiresAt"] = &types.AttributeValueMemberN{Value: s.expiresAt(ttl)}

	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(#k) OR #exp < :now OR #owner = :owner"),
		ExpressionAttributeNames: map[string]string{
			"#k":     "Digest",
			"#exp":   "ExpiresAt",
			"#owner": "Owner",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":   &types.AttributeValueMemberN{Value: s.nowEpoch()},
			":owner": &types.AttributeValueMemberS{Value: owner},
		},
	})

	return leaseWriteResult(err)
}

func (s *dynamoSyncLeaseStore) Renew(ctx context.Context, key, owner string, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, manifestCheckStoreTimeout)
	defer cancel()

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.tableName),
		Key:                 s.itemKey(key),
		UpdateExpression:    aws.String("SET #exp = :exp"),
		ConditionExpression: aws.String("attribute_exists(#k) AND #owner = :owner"),
		ExpressionAttributeNames: map[string]string{
			"#k":     "Digest",
			"#exp":   "ExpiresAt",
			"#owner": "Owner",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":exp":   &types.AttributeValueMemberN{Value: s.expiresAt(ttl)},
			":owner": &types.AttributeValueMemberS{Value: owner},
		},
	})

	return leaseWriteResult(err)
}

func (s *dynamoSyncLeaseStore) Release(ctx context.Context, key, owner string) error {
	ctx, cancel := context.WithTimeout(ctx, manifestCheckStoreTimeout)
	defer cancel()

	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(s.tableName),
		Key:                      s.itemKey(key),
		ConditionExpression:      aws.String("#owner = :owner"),
		ExpressionAttributeNames: map[string]string{"#owner": "Owner"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner": &types.AttributeValueMemberS{Value: owner},
		},
	})

	_, err = leaseWriteResult(err)

	return err
}

// leaseWriteResult maps a failed condition to (false, nil): the lease belongs to someone else.
func leaseWriteResult(err error) (bool, error) {
	if err == nil {
		return true, nil
	}

	var conditionFailed *types.ConditionalCheckFailedException
	if errors.As(err, &conditionFailed) {
		return false, nil
	}

	return false, err
}
