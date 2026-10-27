//go:build sync

package sync

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

// manifestCheckKeyPrefix keeps these items apart from the dedupe cache's digest-keyed items when
// both share a table: a digest never contains "#".
const manifestCheckKeyPrefix = "manifestcheck#"

// manifestCheckStoreTimeout bounds each store call. A read that exceeds it counts as due and a
// write that exceeds it is dropped, so a slow store delays a pull by at most this much.
const manifestCheckStoreTimeout = 5 * time.Second

type manifestCheckItem struct {
	Digest      string `dynamodbav:"Digest,string"`
	LastChecked int64  `dynamodbav:"LastChecked,number"`
}

// dynamoManifestCheckTracker is a manifestCheckStore shared by all replicas through DynamoDB.
type dynamoManifestCheckTracker struct {
	client    *dynamodb.Client
	tableName string
	interval  time.Duration
	log       log.Logger
}

func newDynamoManifestCheckTracker(interval time.Duration, cfg *syncconf.ManifestCheckStoreConfig,
	log log.Logger,
) (*dynamoManifestCheckTracker, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, err
	}

	return &dynamoManifestCheckTracker{
		client:    dynamodb.NewFromConfig(awsCfg),
		tableName: cfg.TableName,
		interval:  interval,
		log:       log,
	}, nil
}

func manifestCheckDigestKey(repo, reference string) string {
	return manifestCheckKeyPrefix + trackerKey(repo, reference)
}

// ShouldCheckUpstream reports whether an upstream check is due for repo:reference. A read or
// decode failure counts as due, so a store outage costs an upstream check rather than a stale tag.
func (t *dynamoManifestCheckTracker) ShouldCheckUpstream(ctx context.Context, repo, reference string) bool {
	ctx, cancel := context.WithTimeout(ctx, manifestCheckStoreTimeout)
	defer cancel()

	resp, err := t.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(t.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: manifestCheckDigestKey(repo, reference)},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.log.Warn().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("failed to read manifest check state, treating as due")

		return true
	}

	if resp.Item == nil {
		return true
	}

	var item manifestCheckItem

	if err := attributevalue.UnmarshalMap(resp.Item, &item); err != nil {
		t.log.Warn().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("failed to decode manifest check state, treating as due")

		return true
	}

	return time.Since(time.Unix(0, item.LastChecked)) >= t.interval
}

// MarkChecked records a successful upstream check. A failed write is logged and not returned;
// the next request for this reference checks upstream again.
func (t *dynamoManifestCheckTracker) MarkChecked(ctx context.Context, repo, reference string) {
	item, err := attributevalue.MarshalMap(manifestCheckItem{
		Digest:      manifestCheckDigestKey(repo, reference),
		LastChecked: time.Now().UnixNano(),
	})
	if err != nil {
		t.log.Warn().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("failed to encode manifest check state")

		return
	}

	ctx, cancel := context.WithTimeout(ctx, manifestCheckStoreTimeout)
	defer cancel()

	if _, err := t.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(t.tableName),
		Item:      item,
	}); err != nil {
		t.log.Warn().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("failed to record manifest check state")
	}
}
