//go:build sync

package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
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

// manifestCheckNamespaceLen is how many hex characters of the registry hash go into a key.
const manifestCheckNamespaceLen = 16

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
	keyPrefix string
	interval  time.Duration
	log       log.Logger
}

func newDynamoManifestCheckTracker(config syncconf.RegistryConfig, log log.Logger,
) (*dynamoManifestCheckTracker, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(config.ManifestCheckStore.Region))
	if err != nil {
		return nil, err
	}

	return &dynamoManifestCheckTracker{
		client:    dynamodb.NewFromConfig(awsCfg),
		tableName: config.ManifestCheckStore.TableName,
		keyPrefix: manifestCheckKeyPrefix + manifestCheckNamespace(config) + "#",
		interval:  config.ManifestCheckInterval,
		log:       log,
	}, nil
}

// manifestCheckNamespace derives a key namespace from a registry's URLs and content rules, so
// that replicas with the same registry configuration share check state while other registries in
// the same table, a fallback mirror for instance, do not. The content rules are part of it because
// they decide which upstream repository a local name maps to: after a remapping, a check recorded
// for the old mapping must not vouch for the new one.
func manifestCheckNamespace(config syncconf.RegistryConfig) string {
	hash := sha256.New()
	hash.Write([]byte(strings.Join(config.URLs, "\n")))

	if len(config.Content) > 0 {
		if content, err := json.Marshal(config.Content); err == nil {
			hash.Write([]byte("\n"))
			hash.Write(content)
		}
	}

	return hex.EncodeToString(hash.Sum(nil))[:manifestCheckNamespaceLen]
}

// syncLeaseStore returns a lease store on the same table and client, namespaced like the tracker.
func (t *dynamoManifestCheckTracker) syncLeaseStore(urls []string) *dynamoSyncLeaseStore {
	return newDynamoSyncLeaseStore(t.client, t.tableName, manifestCheckNamespace(urls))
}

func (t *dynamoManifestCheckTracker) key(repo, reference string) string {
	return t.keyPrefix + trackerKey(repo, reference)
}

// ShouldCheckUpstream reports whether an upstream check is due for repo:reference. A read or
// decode failure counts as due, so a store outage costs an upstream check rather than a stale tag.
func (t *dynamoManifestCheckTracker) ShouldCheckUpstream(ctx context.Context, repo, reference string) bool {
	ctx, cancel := context.WithTimeout(ctx, manifestCheckStoreTimeout)
	defer cancel()

	resp, err := t.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(t.tableName),
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{Value: t.key(repo, reference)},
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
		Digest:      t.key(repo, reference),
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
