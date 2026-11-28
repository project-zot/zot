package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"
	guuid "github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	imgutils "zotregistry.dev/zot/v2/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

var errInjected = errors.New("injected failure")

const (
	batchRepo        = "batch/repo"
	boundSettleDelay = 50 * time.Millisecond
	boundProbeBatch  = 33
	boundMaxInFlight = 32
	boundRefsPerRepo = 100
	failingRefCount  = 10
	failingRefIndex  = 6
)

// imageMetaGate holds every ImageMeta UpdateItem until a probe batch arrived or the settle delay passed and
// records how many were in flight at once.
type imageMetaGate struct {
	table      string
	failDigest string

	arrived   atomic.Int32
	inFlight  atomic.Int32
	maxFlight atomic.Int32

	release     chan struct{}
	releaseOnce sync.Once
}

func newImageMetaGate(table string) *imageMetaGate {
	return &imageMetaGate{table: table, release: make(chan struct{})}
}

func (g *imageMetaGate) addMiddleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("gateImageMetaWrites", func(
		ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
	) (middleware.InitializeOutput, middleware.Metadata, error) {
		input, ok := in.Parameters.(*dynamodb.UpdateItemInput)
		if !ok || aws.ToString(input.TableName) != g.table {
			return next.HandleInitialize(ctx, in)
		}

		digest := ""
		if key, ok := input.Key["TableKey"].(*types.AttributeValueMemberS); ok {
			digest = key.Value
		}

		if g.failDigest != "" && digest == g.failDigest {
			return middleware.InitializeOutput{}, middleware.Metadata{}, fmt.Errorf("%w for %s", errInjected, digest)
		}

		current := g.inFlight.Add(1)

		for {
			maxSeen := g.maxFlight.Load()
			if current <= maxSeen || g.maxFlight.CompareAndSwap(maxSeen, current) {
				break
			}
		}

		if g.arrived.Add(1) >= boundProbeBatch {
			g.releaseOnce.Do(func() { close(g.release) })
		}

		select {
		case <-g.release:
		case <-time.After(boundSettleDelay):
		}

		out, metadata, err := next.HandleInitialize(ctx, in)
		g.inFlight.Add(-1)

		return out, metadata, err
	}), middleware.Before)
}

func newDynamoParams() DBDriverParameters {
	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	return DBDriverParameters{
		Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
		Region:                 "us-east-2",
		RepoMetaTablename:      "RepoMetadataTable" + uuid.String(),
		ImageMetaTablename:     "ImageMeta" + uuid.String(),
		RepoBlobsInfoTablename: "RepoBlobs" + uuid.String(),
		VersionTablename:       "Version" + uuid.String(),
		APIKeyTablename:        "ApiKeyTable" + uuid.String(),
		UserDataTablename:      "UserDataTable" + uuid.String(),
	}
}

func newBatchDynamoDB(t *testing.T, params DBDriverParameters, gate *imageMetaGate) *DynamoDB {
	t.Helper()

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(params.Region))
	if err != nil {
		t.Fatalf("failed to load aws config: %v", err)
	}

	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(params.Endpoint)

		if gate != nil {
			o.APIOptions = append(o.APIOptions, gate.addMiddleware)
		}
	})

	wrapper, err := New(client, params, log.NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create dynamo wrapper: %v", err)
	}

	t.Cleanup(func() {
		for _, table := range []string{
			params.RepoMetaTablename, params.ImageMetaTablename, params.RepoBlobsInfoTablename,
			params.VersionTablename, params.APIKeyTablename, params.UserDataTablename,
		} {
			_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
		}
	})

	return wrapper
}

// batchFixture returns references covering tags, a second tag and a re-pointed tag of one digest, an index tagged
// after its children, a child added by digest after its index and a referrer with a subject.
func batchFixture(pushTime time.Time) []mTypes.RepoReference {
	pushOpts := []mTypes.SetRepoReferenceOption{mTypes.WithPushTimestamp(pushTime)}

	imgA, imgB, imgC := imgutils.CreateRandomImage(), imgutils.CreateRandomImage(), imgutils.CreateRandomImage()
	child1, child2, child3 := imgutils.CreateRandomImage(), imgutils.CreateRandomImage(), imgutils.CreateRandomImage()
	index := imgutils.CreateMultiarchWith().Images([]imgutils.Image{child1, child2, child3}).Build()
	referrer := imgutils.CreateRandomImageWith().Subject(imgA.DescriptorRef()).Build()

	ref := func(reference string, imageMeta mTypes.ImageMeta) mTypes.RepoReference {
		return mTypes.RepoReference{Reference: reference, ImageMeta: imageMeta, Opts: pushOpts}
	}

	return []mTypes.RepoReference{
		ref("t1", imgA.AsImageMeta()),
		ref("t2", imgB.AsImageMeta()),
		ref("t3", imgC.AsImageMeta()),
		ref("t3", imgA.AsImageMeta()),
		ref("c1", child1.AsImageMeta()),
		ref("c2", child2.AsImageMeta()),
		ref("idx", index.AsImageMeta()),
		ref(child3.DigestStr(), child3.AsImageMeta()),
		ref(referrer.DigestStr(), referrer.AsImageMeta()),
	}
}

func distinctRefs(count int, pushTime time.Time) []mTypes.RepoReference {
	refs := make([]mTypes.RepoReference, 0, count)

	for i := range count {
		refs = append(refs, mTypes.RepoReference{
			Reference: fmt.Sprintf("tag%d", i),
			ImageMeta: imgutils.CreateRandomImage().AsImageMeta(),
			Opts:      []mTypes.SetRepoReferenceOption{mTypes.WithPushTimestamp(pushTime)},
		})
	}

	return refs
}

func platformKey(platform *proto_go.Platform) string {
	return platform.GetOS() + "/" + platform.GetArchitecture() + "/" + platform.GetVariant()
}

func sortPlatforms(platforms []*proto_go.Platform) {
	slices.SortFunc(platforms, func(a, b *proto_go.Platform) int {
		return strings.Compare(platformKey(a), platformKey(b))
	})
}

// rawRepoState reads RepoMeta and RepoBlobs of the repo as stored, with the lists built from map iteration sorted.
func rawRepoState(t *testing.T, wrapper *DynamoDB, repo string) (*proto_go.RepoMeta, *proto_go.RepoBlobs) {
	t.Helper()

	repoMeta, err := wrapper.getProtoRepoMeta(context.Background(), repo)
	if err != nil {
		t.Fatalf("failed to read raw RepoMeta: %v", err)
	}

	repoBlobs, err := wrapper.getProtoRepoBlobs(context.Background(), repo)
	if err != nil {
		t.Fatalf("failed to read raw RepoBlobs: %v", err)
	}

	slices.Sort(repoMeta.Vendors)
	sortPlatforms(repoMeta.Platforms)

	for _, blob := range repoBlobs.Blobs {
		slices.Sort(blob.Vendors)
		sortPlatforms(blob.Platforms)
	}

	return repoMeta, repoBlobs
}

func itemExists(t *testing.T, wrapper *DynamoDB, table, key string) bool {
	t.Helper()

	resp, err := wrapper.Client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName:      aws.String(table),
		Key:            map[string]types.AttributeValue{"TableKey": &types.AttributeValueMemberS{Value: key}},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("failed to read item %s from %s: %v", key, table, err)
	}

	return resp.Item != nil
}

func cloneDynamoState(t *testing.T, source *DynamoDB) *DynamoDB {
	t.Helper()

	target := newBatchDynamoDB(t, newDynamoParams(), nil)

	copies := map[string]string{
		source.ImageMetaTablename: target.ImageMetaTablename,
		source.RepoMetaTablename:  target.RepoMetaTablename,
		source.RepoBlobsTablename: target.RepoBlobsTablename,
	}

	for sourceTable, targetTable := range copies {
		var lastKey map[string]types.AttributeValue

		for {
			page, err := source.Client.Scan(context.Background(), &dynamodb.ScanInput{
				TableName:         aws.String(sourceTable),
				ConsistentRead:    aws.Bool(true),
				ExclusiveStartKey: lastKey,
			})
			if err != nil {
				t.Fatalf("failed to scan %s: %v", sourceTable, err)
			}

			for _, item := range page.Items {
				_, err := target.Client.PutItem(context.Background(), &dynamodb.PutItemInput{
					TableName: aws.String(targetTable),
					Item:      item,
				})
				if err != nil {
					t.Fatalf("failed to put item into %s: %v", targetTable, err)
				}
			}

			if page.LastEvaluatedKey == nil {
				break
			}

			lastKey = page.LastEvaluatedKey
		}
	}

	return target
}

func assertSameState(t *testing.T, batch, sequential *DynamoDB, refs []mTypes.RepoReference) {
	t.Helper()

	batchMeta, batchBlobs := rawRepoState(t, batch, batchRepo)
	sequentialMeta, sequentialBlobs := rawRepoState(t, sequential, batchRepo)

	if !proto.Equal(batchMeta, sequentialMeta) {
		t.Errorf("RepoMeta differs\nbatch:      %v\nsequential: %v", batchMeta, sequentialMeta)
	}

	if !proto.Equal(batchBlobs, sequentialBlobs) {
		t.Errorf("RepoBlobs differs\nbatch:      %v\nsequential: %v", batchBlobs, sequentialBlobs)
	}

	for _, ref := range refs {
		batchImage, err := batch.GetImageMeta(ref.ImageMeta.Digest)
		if err != nil {
			t.Fatalf("batch GetImageMeta(%s): %v", ref.ImageMeta.Digest, err)
		}

		sequentialImage, err := sequential.GetImageMeta(ref.ImageMeta.Digest)
		if err != nil {
			t.Fatalf("sequential GetImageMeta(%s): %v", ref.ImageMeta.Digest, err)
		}

		if !reflect.DeepEqual(batchImage, sequentialImage) {
			t.Errorf("ImageMeta of %s differs", ref.ImageMeta.Digest)
		}
	}
}

func TestSetRepoReferencesEqualsSequential(t *testing.T) {
	tskip.SkipDynamo(t)

	ctx := context.Background()
	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("empty start state", func(t *testing.T) {
		refs := batchFixture(pushTime)
		batch := newBatchDynamoDB(t, newDynamoParams(), nil)
		sequential := newBatchDynamoDB(t, newDynamoParams(), nil)

		if err := batch.SetRepoReferences(ctx, batchRepo, refs); err != nil {
			t.Fatalf("SetRepoReferences: %v", err)
		}

		for _, ref := range refs {
			if err := sequential.SetRepoReference(ctx, batchRepo, ref.Reference, ref.ImageMeta, ref.Opts...); err != nil {
				t.Fatalf("SetRepoReference: %v", err)
			}
		}

		assertSameState(t, batch, sequential, refs)
	})

	t.Run("prepopulated start state", func(t *testing.T) {
		refs := batchFixture(pushTime)
		seed := newBatchDynamoDB(t, newDynamoParams(), nil)

		for _, ref := range refs[:5] {
			if err := seed.SetRepoReference(ctx, batchRepo, ref.Reference, ref.ImageMeta, ref.Opts...); err != nil {
				t.Fatalf("seed SetRepoReference: %v", err)
			}
		}

		if err := seed.UpdateStatsOnDownload(batchRepo, "t1"); err != nil {
			t.Fatalf("UpdateStatsOnDownload: %v", err)
		}

		extra := imgutils.CreateRandomImage().AsImageMeta()
		if err := seed.SetRepoReference(ctx, batchRepo, "extra", extra); err != nil {
			t.Fatalf("seed SetRepoReference without push timestamp: %v", err)
		}

		batch := cloneDynamoState(t, seed)
		sequential := cloneDynamoState(t, seed)

		if err := batch.SetRepoReferences(ctx, batchRepo, refs); err != nil {
			t.Fatalf("SetRepoReferences: %v", err)
		}

		for _, ref := range refs {
			if err := sequential.SetRepoReference(ctx, batchRepo, ref.Reference, ref.ImageMeta, ref.Opts...); err != nil {
				t.Fatalf("SetRepoReference: %v", err)
			}
		}

		assertSameState(t, batch, sequential, refs)
	})
}

func TestSetRepoReferencesLastUpdatedAndValidation(t *testing.T) {
	tskip.SkipDynamo(t)

	ctx := context.Background()
	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("repo last updated is written", func(t *testing.T) {
		wrapper := newBatchDynamoDB(t, newDynamoParams(), nil)
		before := time.Now()

		if err := wrapper.SetRepoReferences(ctx, batchRepo, batchFixture(pushTime)[:2]); err != nil {
			t.Fatalf("SetRepoReferences: %v", err)
		}

		if lastUpdated := wrapper.GetRepoLastUpdated(batchRepo); lastUpdated.Before(before) {
			t.Errorf("RepoLastUpdated %v is before the call at %v", lastUpdated, before)
		}
	})

	t.Run("nil references write nothing", func(t *testing.T) {
		wrapper := newBatchDynamoDB(t, newDynamoParams(), nil)

		if err := wrapper.SetRepoReferences(ctx, batchRepo, nil); err != nil {
			t.Fatalf("SetRepoReferences(nil): %v", err)
		}

		if _, err := wrapper.getProtoRepoMeta(ctx, batchRepo); !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			t.Errorf("expected ErrRepoMetaNotFound after empty batch, got: %v", err)
		}

		if lastUpdated := wrapper.GetRepoLastUpdated(batchRepo); !lastUpdated.IsZero() {
			t.Errorf("expected no RepoLastUpdated after empty batch, got %v", lastUpdated)
		}
	})

	t.Run("invalid last reference writes nothing", func(t *testing.T) {
		wrapper := newBatchDynamoDB(t, newDynamoParams(), nil)
		refs := batchFixture(pushTime)[:2]
		refs[1].Reference = ""

		if err := wrapper.SetRepoReferences(ctx, batchRepo, refs); !errors.Is(err, zerr.ErrEmptyTag) {
			t.Fatalf("expected ErrEmptyTag, got: %v", err)
		}

		if _, err := wrapper.GetImageMeta(refs[0].ImageMeta.Digest); !errors.Is(err, zerr.ErrImageMetaNotFound) {
			t.Errorf("ImageMeta of the first reference was written, got: %v", err)
		}

		if _, err := wrapper.getProtoRepoMeta(ctx, batchRepo); !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			t.Errorf("RepoMeta was written, got: %v", err)
		}
	})
}

func TestSetRepoReferencesImageMetaConcurrencyAndError(t *testing.T) {
	tskip.SkipDynamo(t)

	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	for name, repoCount := range map[string]int{"one call": 1, "two concurrent calls": 2} {
		t.Run("concurrency "+name, func(t *testing.T) {
			params := newDynamoParams()
			gate := newImageMetaGate(params.ImageMetaTablename)
			wrapper := newBatchDynamoDB(t, params, gate)

			var waitGroup sync.WaitGroup

			for i := range repoCount {
				refs := distinctRefs(boundRefsPerRepo, pushTime)
				repo := fmt.Sprintf("batch/repo%d", i)

				waitGroup.Go(func() {
					if err := wrapper.SetRepoReferences(context.Background(), repo, refs); err != nil {
						t.Errorf("SetRepoReferences(%s): %v", repo, err)
					}
				})
			}

			waitGroup.Wait()

			if maxFlight := gate.maxFlight.Load(); maxFlight <= 1 || maxFlight > boundMaxInFlight {
				t.Errorf("max concurrent ImageMeta writes is %d, want > 1 and <= %d", maxFlight, boundMaxInFlight)
			}
		})
	}

	t.Run("failed ImageMeta write stores no repo state", func(t *testing.T) {
		params := newDynamoParams()
		gate := newImageMetaGate(params.ImageMetaTablename)
		wrapper := newBatchDynamoDB(t, params, gate)

		refs := distinctRefs(failingRefCount, pushTime)
		gate.failDigest = refs[failingRefIndex].ImageMeta.Digest.String()

		err := wrapper.SetRepoReferences(context.Background(), batchRepo, refs)
		if !errors.Is(err, errInjected) || !strings.Contains(err.Error(), gate.failDigest) {
			t.Fatalf("expected the injected ImageMeta error, got: %v", err)
		}

		if itemExists(t, wrapper, params.RepoMetaTablename, batchRepo) {
			t.Errorf("RepoMeta was written although an ImageMeta write failed")
		}

		if itemExists(t, wrapper, params.RepoBlobsInfoTablename, batchRepo) {
			t.Errorf("RepoBlobs was written although an ImageMeta write failed")
		}
	})
}
