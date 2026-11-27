package dynamodb

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go/middleware"

	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

const writeCallTimeout = 30 * time.Second

// tableFailure fails the requests of the armed table operation, so that the set-up and the assertions of a
// test run unharmed.
type tableFailure struct {
	armed   atomic.Bool
	matches func(parameters any) bool
}

func (f *tableFailure) addMiddleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("failTableOperation", func(
		ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
	) (middleware.InitializeOutput, middleware.Metadata, error) {
		if f.armed.Load() && f.matches(in.Parameters) {
			return middleware.InitializeOutput{}, middleware.Metadata{}, errInjected
		}

		return next.HandleInitialize(ctx, in)
	}), middleware.Before)
}

func getsFrom(table string) func(parameters any) bool {
	return func(parameters any) bool {
		input, ok := parameters.(*dynamodb.GetItemInput)

		return ok && aws.ToString(input.TableName) == table
	}
}

func updatesIn(table string) func(parameters any) bool {
	return func(parameters any) bool {
		input, ok := parameters.(*dynamodb.UpdateItemInput)

		return ok && aws.ToString(input.TableName) == table
	}
}

func newDynamoDBWithFailure(t *testing.T, params DBDriverParameters, failure *tableFailure) *DynamoDB {
	t.Helper()

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(params.Region))
	if err != nil {
		t.Fatalf("failed to load aws config: %v", err)
	}

	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(params.Endpoint)
		o.APIOptions = append(o.APIOptions, failure.addMiddleware)
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

// setRepoReferencesWithin fails the test when the call does not return in time.
func setRepoReferencesWithin(ctx context.Context, t *testing.T, wrapper *DynamoDB, repo string,
	refs []mTypes.RepoReference,
) error {
	t.Helper()

	done := make(chan error, 1)

	go func() { done <- wrapper.SetRepoReferences(ctx, repo, refs) }()

	select {
	case err := <-done:
		return err
	case <-time.After(writeCallTimeout):
		t.Fatalf("SetRepoReferences did not return within %s", writeCallTimeout)

		return nil
	}
}

func assertRepoStateStored(t *testing.T, wrapper *DynamoDB, want bool) {
	t.Helper()

	if stored := itemExists(t, wrapper, wrapper.RepoMetaTablename, batchRepo); stored != want {
		t.Errorf("RepoMeta stored = %t, want %t", stored, want)
	}

	if stored := itemExists(t, wrapper, wrapper.RepoBlobsTablename, batchRepo); stored != want {
		t.Errorf("RepoBlobs stored = %t, want %t", stored, want)
	}
}

func assertImageMetasStored(t *testing.T, wrapper *DynamoDB, refs []mTypes.RepoReference, want bool) {
	t.Helper()

	for _, ref := range refs {
		if stored := itemExists(t, wrapper, wrapper.ImageMetaTablename, ref.ImageMeta.Digest.String()); stored != want {
			t.Errorf("ImageMeta of %s stored = %t, want %t", ref.ImageMeta.Digest, stored, want)
		}
	}
}

func TestSetRepoReferencesWithoutSlotChannel(t *testing.T) {
	tskip.SkipDynamo(t)

	wrapper := newBatchDynamoDB(t, newDynamoParams(), nil)
	wrapper.imageMetaWriteSlots = nil
	refs := distinctRefs(3, time.Now())

	if err := setRepoReferencesWithin(context.Background(), t, wrapper, batchRepo, refs); err != nil {
		t.Fatalf("SetRepoReferences: %v", err)
	}

	assertImageMetasStored(t, wrapper, refs, true)
	assertRepoStateStored(t, wrapper, true)
}

func TestSetRepoReferencesCancelledWhileWaitingForSlot(t *testing.T) {
	tskip.SkipDynamo(t)

	wrapper := newBatchDynamoDB(t, newDynamoParams(), nil)

	// every slot is taken, so that the cancelled context is the only way forward
	wrapper.imageMetaWriteSlots = make(chan struct{}, 2)
	for range cap(wrapper.imageMetaWriteSlots) {
		wrapper.imageMetaWriteSlots <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	refs := distinctRefs(3, time.Now())

	// the error of the slot wait itself: the calls after it fail on the cancelled context as well, with a wrapped error
	err := setRepoReferencesWithin(ctx, t, wrapper, batchRepo, refs)
	if !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	assertImageMetasStored(t, wrapper, refs, false)
	assertRepoStateStored(t, wrapper, false)
}

func TestSetRepoReferencesStopsStartingWritesAfterError(t *testing.T) {
	tskip.SkipDynamo(t)

	params := newDynamoParams()
	gate := newImageMetaGate(params.ImageMetaTablename)
	wrapper := newBatchDynamoDB(t, params, gate)

	// one slot: a write only starts once the previous one has finished
	wrapper.imageMetaWriteSlots = make(chan struct{}, 1)

	refs := distinctRefs(6, time.Now())
	gate.failDigest = refs[0].ImageMeta.Digest.String()

	err := setRepoReferencesWithin(context.Background(), t, wrapper, batchRepo, refs)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected the injected ImageMeta error, got: %v", err)
	}

	// the write right behind the failing one may already have been started, the rest must not be
	assertImageMetasStored(t, wrapper, refs[:1], false)
	assertImageMetasStored(t, wrapper, refs[2:], false)
	assertRepoStateStored(t, wrapper, false)
}

func TestSetRepoReferencesRepoStateErrors(t *testing.T) {
	tskip.SkipDynamo(t)

	cases := []struct {
		name      string
		operation func(table string) func(parameters any) bool
		want      string
	}{
		{"reading the RepoBlobs fails", getsFrom, "RepoBlobs read"},
		{"storing the RepoBlobs fails", updatesIn, "RepoBlobs write"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			params := newDynamoParams()
			failure := &tableFailure{matches: testCase.operation(params.RepoBlobsInfoTablename)}
			wrapper := newDynamoDBWithFailure(t, params, failure)
			refs := distinctRefs(2, time.Now())

			failure.armed.Store(true)

			err := setRepoReferencesWithin(context.Background(), t, wrapper, batchRepo, refs)

			failure.armed.Store(false)

			if !errors.Is(err, errInjected) {
				t.Fatalf("expected the injected %s error, got: %v", testCase.want, err)
			}

			assertRepoStateStored(t, wrapper, false)
		})
	}
}
