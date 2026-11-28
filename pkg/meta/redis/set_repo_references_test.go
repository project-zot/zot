package redis_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	"zotregistry.dev/zot/v2/pkg/meta/redis"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
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

type holdingHook struct {
	imageMetaKey string
	lockPrefix   string
	failDigest   string

	arrived   atomic.Int32
	inFlight  atomic.Int32
	maxFlight atomic.Int32

	release     chan struct{}
	releaseOnce sync.Once

	lockMutex sync.Mutex
	lockSets  map[string]int
}

func newHoldingHook(imageMetaKey, locksKey string) *holdingHook {
	return &holdingHook{
		imageMetaKey: imageMetaKey,
		lockPrefix:   locksKey + ":Image:",
		release:      make(chan struct{}),
		lockSets:     map[string]int{},
	}
}

func (h *holdingHook) DialHook(next goredis.DialHook) goredis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *holdingHook) ProcessPipelineHook(next goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return next
}

func (h *holdingHook) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		args := cmd.Args()

		if cmd.Name() == "set" && len(args) > 1 {
			if key, ok := args[1].(string); ok && strings.HasPrefix(key, h.lockPrefix) {
				h.lockMutex.Lock()
				h.lockSets[strings.TrimPrefix(key, h.lockPrefix)]++
				h.lockMutex.Unlock()
			}
		}

		if cmd.Name() != "hset" || len(args) < 3 || args[1] != h.imageMetaKey {
			return next(ctx, cmd)
		}

		if h.failDigest != "" && args[2] == h.failDigest {
			return fmt.Errorf("%w for %s", errInjected, h.failDigest)
		}

		current := h.inFlight.Add(1)

		for {
			maxSeen := h.maxFlight.Load()
			if current <= maxSeen || h.maxFlight.CompareAndSwap(maxSeen, current) {
				break
			}
		}

		if h.arrived.Add(1) >= boundProbeBatch {
			h.releaseOnce.Do(func() { close(h.release) })
		}

		select {
		case <-h.release:
		case <-time.After(boundSettleDelay):
		}

		err := next(ctx, cmd)
		h.inFlight.Add(-1)

		return err
	}
}

func newRedisWrapper(t *testing.T) *redis.RedisDB {
	t.Helper()

	return newRedisWrapperOn(t, miniredis.RunT(t), nil)
}

func newRedisWrapperOn(t *testing.T, server *miniredis.Miniredis, hook goredis.Hook) *redis.RedisDB {
	t.Helper()

	opts, err := goredis.ParseURL("redis://" + server.Addr())
	if err != nil {
		t.Fatalf("failed to parse redis url: %v", err)
	}

	client := goredis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })

	if hook != nil {
		client.AddHook(hook)
	}

	wrapper, err := redis.New(client, redis.DBDriverParameters{KeyPrefix: "zot"}, log.NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create redis wrapper: %v", err)
	}

	return wrapper
}

// batchFixture returns references covering tags, a second tag and a re-pointed tag of one digest, an index tagged
// after its children, a child added by digest after its index and a referrer with a subject.
func batchFixture(pushTime time.Time) []mTypes.RepoReference {
	pushOpts := []mTypes.SetRepoReferenceOption{mTypes.WithPushTimestamp(pushTime)}

	imgA, imgB, imgC := CreateRandomImage(), CreateRandomImage(), CreateRandomImage()
	child1, child2, child3 := CreateRandomImage(), CreateRandomImage(), CreateRandomImage()
	index := CreateMultiarchWith().Images([]Image{child1, child2, child3}).Build()
	referrer := CreateRandomImageWith().Subject(imgA.DescriptorRef()).Build()

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
			ImageMeta: CreateRandomImage().AsImageMeta(),
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
func rawRepoState(t *testing.T, wrapper *redis.RedisDB, repo string) (*proto_go.RepoMeta, *proto_go.RepoBlobs) {
	t.Helper()

	ctx := context.Background()
	repoMeta := &proto_go.RepoMeta{}
	repoBlobs := &proto_go.RepoBlobs{}

	metaBlob, err := wrapper.Client.HGet(ctx, wrapper.RepoMetaKey, repo).Bytes()
	if err != nil {
		t.Fatalf("failed to read raw RepoMeta: %v", err)
	}

	blobsBlob, err := wrapper.Client.HGet(ctx, wrapper.RepoBlobsKey, repo).Bytes()
	if err != nil {
		t.Fatalf("failed to read raw RepoBlobs: %v", err)
	}

	if err := proto.Unmarshal(metaBlob, repoMeta); err != nil {
		t.Fatalf("failed to unmarshal RepoMeta: %v", err)
	}

	if err := proto.Unmarshal(blobsBlob, repoBlobs); err != nil {
		t.Fatalf("failed to unmarshal RepoBlobs: %v", err)
	}

	slices.Sort(repoMeta.Vendors)
	sortPlatforms(repoMeta.Platforms)

	for _, blob := range repoBlobs.Blobs {
		slices.Sort(blob.Vendors)
		sortPlatforms(blob.Platforms)
	}

	return repoMeta, repoBlobs
}

func cloneRedisState(t *testing.T, source *redis.RedisDB) *redis.RedisDB {
	t.Helper()

	ctx := context.Background()
	server := miniredis.RunT(t)

	for _, key := range []string{
		source.ImageMetaKey, source.RepoMetaKey, source.RepoBlobsKey, source.RepoLastUpdatedKey,
	} {
		entries, err := source.Client.HGetAll(ctx, key).Result()
		if err != nil {
			t.Fatalf("failed to read %s: %v", key, err)
		}

		for field, value := range entries {
			server.HSet(key, field, value)
		}
	}

	return newRedisWrapperOn(t, server, nil)
}

func assertSameState(t *testing.T, batch, sequential *redis.RedisDB, refs []mTypes.RepoReference) {
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
	ctx := context.Background()
	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("empty start state", func(t *testing.T) {
		refs := batchFixture(pushTime)
		batch := newRedisWrapper(t)
		sequential := newRedisWrapper(t)

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
		seed := newRedisWrapper(t)

		for _, ref := range refs[:5] {
			if err := seed.SetRepoReference(ctx, batchRepo, ref.Reference, ref.ImageMeta, ref.Opts...); err != nil {
				t.Fatalf("seed SetRepoReference: %v", err)
			}
		}

		if err := seed.UpdateStatsOnDownload(batchRepo, "t1"); err != nil {
			t.Fatalf("UpdateStatsOnDownload: %v", err)
		}

		extra := CreateRandomImage().AsImageMeta()
		if err := seed.SetRepoReference(ctx, batchRepo, "extra", extra); err != nil {
			t.Fatalf("seed SetRepoReference without push timestamp: %v", err)
		}

		batch := cloneRedisState(t, seed)
		sequential := cloneRedisState(t, seed)

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
	ctx := context.Background()
	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("repo last updated is written", func(t *testing.T) {
		wrapper := newRedisWrapper(t)
		before := time.Now()

		if err := wrapper.SetRepoReferences(ctx, batchRepo, batchFixture(pushTime)[:2]); err != nil {
			t.Fatalf("SetRepoReferences: %v", err)
		}

		if lastUpdated := wrapper.GetRepoLastUpdated(batchRepo); lastUpdated.Before(before) {
			t.Errorf("RepoLastUpdated %v is before the call at %v", lastUpdated, before)
		}
	})

	t.Run("nil references write nothing", func(t *testing.T) {
		wrapper := newRedisWrapper(t)

		if err := wrapper.SetRepoReferences(ctx, batchRepo, nil); err != nil {
			t.Fatalf("SetRepoReferences(nil): %v", err)
		}

		if _, err := wrapper.GetRepoMeta(ctx, batchRepo); !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			t.Errorf("expected ErrRepoMetaNotFound after empty batch, got: %v", err)
		}

		if lastUpdated := wrapper.GetRepoLastUpdated(batchRepo); !lastUpdated.IsZero() {
			t.Errorf("expected no RepoLastUpdated after empty batch, got %v", lastUpdated)
		}
	})

	t.Run("invalid last reference writes nothing", func(t *testing.T) {
		wrapper := newRedisWrapper(t)
		refs := batchFixture(pushTime)[:2]
		refs[1].Reference = ""

		if err := wrapper.SetRepoReferences(ctx, batchRepo, refs); !errors.Is(err, zerr.ErrEmptyTag) {
			t.Fatalf("expected ErrEmptyTag, got: %v", err)
		}

		if _, err := wrapper.GetImageMeta(refs[0].ImageMeta.Digest); !errors.Is(err, zerr.ErrImageMetaNotFound) {
			t.Errorf("ImageMeta of the first reference was written, got: %v", err)
		}

		if _, err := wrapper.GetRepoMeta(ctx, batchRepo); !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			t.Errorf("RepoMeta was written, got: %v", err)
		}
	})
}

func TestSetRepoReferencesWritesImageMetaConcurrently(t *testing.T) {
	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	for name, repoCount := range map[string]int{"one call": 1, "two concurrent calls": 2} {
		t.Run(name, func(t *testing.T) {
			server := miniredis.RunT(t)

			probe := newRedisWrapperOn(t, server, nil)
			hook := newHoldingHook(probe.ImageMetaKey, probe.LocksKey)
			wrapper := newRedisWrapperOn(t, server, hook)

			refsByRepo := map[string][]mTypes.RepoReference{}
			for i := range repoCount {
				refsByRepo[fmt.Sprintf("batch/repo%d", i)] = distinctRefs(boundRefsPerRepo, pushTime)
			}

			var waitGroup sync.WaitGroup

			for repo, refs := range refsByRepo {
				waitGroup.Go(func() {
					if err := wrapper.SetRepoReferences(context.Background(), repo, refs); err != nil {
						t.Errorf("SetRepoReferences(%s): %v", repo, err)
					}
				})
			}

			waitGroup.Wait()

			if maxFlight := hook.maxFlight.Load(); maxFlight <= 1 || maxFlight > boundMaxInFlight {
				t.Errorf("max concurrent ImageMeta writes is %d, want > 1 and <= %d", maxFlight, boundMaxInFlight)
			}

			for repo, refs := range refsByRepo {
				for _, ref := range refs {
					if acquired := hook.lockSets[ref.ImageMeta.Digest.String()]; acquired != 1 {
						t.Errorf("image lock of %s (%s) acquired %d times, want 1", ref.ImageMeta.Digest, repo, acquired)
					}
				}
			}
		})
	}
}

func TestSetRepoReferencesImageMetaErrorWritesNoRepoMeta(t *testing.T) {
	ctx := context.Background()
	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	server := miniredis.RunT(t)

	probe := newRedisWrapperOn(t, server, nil)
	hook := newHoldingHook(probe.ImageMetaKey, probe.LocksKey)
	wrapper := newRedisWrapperOn(t, server, hook)

	refs := distinctRefs(failingRefCount, pushTime)
	hook.failDigest = refs[failingRefIndex].ImageMeta.Digest.String()

	err := wrapper.SetRepoReferences(ctx, batchRepo, refs)
	if !errors.Is(err, errInjected) || !strings.Contains(err.Error(), hook.failDigest) {
		t.Fatalf("expected the injected ImageMeta error, got: %v", err)
	}

	if _, err := wrapper.GetRepoMeta(ctx, batchRepo); !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		t.Errorf("RepoMeta was written although an ImageMeta write failed, got: %v", err)
	}

	if blobs, _ := server.HKeys(probe.RepoBlobsKey); len(blobs) != 0 {
		t.Errorf("RepoBlobs was written although an ImageMeta write failed: %v", blobs)
	}
}
