package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	"zotregistry.dev/zot/v2/pkg/log"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

var errWriteInjected = errors.New("injected write failure")

const (
	writeRepo        = "write/repo"
	writeCallTimeout = 10 * time.Second
	invalidUTF8      = "\xff"
)

// failingHook fails every command of the given name on the given key (and field, if set), and optionally
// every pipeline.
type failingHook struct {
	command      string
	key          string
	field        string
	failPipeline bool
}

func (h *failingHook) DialHook(next goredis.DialHook) goredis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *failingHook) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		args := cmd.Args()

		if cmd.Name() == h.command && len(args) > 1 && args[1] == h.key &&
			(h.field == "" || (len(args) > 2 && args[2] == h.field)) {
			return fmt.Errorf("%w on %s", errWriteInjected, h.key)
		}

		return next(ctx, cmd)
	}
}

func (h *failingHook) ProcessPipelineHook(next goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []goredis.Cmder) error {
		if h.failPipeline {
			return fmt.Errorf("%w on pipeline", errWriteInjected)
		}

		return next(ctx, cmds)
	}
}

func newWriteTestDB(t *testing.T, hook goredis.Hook) (*RedisDB, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)

	opts, err := goredis.ParseURL("redis://" + server.Addr())
	if err != nil {
		t.Fatalf("failed to parse redis url: %v", err)
	}

	client := goredis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })

	if hook != nil {
		client.AddHook(hook)
	}

	wrapper, err := New(client, DBDriverParameters{KeyPrefix: "zot"}, log.NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create redis wrapper: %v", err)
	}

	return wrapper, server
}

func writeRefs(count int) []mTypes.RepoReference {
	refs := make([]mTypes.RepoReference, 0, count)

	for i := range count {
		refs = append(refs, mTypes.RepoReference{
			Reference: fmt.Sprintf("tag%d", i),
			ImageMeta: CreateRandomImage().AsImageMeta(),
		})
	}

	return refs
}

// setRepoReferencesWithin fails the test when the call does not return in time.
func setRepoReferencesWithin(t *testing.T, ctx context.Context, wrapper *RedisDB, repo string,
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

func assertNoRepoState(t *testing.T, wrapper *RedisDB, server *miniredis.Miniredis) {
	t.Helper()

	for _, key := range []string{wrapper.RepoMetaKey, wrapper.RepoBlobsKey, wrapper.RepoLastUpdatedKey} {
		if fields, _ := server.HKeys(key); len(fields) != 0 {
			t.Errorf("%s was written: %v", key, fields)
		}
	}
}

func assertStoredImageMetas(t *testing.T, wrapper *RedisDB, server *miniredis.Miniredis,
	refs []mTypes.RepoReference, want bool,
) {
	t.Helper()

	for _, ref := range refs {
		if stored := hashHasField(server, wrapper.ImageMetaKey, ref.ImageMeta.Digest.String()); stored != want {
			t.Errorf("ImageMeta of %s stored = %t, want %t", ref.ImageMeta.Digest, stored, want)
		}
	}
}

func hashHasField(server *miniredis.Miniredis, key, field string) bool {
	fields, _ := server.HKeys(key)

	for _, existing := range fields {
		if existing == field {
			return true
		}
	}

	return false
}

func TestSetRepoReferencesWithoutSlotChannel(t *testing.T) {
	wrapper, server := newWriteTestDB(t, nil)
	wrapper.imageMetaWriteSlots = nil
	refs := writeRefs(3)

	if err := setRepoReferencesWithin(t, context.Background(), wrapper, writeRepo, refs); err != nil {
		t.Fatalf("SetRepoReferences: %v", err)
	}

	assertStoredImageMetas(t, wrapper, server, refs, true)

	if !hashHasField(server, wrapper.RepoMetaKey, writeRepo) {
		t.Errorf("RepoMeta of %s was not written", writeRepo)
	}
}

func TestSetRepoReferencesCancelledWhileWaitingForSlot(t *testing.T) {
	wrapper, server := newWriteTestDB(t, nil)

	// every slot is taken, so that the cancelled context is the only way forward
	wrapper.imageMetaWriteSlots = make(chan struct{}, 2)
	for range cap(wrapper.imageMetaWriteSlots) {
		wrapper.imageMetaWriteSlots <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	refs := writeRefs(3)

	err := setRepoReferencesWithin(t, ctx, wrapper, writeRepo, refs)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	assertStoredImageMetas(t, wrapper, server, refs, false)
	assertNoRepoState(t, wrapper, server)
}

func TestSetRepoReferencesStopsStartingWritesAfterError(t *testing.T) {
	refs := writeRefs(6)

	hook := &failingHook{command: "hset", key: "zot:ImageMeta", field: refs[0].ImageMeta.Digest.String()}
	wrapper, server := newWriteTestDB(t, hook)

	// one slot: a write only starts once the previous one has finished
	wrapper.imageMetaWriteSlots = make(chan struct{}, 1)

	err := setRepoReferencesWithin(t, context.Background(), wrapper, writeRepo, refs)
	if !errors.Is(err, errWriteInjected) {
		t.Fatalf("expected the injected ImageMeta error, got: %v", err)
	}

	// the write right behind the failing one may already have been started, the rest must not be
	assertStoredImageMetas(t, wrapper, server, refs[:1], false)
	assertStoredImageMetas(t, wrapper, server, refs[2:], false)
	assertNoRepoState(t, wrapper, server)
}

func TestSetRepoReferencesRepoBlobsReadError(t *testing.T) {
	hook := &failingHook{command: "hget", key: "zot:RepoBlobsMeta"}
	wrapper, server := newWriteTestDB(t, hook)

	err := setRepoReferencesWithin(t, context.Background(), wrapper, writeRepo, writeRefs(2))
	if !errors.Is(err, errWriteInjected) || !strings.Contains(err.Error(), "failed to get repo blobs record") {
		t.Fatalf("expected the repo blobs read error, got: %v", err)
	}

	assertNoRepoState(t, wrapper, server)
}

func TestSetRepoReferencesTransactionError(t *testing.T) {
	hook := &failingHook{}
	wrapper, server := newWriteTestDB(t, hook)

	// armed after the connection set-up, which runs through the pipeline hook as well
	hook.failPipeline = true

	err := setRepoReferencesWithin(t, context.Background(), wrapper, writeRepo, writeRefs(2))
	if !errors.Is(err, errWriteInjected) {
		t.Fatalf("expected the injected transaction error, got: %v", err)
	}

	assertNoRepoState(t, wrapper, server)
}

func TestSetRepoReferencesMarshalErrors(t *testing.T) {
	t.Run("ImageMeta that cannot be marshaled writes nothing", func(t *testing.T) {
		wrapper, server := newWriteTestDB(t, nil)
		refs := writeRefs(2)
		refs[1].ImageMeta.Manifests[0].Manifest.Annotations = map[string]string{"key": invalidUTF8}

		err := setRepoReferencesWithin(t, context.Background(), wrapper, writeRepo, refs)
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("expected a marshal error, got: %v", err)
		}

		assertStoredImageMetas(t, wrapper, server, refs, false)
		assertNoRepoState(t, wrapper, server)
	})

	t.Run("RepoBlobs that cannot be marshaled writes no repo state", func(t *testing.T) {
		wrapper, server := newWriteTestDB(t, nil)
		repo := writeRepo + invalidUTF8

		// a stored RepoMeta keeps its own valid name, so that only the RepoBlobs carry the invalid repo name
		storedMeta, err := proto.Marshal(&proto_go.RepoMeta{Name: writeRepo})
		if err != nil {
			t.Fatalf("failed to marshal RepoMeta: %v", err)
		}

		server.HSet(wrapper.RepoMetaKey, repo, string(storedMeta))

		err = setRepoReferencesWithin(t, context.Background(), wrapper, repo, writeRefs(2))
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("expected a marshal error, got: %v", err)
		}

		if stored := server.HGet(wrapper.RepoMetaKey, repo); stored != string(storedMeta) {
			t.Errorf("RepoMeta was overwritten: %q", stored)
		}

		for _, key := range []string{wrapper.RepoBlobsKey, wrapper.RepoLastUpdatedKey} {
			if fields, _ := server.HKeys(key); len(fields) != 0 {
				t.Errorf("%s was written: %v", key, fields)
			}
		}
	})

	t.Run("RepoMeta that cannot be marshaled writes no repo state", func(t *testing.T) {
		wrapper, server := newWriteTestDB(t, nil)
		refs := writeRefs(2)
		refs[1].Reference = "tag" + invalidUTF8

		err := setRepoReferencesWithin(t, context.Background(), wrapper, writeRepo, refs)
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("expected a marshal error, got: %v", err)
		}

		assertNoRepoState(t, wrapper, server)
	})
}
