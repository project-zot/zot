package mocks_test

import (
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"

	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errMockRef = errors.New("mock reference error")

func TestMetaDBMockSetRepoReferences(t *testing.T) {
	refs := []mTypes.RepoReference{
		{Reference: "a", ImageMeta: mTypes.ImageMeta{Digest: godigest.FromString("a")}},
		{Reference: "b", ImageMeta: mTypes.ImageMeta{Digest: godigest.FromString("b")}},
		{Reference: "c", ImageMeta: mTypes.ImageMeta{Digest: godigest.FromString("c")}},
	}

	t.Run("falls back to SetRepoReferenceFn per reference in order", func(t *testing.T) {
		type call struct {
			repo      string
			reference string
			digest    godigest.Digest
		}

		var calls []call

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(_ context.Context, repo string, reference string, imageMeta mTypes.ImageMeta) error {
				calls = append(calls, call{repo, reference, imageMeta.Digest})

				return nil
			},
		}

		if err := metaDB.SetRepoReferences(context.Background(), "repo", refs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(calls) != len(refs) {
			t.Fatalf("SetRepoReferenceFn called %d times, want %d", len(calls), len(refs))
		}

		for i, ref := range refs {
			want := call{"repo", ref.Reference, ref.ImageMeta.Digest}
			if calls[i] != want {
				t.Fatalf("call %d = %+v, want %+v", i, calls[i], want)
			}
		}
	})

	t.Run("returns the first error and stops", func(t *testing.T) {
		calls := 0

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(_ context.Context, _ string, _ string, _ mTypes.ImageMeta) error {
				calls++

				if calls == 2 {
					return errMockRef
				}

				return nil
			},
		}

		err := metaDB.SetRepoReferences(context.Background(), "repo", refs)
		if !errors.Is(err, errMockRef) {
			t.Fatalf("error = %v, want %v", err, errMockRef)
		}

		if calls != 2 {
			t.Fatalf("SetRepoReferenceFn called %d times, want 2", calls)
		}
	})

	t.Run("uses SetRepoReferencesFn alone when set", func(t *testing.T) {
		batchCalls := 0
		singleCalls := 0

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(_ context.Context, _ string, _ string, _ mTypes.ImageMeta) error {
				singleCalls++

				return nil
			},
			SetRepoReferencesFn: func(_ context.Context, repo string, got []mTypes.RepoReference) error {
				batchCalls++

				if repo != "repo" || len(got) != len(refs) {
					t.Fatalf("SetRepoReferencesFn got repo %q and %d refs", repo, len(got))
				}

				return nil
			},
		}

		if err := metaDB.SetRepoReferences(context.Background(), "repo", refs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if batchCalls != 1 || singleCalls != 0 {
			t.Fatalf("SetRepoReferencesFn called %d times, SetRepoReferenceFn %d times, want 1 and 0",
				batchCalls, singleCalls)
		}
	})
}
