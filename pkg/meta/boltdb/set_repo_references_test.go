package boltdb_test

import (
	"bytes"
	"context"
	"errors"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

const batchRepo = "batch/repo"

func newBoltWrapper(t *testing.T, rootDir string) *boltdb.BoltDB {
	t.Helper()

	driver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: rootDir})
	if err != nil {
		t.Fatalf("failed to open bolt driver: %v", err)
	}

	t.Cleanup(func() { _ = driver.Close() })

	wrapper, err := boltdb.New(driver, log.NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create bolt wrapper: %v", err)
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

func platformKey(platform *proto_go.Platform) string {
	return platform.GetOS() + "/" + platform.GetArchitecture() + "/" + platform.GetVariant()
}

func sortPlatforms(platforms []*proto_go.Platform) {
	slices.SortFunc(platforms, func(a, b *proto_go.Platform) int {
		return strings.Compare(platformKey(a), platformKey(b))
	})
}

// rawRepoState reads RepoMeta and RepoBlobs of the repo as stored, with the lists built from map iteration sorted.
func rawRepoState(t *testing.T, wrapper *boltdb.BoltDB, repo string) (*proto_go.RepoMeta, *proto_go.RepoBlobs) {
	t.Helper()

	repoMeta := &proto_go.RepoMeta{}
	repoBlobs := &proto_go.RepoBlobs{}

	err := wrapper.DB.View(func(tx *bbolt.Tx) error {
		if err := proto.Unmarshal(tx.Bucket([]byte(boltdb.RepoMetaBuck)).Get([]byte(repo)), repoMeta); err != nil {
			return err
		}

		return proto.Unmarshal(tx.Bucket([]byte(boltdb.RepoBlobsBuck)).Get([]byte(repo)), repoBlobs)
	})
	if err != nil {
		t.Fatalf("failed to read raw repo state: %v", err)
	}

	slices.Sort(repoMeta.Vendors)
	sortPlatforms(repoMeta.Platforms)

	for _, blob := range repoBlobs.Blobs {
		slices.Sort(blob.Vendors)
		sortPlatforms(blob.Platforms)
	}

	return repoMeta, repoBlobs
}

func cloneBoltState(t *testing.T, source *boltdb.BoltDB) *boltdb.BoltDB {
	t.Helper()

	targetDir := t.TempDir()

	err := source.DB.View(func(tx *bbolt.Tx) error {
		return tx.CopyFile(path.Join(targetDir, "meta.db"), 0o600)
	})
	if err != nil {
		t.Fatalf("failed to clone bolt state: %v", err)
	}

	return newBoltWrapper(t, targetDir)
}

func assertSameState(t *testing.T, batch, sequential *boltdb.BoltDB, refs []mTypes.RepoReference) {
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
		batch := newBoltWrapper(t, t.TempDir())
		sequential := newBoltWrapper(t, t.TempDir())

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
		seed := newBoltWrapper(t, t.TempDir())

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

		batch := cloneBoltState(t, seed)
		sequential := cloneBoltState(t, seed)

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
		wrapper := newBoltWrapper(t, t.TempDir())
		before := time.Now()

		if err := wrapper.SetRepoReferences(ctx, batchRepo, batchFixture(pushTime)[:2]); err != nil {
			t.Fatalf("SetRepoReferences: %v", err)
		}

		if lastUpdated := wrapper.GetRepoLastUpdated(batchRepo); lastUpdated.Before(before) {
			t.Errorf("RepoLastUpdated %v is before the call at %v", lastUpdated, before)
		}
	})

	t.Run("nil references write nothing", func(t *testing.T) {
		wrapper := newBoltWrapper(t, t.TempDir())

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
		wrapper := newBoltWrapper(t, t.TempDir())
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

type rawValues struct {
	repoMeta   []byte
	repoBlobs  []byte
	imageCount int
}

func readRawValues(t *testing.T, wrapper *boltdb.BoltDB, repo string) rawValues {
	t.Helper()

	var values rawValues

	err := wrapper.DB.View(func(transaction *bbolt.Tx) error {
		values.repoMeta = bytes.Clone(transaction.Bucket([]byte(boltdb.RepoMetaBuck)).Get([]byte(repo)))
		values.repoBlobs = bytes.Clone(transaction.Bucket([]byte(boltdb.RepoBlobsBuck)).Get([]byte(repo)))
		values.imageCount = transaction.Bucket([]byte(boltdb.ImageMetaBuck)).Stats().KeyN

		return nil
	})
	if err != nil {
		t.Fatalf("failed to read raw values: %v", err)
	}

	return values
}

func TestSetRepoReferencesStorageErrorsRollBack(t *testing.T) {
	const (
		oversizedKeyLength = 40000
		invalidUTF8        = "\xff"
		corruptBlob        = "\x0f"
	)

	pushTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		repo    string
		seed    func(transaction *bbolt.Tx, repo string) error
		change  func(refs []mTypes.RepoReference)
		wantErr func(err error) bool
	}{
		{
			name: "ImageMeta key is too large",
			repo: batchRepo,
			change: func(refs []mTypes.RepoReference) {
				refs[0].ImageMeta.Digest = godigest.Digest(strings.Repeat("a", oversizedKeyLength))
			},
			wantErr: func(err error) bool { return errors.Is(err, bbolt.ErrKeyTooLarge) },
		},
		{
			name: "ImageMeta cannot be marshaled",
			repo: batchRepo,
			change: func(refs []mTypes.RepoReference) {
				refs[0].ImageMeta.Manifests[0].Manifest.Annotations = map[string]string{"key": invalidUTF8}
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "invalid UTF-8") },
		},
		{
			name: "stored RepoMeta is corrupt",
			repo: batchRepo,
			seed: func(transaction *bbolt.Tx, repo string) error {
				return transaction.Bucket([]byte(boltdb.RepoMetaBuck)).Put([]byte(repo), []byte(corruptBlob))
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "wire-format") },
		},
		{
			name: "stored RepoBlobs is corrupt",
			repo: batchRepo,
			seed: func(transaction *bbolt.Tx, repo string) error {
				return transaction.Bucket([]byte(boltdb.RepoBlobsBuck)).Put([]byte(repo), []byte(corruptBlob))
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "wire-format") },
		},
		{
			name: "repo key collides with a bucket inside RepoLastUpdated",
			repo: batchRepo,
			seed: func(transaction *bbolt.Tx, repo string) error {
				lastUpdated := transaction.Bucket([]byte(boltdb.RepoBlobsBuck)).Bucket([]byte(boltdb.RepoLastUpdatedBuck))

				_, err := lastUpdated.CreateBucket([]byte(repo))

				return err
			},
			wantErr: func(err error) bool { return errors.Is(err, bbolt.ErrIncompatibleValue) },
		},
		{
			name:    "repo key collides with the RepoLastUpdated bucket",
			repo:    boltdb.RepoLastUpdatedBuck,
			wantErr: func(err error) bool { return errors.Is(err, bbolt.ErrIncompatibleValue) },
		},
		{
			// a stored RepoMeta keeps its own valid name, so that only the RepoBlobs carry the invalid repo name
			name: "RepoBlobs cannot be marshaled",
			repo: batchRepo + invalidUTF8,
			seed: func(transaction *bbolt.Tx, repo string) error {
				storedMeta, err := proto.Marshal(&proto_go.RepoMeta{Name: batchRepo})
				if err != nil {
					return err
				}

				return transaction.Bucket([]byte(boltdb.RepoMetaBuck)).Put([]byte(repo), storedMeta)
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "invalid UTF-8") },
		},
		{
			name: "RepoMeta cannot be marshaled",
			repo: batchRepo,
			change: func(refs []mTypes.RepoReference) {
				refs[1].Reference = "tag" + invalidUTF8
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "invalid UTF-8") },
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper := newBoltWrapper(t, t.TempDir())
			refs := batchFixture(pushTime)[:2]

			if testCase.change != nil {
				testCase.change(refs)
			}

			if testCase.seed != nil {
				err := wrapper.DB.Update(func(transaction *bbolt.Tx) error {
					return testCase.seed(transaction, testCase.repo)
				})
				if err != nil {
					t.Fatalf("failed to seed: %v", err)
				}
			}

			before := readRawValues(t, wrapper, testCase.repo)

			if err := wrapper.SetRepoReferences(context.Background(), testCase.repo, refs); !testCase.wantErr(err) {
				t.Fatalf("unexpected error: %v", err)
			}

			after := readRawValues(t, wrapper, testCase.repo)

			if after.imageCount != 0 {
				t.Errorf("%d ImageMeta records survived the failed transaction", after.imageCount)
			}

			if !bytes.Equal(before.repoMeta, after.repoMeta) || !bytes.Equal(before.repoBlobs, after.repoBlobs) {
				t.Errorf("the repo state changed although the transaction failed")
			}
		})
	}
}

func TestSetRepoReferenceStorageErrorsRollBack(t *testing.T) {
	cases := []struct {
		name string
		repo string
		seed func(transaction *bbolt.Tx, repo string) error
	}{
		{
			name: "repo key collides with a bucket inside RepoLastUpdated",
			repo: batchRepo,
			seed: func(transaction *bbolt.Tx, repo string) error {
				lastUpdated := transaction.Bucket([]byte(boltdb.RepoBlobsBuck)).Bucket([]byte(boltdb.RepoLastUpdatedBuck))

				_, err := lastUpdated.CreateBucket([]byte(repo))

				return err
			},
		},
		{name: "repo key collides with the RepoLastUpdated bucket", repo: boltdb.RepoLastUpdatedBuck},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper := newBoltWrapper(t, t.TempDir())
			imageMeta := batchFixture(time.Now())[0].ImageMeta

			if testCase.seed != nil {
				err := wrapper.DB.Update(func(transaction *bbolt.Tx) error {
					return testCase.seed(transaction, testCase.repo)
				})
				if err != nil {
					t.Fatalf("failed to seed: %v", err)
				}
			}

			before := readRawValues(t, wrapper, testCase.repo)

			err := wrapper.SetRepoReference(context.Background(), testCase.repo, "tag", imageMeta)
			if !errors.Is(err, bbolt.ErrIncompatibleValue) {
				t.Fatalf("expected ErrIncompatibleValue, got: %v", err)
			}

			after := readRawValues(t, wrapper, testCase.repo)

			if after.imageCount != 0 {
				t.Errorf("%d ImageMeta records survived the failed transaction", after.imageCount)
			}

			if !bytes.Equal(before.repoMeta, after.repoMeta) || !bytes.Equal(before.repoBlobs, after.repoBlobs) {
				t.Errorf("the repo state changed although the transaction failed")
			}
		})
	}
}
