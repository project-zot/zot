package meta_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var (
	errDeleteAfterMetaHookTest        = errors.New("delete manifest after meta failure hook test")
	errDigestTagsSetRepoReferenceFail = errors.New("injected SetRepoReference failure for digest-tags rollback tests")
	errGetRepoMetaForDigestTags       = errors.New("get repo meta failed for digest tags test")
	errSetRepoRefForHookTest          = errors.New("set repo reference failed for hook test")
)

// setRepoRefFailMetaDB delegates to an inner MetaDB but fails SetRepoReference for one tag (used to
// exercise multi-tag digest rollback after a partial OnUpdateManifest success).
type setRepoRefFailMetaDB struct {
	mTypes.MetaDB

	failRef string
}

func (w *setRepoRefFailMetaDB) SetRepoReference(
	ctx context.Context, repo, ref string, imageMeta mTypes.ImageMeta, opts ...mTypes.SetRepoReferenceOption,
) error {
	if ref == w.failRef {
		return errDigestTagsSetRepoReferenceFail
	}

	return w.MetaDB.SetRepoReference(ctx, repo, ref, imageMeta, opts...)
}

// failDeleteImageStore delegates to an inner ImageStore but forces DeleteImageManifest to return deleteErr.
type failDeleteImageStore struct {
	stypes.ImageStore

	deleteErr error
}

func (f *failDeleteImageStore) DeleteImageManifest(ctx context.Context, repo, reference string,
	detectCollision bool,
) error {
	return f.deleteErr
}

func TestOnUpdateManifestDigestTags_emptyTags(t *testing.T) {
	Convey("OnUpdateManifestDigestTags with no tags is a no-op (nil MetaDB: no GetRepoMeta/SetRepoReference path)",
		t, func() {
			log := log.NewTestLogger()

			err := meta.OnUpdateManifestDigestTags(context.Background(), "repo", nil, ispec.MediaTypeImageManifest,
				godigest.Digest(""), nil, storage.StoreController{}, nil, log)
			So(err, ShouldBeNil)
		})
}

func TestOnUpdateManifestDigestTags_success(t *testing.T) {
	Convey("OnUpdateManifestDigestTags updates metadb for each digest query tag", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{RootDir: rootDir}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		image := CreateDefaultImage()
		mediaType := image.ManifestDescriptor.MediaType
		if mediaType == "" {
			mediaType = ispec.MediaTypeImageManifest
		}

		manifestBody := image.ManifestDescriptor.Data
		manifestDigest := image.Digest()

		err = WriteImageToFileSystem(image, "repo", "seed", storeController)
		So(err, ShouldBeNil)

		err = meta.OnUpdateManifest(context.Background(), "repo", "seed", mediaType, manifestDigest, manifestBody,
			storeController, metaDB, log)
		So(err, ShouldBeNil)

		imgStore := storeController.GetImageStore("repo")
		_, _, err = imgStore.PutImageManifest(context.Background(), "repo", manifestDigest.String(), mediaType, manifestBody,
			[]string{"ta", "tb"})
		So(err, ShouldBeNil)

		err = meta.OnUpdateManifestDigestTags(context.Background(), "repo", []string{"ta", "tb"}, mediaType,
			manifestDigest, manifestBody, storeController, metaDB, log)
		So(err, ShouldBeNil)

		wantDigest := manifestDigest.String()

		repoMeta, err := metaDB.GetRepoMeta(context.Background(), "repo")
		So(err, ShouldBeNil)
		So(repoMeta.Tags, ShouldContainKey, "ta")
		So(repoMeta.Tags, ShouldContainKey, "tb")
		So(repoMeta.Tags, ShouldContainKey, "seed")
		So(repoMeta.Tags["ta"].Digest, ShouldEqual, wantDigest)
		So(repoMeta.Tags["tb"].Digest, ShouldEqual, wantDigest)
		So(repoMeta.Tags["seed"].Digest, ShouldEqual, wantDigest)
	})
}

func TestOnUpdateManifestDigestTags_rollbackPartialMeta(t *testing.T) {
	Convey("OnUpdateManifestDigestTags rollback deletes all new index tags; meta rollback only for applied tags",
		t, func() {
			rootDir := t.TempDir()
			storeController := storage.StoreController{}
			log := log.NewTestLogger()
			metrics := monitoring.NewNopMetricServer()

			storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

			params := boltdb.DBParameters{RootDir: rootDir}
			boltDriver, err := boltdb.GetBoltDriver(params)
			So(err, ShouldBeNil)

			metaDB, err := boltdb.New(boltDriver, log)
			So(err, ShouldBeNil)

			image := CreateDefaultImage()
			mediaType := image.ManifestDescriptor.MediaType
			if mediaType == "" {
				mediaType = ispec.MediaTypeImageManifest
			}

			manifestBody := image.ManifestDescriptor.Data
			manifestDigest := image.Digest()

			err = WriteImageToFileSystem(image, "repo", "seed", storeController)
			So(err, ShouldBeNil)

			err = meta.OnUpdateManifest(context.Background(), "repo", "seed", mediaType, manifestDigest, manifestBody,
				storeController, metaDB, log)
			So(err, ShouldBeNil)

			imgStore := storeController.GetImageStore("repo")
			_, _, err = imgStore.PutImageManifest(context.Background(), "repo", manifestDigest.String(), mediaType, manifestBody,
				[]string{"ta", "tb"})
			So(err, ShouldBeNil)

			repoMetaBefore, err := metaDB.GetRepoMeta(context.Background(), "repo")
			So(err, ShouldBeNil)
			seedDigestBefore := repoMetaBefore.Tags["seed"].Digest
			So(seedDigestBefore, ShouldEqual, manifestDigest.String())

			wrapped := &setRepoRefFailMetaDB{MetaDB: metaDB, failRef: "tb"}

			err = meta.OnUpdateManifestDigestTags(context.Background(), "repo", []string{"ta", "tb"}, mediaType,
				manifestDigest, manifestBody, storeController, wrapped, log)
			So(err, ShouldEqual, errDigestTagsSetRepoReferenceFail)

			_, _, _, err = imgStore.GetImageManifest("repo", "ta")
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
			_, _, _, err = imgStore.GetImageManifest("repo", "tb")
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)

			seedBody, _, _, err := imgStore.GetImageManifest("repo", "seed")
			So(err, ShouldBeNil)
			So(godigest.FromBytes(seedBody).String(), ShouldEqual, manifestDigest.String())

			repoMeta, err := metaDB.GetRepoMeta(context.Background(), "repo")
			So(err, ShouldBeNil)
			So(repoMeta.Tags, ShouldNotContainKey, "ta")
			So(repoMeta.Tags, ShouldNotContainKey, "tb")
			So(repoMeta.Tags, ShouldContainKey, "seed")
			So(repoMeta.Tags["seed"].Digest, ShouldEqual, seedDigestBefore)
		})
}

func TestOnUpdateManifestDigestTags_rollbackRestoresMovedTag(t *testing.T) {
	Convey("rollback restores a tag moved from digest A to digest B back to digest A when MetaDB fails later",
		t, func() {
			rootDir := t.TempDir()
			storeController := storage.StoreController{}
			log := log.NewTestLogger()
			metrics := monitoring.NewNopMetricServer()

			storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

			params := boltdb.DBParameters{RootDir: rootDir}
			boltDriver, err := boltdb.GetBoltDriver(params)
			So(err, ShouldBeNil)

			metaDB, err := boltdb.New(boltDriver, log)
			So(err, ShouldBeNil)

			imageA := CreateDefaultImage()
			imageB := CreateRandomImage()
			So(imageA.Digest(), ShouldNotEqual, imageB.Digest())

			mediaTypeA := imageA.ManifestDescriptor.MediaType
			if mediaTypeA == "" {
				mediaTypeA = ispec.MediaTypeImageManifest
			}

			mediaTypeB := imageB.ManifestDescriptor.MediaType
			if mediaTypeB == "" {
				mediaTypeB = ispec.MediaTypeImageManifest
			}

			bodyA := imageA.ManifestDescriptor.Data
			digestA := imageA.Digest()
			bodyB := imageB.ManifestDescriptor.Data
			digestB := imageB.Digest()

			err = WriteImageToFileSystem(imageA, "repo", "movable", storeController)
			So(err, ShouldBeNil)

			err = meta.OnUpdateManifest(context.Background(), "repo", "movable", mediaTypeA, digestA, bodyA,
				storeController, metaDB, log)
			So(err, ShouldBeNil)

			err = WriteImageToFileSystem(imageB, "repo", "yardB", storeController)
			So(err, ShouldBeNil)

			err = meta.OnUpdateManifest(context.Background(), "repo", "yardB", mediaTypeB, digestB, bodyB,
				storeController, metaDB, log)
			So(err, ShouldBeNil)

			imgStore := storeController.GetImageStore("repo")

			_, _, err = imgStore.PutImageManifest(context.Background(), "repo", digestB.String(), mediaTypeB, bodyB,
				[]string{"movable", "onlyB"})
			So(err, ShouldBeNil)

			wrapped := &setRepoRefFailMetaDB{MetaDB: metaDB, failRef: "onlyB"}

			err = meta.OnUpdateManifestDigestTags(context.Background(), "repo", []string{"movable", "onlyB"}, mediaTypeB,
				digestB, bodyB, storeController, wrapped, log)
			So(err, ShouldEqual, errDigestTagsSetRepoReferenceFail)

			movableBody, movableD, _, err := imgStore.GetImageManifest("repo", "movable")
			So(err, ShouldBeNil)
			So(movableD.String(), ShouldEqual, digestA.String())
			So(godigest.FromBytes(movableBody).String(), ShouldEqual, digestA.String())

			_, _, _, err = imgStore.GetImageManifest("repo", "onlyB")
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)

			repoMeta, err := metaDB.GetRepoMeta(context.Background(), "repo")
			So(err, ShouldBeNil)
			So(repoMeta.Tags["movable"].Digest, ShouldEqual, digestA.String())
			So(repoMeta.Tags["yardB"].Digest, ShouldEqual, digestB.String())
			So(repoMeta.Tags, ShouldNotContainKey, "onlyB")
		})
}

func TestOnUpdateManifestDigestTags_getRepoMetaError(t *testing.T) {
	Convey("OnUpdateManifestDigestTags returns when GetRepoMeta fails with a non-ErrRepoMetaNotFound error", t, func() {
		log := log.NewTestLogger()
		metaDB := mocks.MetaDBMock{
			GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{}, errGetRepoMetaForDigestTags
			},
		}

		d := godigest.FromString("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

		err := meta.OnUpdateManifestDigestTags(context.Background(), "repo", []string{"a"}, ispec.MediaTypeImageManifest,
			d, []byte("{}"), storage.StoreController{}, metaDB, log)
		So(errors.Is(err, errGetRepoMetaForDigestTags), ShouldBeTrue)
	})
}

func TestOnUpdateManifestDigestTags_whenRepoMetaMissing(t *testing.T) {
	Convey("ErrRepoMetaNotFound during snapshot still allows digest query tag meta updates", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{RootDir: rootDir}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		image := CreateDefaultImage()
		mediaType := image.ManifestDescriptor.MediaType
		if mediaType == "" {
			mediaType = ispec.MediaTypeImageManifest
		}

		manifestBody := image.ManifestDescriptor.Data
		manifestDigest := image.Digest()

		err = WriteImageToFileSystem(image, "repo", "seed", storeController)
		So(err, ShouldBeNil)

		_, err = metaDB.GetRepoMeta(context.Background(), "repo")
		So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)

		imgStore := storeController.GetImageStore("repo")
		_, _, err = imgStore.PutImageManifest(context.Background(), "repo", manifestDigest.String(), mediaType, manifestBody,
			[]string{"ta", "tb"})
		So(err, ShouldBeNil)

		err = meta.OnUpdateManifestDigestTags(context.Background(), "repo", []string{"ta", "tb"}, mediaType,
			manifestDigest, manifestBody, storeController, metaDB, log)
		So(err, ShouldBeNil)

		wantDigest := manifestDigest.String()

		repoMeta, err := metaDB.GetRepoMeta(context.Background(), "repo")
		So(err, ShouldBeNil)
		So(repoMeta.Tags, ShouldContainKey, "ta")
		So(repoMeta.Tags, ShouldContainKey, "tb")
		So(repoMeta.Tags, ShouldNotContainKey, "seed")
		So(repoMeta.Tags["ta"].Digest, ShouldEqual, wantDigest)
		So(repoMeta.Tags["tb"].Digest, ShouldEqual, wantDigest)
	})
}

func TestOnUpdateManifest_setRepoReferenceFailsRemovesManifest(t *testing.T) {
	Convey("OnUpdateManifest deletes the manifest from the store when SetRepoReference fails", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(context.Context, string, string, mTypes.ImageMeta) error {
				return errSetRepoRefForHookTest
			},
		}

		image := CreateDefaultImage()
		mediaType := image.ManifestDescriptor.MediaType
		if mediaType == "" {
			mediaType = ispec.MediaTypeImageManifest
		}

		err := WriteImageToFileSystem(image, "repo", "tag1", storeController)
		So(err, ShouldBeNil)

		imgStore := storeController.GetImageStore("repo")

		err = meta.OnUpdateManifest(context.Background(), "repo", "tag1", mediaType, image.Digest(),
			image.ManifestDescriptor.Data, storeController, metaDB, log)
		So(errors.Is(err, errSetRepoRefForHookTest), ShouldBeTrue)

		_, _, _, err = imgStore.GetImageManifest("repo", "tag1")
		So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
	})
}

func TestOnUpdateManifest_whenDeleteAfterMetaFailureFails(t *testing.T) {
	Convey("OnUpdateManifest returns the delete error when meta fails and store cleanup fails", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		baseStore := local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)
		storeController.DefaultStore = &failDeleteImageStore{
			ImageStore: baseStore,
			deleteErr:  errDeleteAfterMetaHookTest,
		}

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(context.Context, string, string, mTypes.ImageMeta) error {
				return errSetRepoRefForHookTest
			},
		}

		image := CreateDefaultImage()
		mediaType := image.ManifestDescriptor.MediaType
		if mediaType == "" {
			mediaType = ispec.MediaTypeImageManifest
		}

		err := WriteImageToFileSystem(image, "repo", "tag1", storeController)
		So(err, ShouldBeNil)

		err = meta.OnUpdateManifest(context.Background(), "repo", "tag1", mediaType, image.Digest(),
			image.ManifestDescriptor.Data, storeController, metaDB, log)
		So(errors.Is(err, errDeleteAfterMetaHookTest), ShouldBeTrue)
	})
}

func TestOnUpdateManifest(t *testing.T) {
	Convey("On UpdateManifest", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{
			RootDir: rootDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		image := CreateDefaultImage()

		err = WriteImageToFileSystem(CreateDefaultImage(), "repo", "tag1", storeController)
		So(err, ShouldBeNil)

		err = meta.OnUpdateManifest(context.Background(), "repo", "tag1", ispec.MediaTypeImageManifest, image.Digest(),
			image.ManifestDescriptor.Data, storeController, metaDB, log)
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(context.Background(), "repo")
		So(err, ShouldBeNil)

		So(repoMeta.Tags, ShouldContainKey, "tag1")
	})
}

func TestUpdateErrors(t *testing.T) {
	Convey("Update operations", t, func() {
		imageStore := mocks.MockedImageStore{}
		storeController := storage.StoreController{DefaultStore: &imageStore}
		metaDB := mocks.MetaDBMock{}
		log := log.NewTestLogger()

		Convey("IsReferrersTag true update", func() {
			err := meta.OnUpdateManifest(context.Background(), "repo", "sha256-123", "digest", "media", []byte("bad"),
				storeController, metaDB, log)
			So(err, ShouldBeNil)
		})
		Convey("IsReferrersTag true delete", func() {
			err := meta.OnDeleteManifest("repo", "sha256-123", "digest", "media", []byte("bad"),
				storeController, metaDB, log)
			So(err, ShouldBeNil)
		})
	})
}

// TestOnDeleteManifest_EmptiedRepoStopsCountingTowardsQuota verifies that deleting the last manifest in
// a repo removes the repo itself, layout and meta together, so it stops counting towards maxRepos.
func TestOnDeleteManifest_EmptiedRepoStopsCountingTowardsQuota(t *testing.T) {
	Convey("Deleting the last manifest in a repo removes its layout and its meta", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{RootDir: rootDir}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		imgStore := storeController.GetImageStore("repo")
		ctx := context.Background()

		image := CreateDefaultImage()
		digest := image.Digest()
		body := image.ManifestDescriptor.Data

		So(WriteImageToFileSystem(image, "repo", "latest", storeController), ShouldBeNil)
		So(meta.OnUpdateManifest(ctx, "repo", "latest", ispec.MediaTypeImageManifest, digest, body,
			storeController, metaDB, log), ShouldBeNil)

		count, err := metaDB.CountRepos(ctx)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 1)

		So(imgStore.DeleteImageManifest(ctx, "repo", digest.String(), false), ShouldBeNil)
		So(meta.OnDeleteManifest("repo", digest.String(), ispec.MediaTypeImageManifest, digest, body,
			storeController, metaDB, log), ShouldBeNil)

		_, err = metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)

		count, err = metaDB.CountRepos(ctx)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 0)
	})

	Convey("A repo still holding another tagged manifest keeps its meta", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{RootDir: rootDir}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		imgStore := storeController.GetImageStore("repo")
		ctx := context.Background()

		first := CreateRandomImage()
		second := CreateRandomImage()

		So(WriteImageToFileSystem(first, "repo", "first", storeController), ShouldBeNil)
		So(meta.OnUpdateManifest(ctx, "repo", "first", ispec.MediaTypeImageManifest, first.Digest(),
			first.ManifestDescriptor.Data, storeController, metaDB, log), ShouldBeNil)

		So(WriteImageToFileSystem(second, "repo", "second", storeController), ShouldBeNil)
		So(meta.OnUpdateManifest(ctx, "repo", "second", ispec.MediaTypeImageManifest, second.Digest(),
			second.ManifestDescriptor.Data, storeController, metaDB, log), ShouldBeNil)

		So(imgStore.DeleteImageManifest(ctx, "repo", first.Digest().String(), false), ShouldBeNil)
		So(meta.OnDeleteManifest("repo", first.Digest().String(), ispec.MediaTypeImageManifest, first.Digest(),
			first.ManifestDescriptor.Data, storeController, metaDB, log), ShouldBeNil)

		_, err = metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)

		count, err := metaDB.CountRepos(ctx)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 1)

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldContain, "repo")
	})

	Convey("A repo holding only an untagged manifest keeps its meta", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{RootDir: rootDir}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		imgStore := storeController.GetImageStore("repo")
		ctx := context.Background()

		tagged := CreateRandomImage()
		untagged := CreateRandomImage()

		So(WriteImageToFileSystem(tagged, "repo", "v1", storeController), ShouldBeNil)
		So(meta.OnUpdateManifest(ctx, "repo", "v1", ispec.MediaTypeImageManifest, tagged.Digest(),
			tagged.ManifestDescriptor.Data, storeController, metaDB, log), ShouldBeNil)

		// Referenced by digest, so it carries no tag, which is how a signature
		// referrer or an attached artifact sits in a repo.
		So(WriteImageToFileSystem(untagged, "repo", untagged.Digest().String(), storeController), ShouldBeNil)
		So(meta.OnUpdateManifest(ctx, "repo", untagged.Digest().String(), ispec.MediaTypeImageManifest,
			untagged.Digest(), untagged.ManifestDescriptor.Data, storeController, metaDB, log), ShouldBeNil)

		So(imgStore.DeleteImageManifest(ctx, "repo", tagged.Digest().String(), false), ShouldBeNil)
		So(meta.OnDeleteManifest("repo", tagged.Digest().String(), ispec.MediaTypeImageManifest, tagged.Digest(),
			tagged.ManifestDescriptor.Data, storeController, metaDB, log), ShouldBeNil)

		// No tag is left, but the untagged manifest still holds the repo, so its
		// meta must survive and keep counting towards maxRepos.
		repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)

		for tag := range repoMeta.Tags {
			So(tag, ShouldBeEmpty)
		}

		count, err := metaDB.CountRepos(ctx)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 1)

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldContain, "repo")
	})
}

// TestOnDeleteManifest_OrphanedSignatureReferrerReleasesRepo verifies that deleting a signature
// referrer whose subject manifest was already untagged is not treated as a failure: the signature
// meta is already gone (an expected miss), and since the delete emptied the repo, the layout and
// the meta record are released so the repo stops counting towards maxRepos.
func TestOnDeleteManifest_OrphanedSignatureReferrerReleasesRepo(t *testing.T) {
	Convey("Deleting the last leftover signature referrer releases the emptied repo",
		t, func() {
			rootDir := t.TempDir()
			storeController := storage.StoreController{}
			log := log.NewTestLogger()
			metrics := monitoring.NewNopMetricServer()

			storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

			params := boltdb.DBParameters{RootDir: rootDir}
			boltDriver, err := boltdb.GetBoltDriver(params)
			So(err, ShouldBeNil)

			metaDB, err := boltdb.New(boltDriver, log)
			So(err, ShouldBeNil)

			imgStore := storeController.GetImageStore("repo")
			ctx := context.Background()

			// Push and register the subject image.
			image := CreateDefaultImage()
			subjectDigest := image.Digest()
			subjectBody := image.ManifestDescriptor.Data

			So(WriteImageToFileSystem(image, "repo", "latest", storeController), ShouldBeNil)
			So(meta.OnUpdateManifest(ctx, "repo", "latest", ispec.MediaTypeImageManifest, subjectDigest, subjectBody,
				storeController, metaDB, log), ShouldBeNil)

			// Push and register a sigstore-bundle referrer signing it.
			emptyConfig := []byte("{}")
			emptyConfigDigest := godigest.FromBytes(emptyConfig)
			_, _, err = imgStore.FullBlobUpload(ctx, "repo", bytes.NewReader(emptyConfig), emptyConfigDigest)
			So(err, ShouldBeNil)

			referrer := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: zcommon.ArtifactTypeCosignBundle,
				Config: ispec.Descriptor{
					MediaType: "application/vnd.oci.empty.v1+json",
					Digest:    emptyConfigDigest,
					Size:      int64(len(emptyConfig)),
				},
				Layers: []ispec.Descriptor{},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    subjectDigest,
					Size:      int64(len(subjectBody)),
				},
			}
			referrer.SchemaVersion = 2

			referrerBody, err := json.Marshal(referrer)
			So(err, ShouldBeNil)
			referrerDigest := godigest.FromBytes(referrerBody)

			_, _, err = imgStore.PutImageManifest(ctx, "repo", referrerDigest.String(), ispec.MediaTypeImageManifest,
				referrerBody, nil)
			So(err, ShouldBeNil)
			So(meta.OnUpdateManifest(ctx, "repo", referrerDigest.String(), ispec.MediaTypeImageManifest, referrerDigest,
				referrerBody, storeController, metaDB, log), ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(repoMeta.Signatures, ShouldContainKey, subjectDigest.String())

			// Delete the subject by digest, so only the signature referrer is left in the index.
			So(imgStore.DeleteImageManifest(ctx, "repo", subjectDigest.String(), false), ShouldBeNil)
			So(meta.OnDeleteManifest("repo", subjectDigest.String(), ispec.MediaTypeImageManifest, subjectDigest,
				subjectBody, storeController, metaDB, log), ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(repoMeta.Signatures, ShouldNotContainKey, subjectDigest.String())

			// The referrer is still present in the image store; deleting it finds its signature
			// meta already gone, which is expected and must not surface as an error. The repo is
			// now empty, so both the layout and the meta record are released.
			So(imgStore.DeleteImageManifest(ctx, "repo", referrerDigest.String(), false), ShouldBeNil)
			So(meta.OnDeleteManifest("repo", referrerDigest.String(), ispec.MediaTypeImageManifest, referrerDigest,
				referrerBody, storeController, metaDB, log), ShouldBeNil)

			So(imgStore.DirExists(path.Join(rootDir, "repo")), ShouldBeFalse)

			_, err = metaDB.GetRepoMeta(ctx, "repo")
			So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)

			count, err := metaDB.CountRepos(ctx)
			So(err, ShouldBeNil)
			So(count, ShouldEqual, 0)
		})
}
