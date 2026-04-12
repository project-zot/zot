package meta_test

import (
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
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
	ctx context.Context, repo, ref string, imageMeta mTypes.ImageMeta,
) error {
	if ref == w.failRef {
		return errDigestTagsSetRepoReferenceFail
	}

	return w.MetaDB.SetRepoReference(ctx, repo, ref, imageMeta)
}

// failDeleteImageStore delegates to an inner ImageStore but forces DeleteImageManifest to return deleteErr.
type failDeleteImageStore struct {
	stypes.ImageStore

	deleteErr error
}

func (f *failDeleteImageStore) DeleteImageManifest(_ context.Context, repo, reference string, detectCollision bool) error {
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
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop()
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
			metrics := monitoring.NewMetricsServer(false, log)

			defer metrics.Stop()
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
			metrics := monitoring.NewMetricsServer(false, log)

			defer metrics.Stop()
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
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop()
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
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop()
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
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop()
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
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
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
