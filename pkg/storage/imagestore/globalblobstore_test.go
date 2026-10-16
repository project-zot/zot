package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// The global blobstore lives next to the repositories under the store root, but it is never
// one: no walk may list it as a repository or return its blobs as a repository's.
func TestWalksSkipGlobalBlobstore(t *testing.T) {
	Convey("Repository and digest walks never treat the global blobstore as a repository", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		imgStore := imagestore.NewImageStore(dir, dir, false, true, log, monitoring.NewNopMetricServer(), nil,
			local.New(true), nil, nil, nil)

		img := image.CreateRandomImage()
		So(image.WriteImageToFileSystem(img, "repo", "tag", storage.StoreController{DefaultStore: imgStore}),
			ShouldBeNil)

		digest := godigest.FromBytes(img.Layers[0])

		// make the blobstore look as much like a repository as possible
		blobstore := path.Join(dir, storageConstants.GlobalBlobsRepo)
		blobPath := path.Join(blobstore, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
		So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(blobPath, img.Layers[0], storageConstants.DefaultFilePerms), ShouldBeNil)

		for _, name := range []string{ispec.ImageLayoutFile, ispec.ImageIndexFile} {
			content, err := os.ReadFile(path.Join(dir, "repo", name))
			So(err, ShouldBeNil)
			//nolint:gosec // test path is tempdir-scoped
			So(os.WriteFile(path.Join(blobstore, name), content, storageConstants.DefaultFilePerms), ShouldBeNil)
		}

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldResemble, []string{"repo"})

		page, _, err := imgStore.GetNextRepositories("", 100, func(string) (bool, error) { return true, nil })
		So(err, ShouldBeNil)
		So(page, ShouldResemble, []string{"repo"})

		processed := map[string]struct{}{}

		for {
			repo, err := imgStore.GetNextRepository(processed)
			So(err, ShouldBeNil)

			if repo == "" {
				break
			}

			So(repo, ShouldNotEqual, storageConstants.GlobalBlobsRepo)

			processed[repo] = struct{}{}
		}

		So(processed, ShouldContainKey, "repo")

		var lastDigests []godigest.Digest

		for {
			next, blobPaths, err := imgStore.GetNextDigestWithBlobPaths(repos, lastDigests)
			So(err, ShouldBeNil)

			if next == "" {
				break
			}

			for _, blobPath := range blobPaths {
				So(strings.Contains(blobPath, storageConstants.GlobalBlobsRepo), ShouldBeFalse)
			}

			lastDigests = append(lastDigests, next)
		}

		So(lastDigests, ShouldContain, digest)
	})
}

func TestLocalGlobalBlobstore(t *testing.T) {
	content := []byte("global-blobstore-content")
	digest := godigest.FromBytes(content)

	// recordPath turns a cache record, relative on local storage, into a store path
	recordPath := func(dir, record string) string { return path.Join(dir, record) }

	sameFile := func(path1, path2 string) bool {
		info1, err := os.Stat(path1)
		So(err, ShouldBeNil)

		info2, err := os.Stat(path2)
		So(err, ShouldBeNil)

		return os.SameFile(info1, info2)
	}

	Convey("A local store keeps deduped content once, in the global blobstore", t, func() {
		dir := t.TempDir()
		imgStore, cacheDriver := newLocalDedupeStoreAt(dir, local.New(true))
		ctx := context.Background()

		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		repoA := imgStore.BlobPath("repo-a", digest)
		repoB := imgStore.BlobPath("repo-b", digest)

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		Convey("the first push puts the content in the blobstore, recorded as the origin", func() {
			data, err := os.ReadFile(globalBlobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
			So(sameFile(globalBlobPath, repoA), ShouldBeTrue)

			record, err := cacheDriver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(recordPath(dir, record), ShouldEqual, globalBlobPath)
			So(cacheDriver.HasBlob(digest, repoA), ShouldBeTrue)
		})

		Convey("a second repo shares the same inode", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)
			So(sameFile(globalBlobPath, repoB), ShouldBeTrue)

			repos, err := imgStore.GetAllDedupeReposCandidates(digest)
			So(err, ShouldBeNil)
			So(repos, ShouldHaveLength, 2)
			So(repos, ShouldContain, "repo-a")
			So(repos, ShouldContain, "repo-b")
		})

		Convey("the blobstore copy is deleted with the last repo copy, and not before", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

			data, err := os.ReadFile(repoB)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)

			_, err = os.Stat(globalBlobPath)
			So(err, ShouldBeNil)

			So(imgStore.DeleteBlob("repo-b", digest), ShouldBeNil)

			_, err = os.Stat(globalBlobPath)
			So(os.IsNotExist(err), ShouldBeTrue)

			_, err = cacheDriver.GetBlob(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})

		Convey("a push over wrong shared content repairs it through the blobstore", func() {
			_, _, err := imgStore.FullBlobUpload(ctx, "repo-b", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			So(os.Truncate(globalBlobPath, 3), ShouldBeNil)

			_, _, err = imgStore.FullBlobUpload(ctx, "repo-c", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			for _, blobPath := range []string{globalBlobPath, repoA, repoB, imgStore.BlobPath("repo-c", digest)} {
				data, err := os.ReadFile(blobPath)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)
			}
		})
	})

	Convey("A first push that fails after the blobstore copy is made can be finished", t, func() {
		dir := t.TempDir()
		// the first Move is the one renaming the upload onto the repo path
		imgStore, cacheDriver := newLocalDedupeStoreAt(dir, &failingMoveDriver{Driver: local.New(true), failures: 1})
		ctx := context.Background()

		So(imgStore.InitRepo(ctx, "repo-a"), ShouldBeNil)

		uuid, err := imgStore.NewBlobUpload(ctx, "repo-a")
		So(err, ShouldBeNil)

		_, err = imgStore.PutBlobChunkStreamed(ctx, "repo-a", uuid, bytes.NewReader(content))
		So(err, ShouldBeNil)

		So(imgStore.FinishBlobUpload("repo-a", uuid, bytes.NewReader(nil), digest), ShouldNotBeNil)

		// the upload is still there, and the retry links the repo copy to the recorded origin
		So(imgStore.FinishBlobUpload("repo-a", uuid, bytes.NewReader(nil), digest), ShouldBeNil)

		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		So(sameFile(globalBlobPath, imgStore.BlobPath("repo-a", digest)), ShouldBeTrue)

		record, err := cacheDriver.GetBlob(digest)
		So(err, ShouldBeNil)
		So(recordPath(dir, record), ShouldEqual, globalBlobPath)
	})

	Convey("Without the global blobstore in use, pushes never create it", t, func() {
		Convey("remote storage keeps its origin in a repo until it moves too", func() {
			dir := t.TempDir()
			imgStore, _ := newLocalDedupeStoreAt(dir, &remoteNamedDriver{Driver: local.New(true)})

			_, _, err := imgStore.FullBlobUpload(context.Background(), "repo-a", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			_, err = os.Stat(path.Join(dir, storageConstants.GlobalBlobsRepo))
			So(os.IsNotExist(err), ShouldBeTrue)
		})

		Convey("a local store with dedupe off stores each copy in its repo", func() {
			dir := t.TempDir()
			imgStore := imagestore.NewImageStore(dir, dir, false, true, zlog.NewTestLogger(),
				monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)

			_, _, err := imgStore.FullBlobUpload(context.Background(), "repo-a", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			_, err = os.Stat(path.Join(dir, storageConstants.GlobalBlobsRepo))
			So(os.IsNotExist(err), ShouldBeTrue)
		})
	})
}
