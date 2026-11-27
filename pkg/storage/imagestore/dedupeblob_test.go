package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestDedupeBlobOriginWithoutContent(t *testing.T) {
	Convey("A push is not linked to a dedupe origin that has no content", t, func() {
		content := []byte("dedupe-origin-content")
		digest := godigest.FromBytes(content)

		for _, testCase := range []struct {
			name     string
			driver   storageTypes.Driver
			relPaths bool
		}{
			{"remote", &remoteNamedDriver{Driver: local.New(true)}, false},
			{"local", local.New(true), true},
		} {
			Convey(testCase.name, func() {
				dir := t.TempDir()
				log := zlog.NewTestLogger()

				cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: testCase.relPaths,
				}, log)
				So(err, ShouldBeNil)

				imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
					testCase.driver, cacheDriver, nil, nil)

				ctx := context.Background()

				// the cache names an empty copy as the origin: a placeholder whose content was
				// lost, or a corrupt local copy recorded by an older dedupe walk. Another repo
				// shares it: a hardlink locally, a placeholder remotely.
				emptyOrigin := ""

				for _, repo := range []string{"repo-empty", "repo-other"} {
					So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

					blobPath := imgStore.BlobPath(repo, digest)
					So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)

					if emptyOrigin == "" || !testCase.relPaths {
						So(os.WriteFile(blobPath, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
					} else {
						So(os.Link(emptyOrigin, blobPath), ShouldBeNil)
					}

					So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

					if emptyOrigin == "" {
						emptyOrigin = blobPath
					}
				}

				_, size, err := imgStore.FullBlobUpload(ctx, "repo-push", bytes.NewReader(content), digest)
				So(err, ShouldBeNil)
				So(size, ShouldEqual, len(content))

				// the push repaired the origin rather than replacing it, so every repo reads it
				data, err := os.ReadFile(emptyOrigin)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

				for _, repo := range []string{"repo-empty", "repo-other", "repo-push"} {
					ok, blobSize, err := imgStore.CheckBlob(ctx, repo, digest)
					So(err, ShouldBeNil)
					So(ok, ShouldBeTrue)
					So(blobSize, ShouldEqual, len(content))
				}

				record, err := cacheDriver.GetBlob(digest)
				So(err, ShouldBeNil)

				if testCase.relPaths {
					record = path.Join(dir, record)
				}

				So(record, ShouldEqual, emptyOrigin)
				So(cacheDriver.HasBlob(digest, imgStore.BlobPath("repo-push", digest)), ShouldBeTrue)
			})
		}
	})
}

func TestDedupeBlobRepairsSharedContent(t *testing.T) {
	Convey("Pushing a blob again over wrong shared content repairs every copy of it", t, func() {
		// a truncated inode, and one truncated to nothing
		for _, corruptSize := range []int64{3, 0} {
			Convey(fmt.Sprintf("shared content cut to %d bytes", corruptSize), func() {
				testRepairSharedContent(t, corruptSize)
			})
		}
	})
}

// testRepairSharedContent pushes a blob again after cutting the inode two repos share to
// corruptSize bytes, and checks that both copies are repaired.
func testRepairSharedContent(t *testing.T, corruptSize int64) {
	t.Helper()

	dir := t.TempDir()
	log := zlog.NewTestLogger()

	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)
	So(err, ShouldBeNil)

	imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
		local.New(true), cacheDriver, nil, nil)

	storeController := storage.StoreController{DefaultStore: imgStore}

	img := image.CreateRandomImage()
	So(image.WriteImageToFileSystem(img, "repo-a", "tag", storeController), ShouldBeNil)
	So(image.WriteImageToFileSystem(img, "repo-b", "tag", storeController), ShouldBeNil)

	layer := img.Layers[0]
	digest := godigest.FromBytes(layer)
	origin := imgStore.BlobPath("repo-a", digest)
	copyB := imgStore.BlobPath("repo-b", digest)

	// both copies are links to one inode, so truncating it corrupts both
	So(os.Truncate(origin, corruptSize), ShouldBeNil)

	data, err := os.ReadFile(copyB)
	So(err, ShouldBeNil)
	So(data, ShouldHaveLength, corruptSize)

	_, _, err = imgStore.FullBlobUpload(context.Background(), "repo-b", bytes.NewReader(layer), digest)
	So(err, ShouldBeNil)

	// a rename would have repaired only repo-b's path; the origin and its links stay wrong
	for _, blobPath := range []string{origin, copyB} {
		data, err := os.ReadFile(blobPath)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, layer)
	}
}

func TestDedupeBlobOriginWithWrongContent(t *testing.T) {
	Convey("A push into a new repo repairs an origin left with part of its content", t, func() {
		content := []byte("dedupe-origin-content")
		digest := godigest.FromBytes(content)

		for _, testCase := range []struct {
			name     string
			driver   storageTypes.Driver
			relPaths bool
		}{
			{"remote", &remoteNamedDriver{Driver: local.New(true)}, false},
			{"local", local.New(true), true},
		} {
			Convey(testCase.name, func() {
				dir := t.TempDir()
				log := zlog.NewTestLogger()

				cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: testCase.relPaths,
				}, log)
				So(err, ShouldBeNil)

				imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
					testCase.driver, cacheDriver, nil, nil)

				ctx := context.Background()

				// what a repair that failed partway through leaves behind: a prefix of the content
				So(imgStore.InitRepo(ctx, "repo-origin"), ShouldBeNil)

				origin := imgStore.BlobPath("repo-origin", digest)
				So(os.MkdirAll(path.Dir(origin), storageConstants.DefaultDirPerms), ShouldBeNil)
				So(os.WriteFile(origin, content[:5], storageConstants.DefaultFilePerms), ShouldBeNil)
				So(cacheDriver.PutBlob(digest, origin), ShouldBeNil)

				_, _, err = imgStore.FullBlobUpload(ctx, "repo-new", bytes.NewReader(content), digest)
				So(err, ShouldBeNil)

				data, err := os.ReadFile(origin)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

				for _, repo := range []string{"repo-origin", "repo-new"} {
					ok, blobSize, err := imgStore.CheckBlob(ctx, repo, digest)
					So(err, ShouldBeNil)
					So(ok, ShouldBeTrue)
					So(blobSize, ShouldEqual, len(content))
				}
			})
		}
	})
}

// failingLinkDriver fails the first failures calls to Link, then delegates.
type failingLinkDriver struct {
	storageTypes.Driver

	failures int
}

func (d *failingLinkDriver) Link(src, dest string) error {
	if d.failures > 0 {
		d.failures--

		return errDriverFailed
	}

	return d.Driver.Link(src, dest)
}

func TestDedupeBlobKeepsUploadUntilLinked(t *testing.T) {
	Convey("A failed link while finishing an upload over an empty origin keeps the upload", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		storeDriver := &failingLinkDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}, failures: 1}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			storeDriver, cacheDriver, nil, nil)

		ctx := context.Background()
		content := []byte("dedupe-origin-content")
		digest := godigest.FromBytes(content)

		So(imgStore.InitRepo(ctx, "repo-empty"), ShouldBeNil)

		emptyOrigin := imgStore.BlobPath("repo-empty", digest)
		So(os.MkdirAll(path.Dir(emptyOrigin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(emptyOrigin, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, emptyOrigin), ShouldBeNil)

		So(imgStore.InitRepo(ctx, "repo-push"), ShouldBeNil)

		uuid, err := imgStore.NewBlobUpload(ctx, "repo-push")
		So(err, ShouldBeNil)

		_, err = imgStore.PutBlobChunkStreamed(ctx, "repo-push", uuid, bytes.NewReader(content))
		So(err, ShouldBeNil)

		// the link fails before anything consumed the upload, so the session survives
		So(imgStore.FinishBlobUpload("repo-push", uuid, bytes.NewReader(nil), digest), ShouldNotBeNil)

		size, err := imgStore.GetBlobUpload("repo-push", uuid)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, len(content))

		// and the retry finishes it, repairing the origin
		So(imgStore.FinishBlobUpload("repo-push", uuid, bytes.NewReader(nil), digest), ShouldBeNil)

		data, err := os.ReadFile(emptyOrigin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		ok, blobSize, err := imgStore.CheckBlob(ctx, "repo-push", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(blobSize, ShouldEqual, len(content))
	})
}

func TestDedupeBlobNeverRepairsFromAChangedUpload(t *testing.T) {
	Convey("An upload changed after it was verified never overwrites a healthy origin", t, func() {
		content := []byte("dedupe-origin-content")
		digest := godigest.FromBytes(content)

		for _, testCase := range []struct {
			name     string
			driver   storageTypes.Driver
			relPaths bool
		}{
			{"remote", &remoteNamedDriver{Driver: local.New(true)}, false},
			{"local", local.New(true), true},
		} {
			Convey(testCase.name, func() {
				dir := t.TempDir()
				log := zlog.NewTestLogger()

				cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: testCase.relPaths,
				}, log)
				So(err, ShouldBeNil)

				imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
					testCase.driver, cacheDriver, nil, nil)

				ctx := context.Background()

				_, _, err = imgStore.FullBlobUpload(ctx, "repo-origin", bytes.NewReader(content), digest)
				So(err, ShouldBeNil)

				// the payload every copy shares, in the global blobstore on either backend
				origin := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)

				// what a chunk upload racing the finalization leaves: the verified bytes, then more
				So(imgStore.InitRepo(ctx, "repo-push"), ShouldBeNil)

				src := path.Join(dir, "repo-push", storageConstants.BlobUploadDir, "racing-upload")
				So(os.MkdirAll(path.Dir(src), storageConstants.DefaultDirPerms), ShouldBeNil)
				So(os.WriteFile(src, append(append([]byte{}, content...), "appended"...),
					storageConstants.DefaultFilePerms), ShouldBeNil)

				// FinishBlobUpload creates the blob's directory before it dedupes
				dst := imgStore.BlobPath("repo-push", digest)
				So(os.MkdirAll(path.Dir(dst), storageConstants.DefaultDirPerms), ShouldBeNil)

				err = imgStore.DedupeBlob(src, digest, "repo-push", dst)
				So(errors.Is(err, zerr.ErrBadBlobDigest), ShouldBeTrue)

				// the origin keeps its content, the upload is left in place, and no snapshot remains
				data, err := os.ReadFile(origin)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

				_, err = os.Stat(src)
				So(err, ShouldBeNil)

				snapshots, err := filepath.Glob(src + ".*.verified")
				So(err, ShouldBeNil)
				So(snapshots, ShouldBeEmpty)

				ok, blobSize, err := imgStore.CheckBlob(ctx, "repo-origin", digest)
				So(err, ShouldBeNil)
				So(ok, ShouldBeTrue)
				So(blobSize, ShouldEqual, len(content))
			})
		}
	})
}

// snapshotReadHookDriver calls hook once, the first time a verified snapshot is read: between
// the snapshot being hashed and the repair copying it.
type snapshotReadHookDriver struct {
	storageTypes.Driver

	once sync.Once
	hook func()
}

func (d *snapshotReadHookDriver) Reader(readPath string, offset int64) (io.ReadCloser, error) {
	if strings.HasSuffix(readPath, ".verified") {
		d.once.Do(d.hook)
	}

	return d.Driver.Reader(readPath, offset)
}

func TestDedupeBlobRepairSnapshot(t *testing.T) {
	content := []byte("dedupe-origin-content")
	digest := godigest.FromBytes(content)

	newStore := func(dir string, storeDriver storageTypes.Driver, relPaths bool) (storageTypes.ImageStore,
		storageTypes.Cache, string,
	) {
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: relPaths,
		}, log)
		So(err, ShouldBeNil)

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			storeDriver, cacheDriver, nil, nil)

		// the cache names an empty copy as the origin, so a push of the blob repairs it
		So(imgStore.InitRepo(context.Background(), "repo-empty"), ShouldBeNil)

		emptyOrigin := imgStore.BlobPath("repo-empty", digest)
		So(os.MkdirAll(path.Dir(emptyOrigin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(emptyOrigin, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, emptyOrigin), ShouldBeNil)

		return imgStore, cacheDriver, emptyOrigin
	}

	snapshotsLeft := func(dir string) []string {
		snapshots, err := filepath.Glob(path.Join(dir, "repo-push", storageConstants.BlobUploadDir, "*.verified"))
		So(err, ShouldBeNil)

		return snapshots
	}

	Convey("The snapshot cannot be written through the upload API", t, func() {
		dir := t.TempDir()
		storeDriver := &snapshotReadHookDriver{Driver: local.New(true)}
		imgStore, _, emptyOrigin := newStore(dir, storeDriver, true)
		ctx := context.Background()

		So(imgStore.InitRepo(ctx, "repo-push"), ShouldBeNil)

		uuid, err := imgStore.NewBlobUpload(ctx, "repo-push")
		So(err, ShouldBeNil)

		_, err = imgStore.PutBlobChunkStreamed(ctx, "repo-push", uuid, bytes.NewReader(content))
		So(err, ShouldBeNil)

		// a client appending to the session ID a snapshot name could be derived from
		storeDriver.hook = func() {
			_, _ = imgStore.PutBlobChunkStreamed(ctx, "repo-push", uuid+".verified",
				bytes.NewReader([]byte("unverified")))
		}

		So(imgStore.FinishBlobUpload("repo-push", uuid, bytes.NewReader(nil), digest), ShouldBeNil)

		data, err := os.ReadFile(emptyOrigin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		So(snapshotsLeft(dir), ShouldBeEmpty)
	})

	Convey("A failed repair leaves no snapshot behind, and the retry succeeds", t, func() {
		dir := t.TempDir()
		// the first Move is the repair's: the remote lifecycle moves the snapshot onto the origin
		storeDriver := &failingMoveDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}, failures: 1}
		imgStore, _, emptyOrigin := newStore(dir, storeDriver, false)
		ctx := context.Background()

		_, _, err := imgStore.FullBlobUpload(ctx, "repo-push", bytes.NewReader(content), digest)
		So(err, ShouldNotBeNil)
		So(snapshotsLeft(dir), ShouldBeEmpty)

		_, _, err = imgStore.FullBlobUpload(ctx, "repo-push", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(snapshotsLeft(dir), ShouldBeEmpty)

		data, err := os.ReadFile(emptyOrigin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})
}

// endlessReader produces bytes slowly and never ends, like an upload a client keeps appending to.
type endlessReader struct{}

func (endlessReader) Read(buf []byte) (int, error) {
	time.Sleep(time.Millisecond)

	n := min(len(buf), 1024) //nolint:mnd

	for i := range n {
		buf[i] = 'x'
	}

	return n, nil
}

// appendingUploadDriver reads the upload at path as its content followed by endless appends.
type appendingUploadDriver struct {
	storageTypes.Driver

	path string
}

func (d *appendingUploadDriver) Reader(readPath string, offset int64) (io.ReadCloser, error) {
	reader, err := d.Driver.Reader(readPath, offset)
	if err != nil || readPath != d.path {
		return reader, err
	}

	return struct {
		io.Reader
		io.Closer
	}{io.MultiReader(reader, endlessReader{}), reader}, nil
}

func TestDedupeBlobRepairSnapshotIsBounded(t *testing.T) {
	Convey("A repair copies only the upload's size, however long the upload keeps growing", t, func() {
		content := []byte("dedupe-origin-content")
		digest := godigest.FromBytes(content)
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		So(err, ShouldBeNil)

		src := path.Join(dir, "repo-push", storageConstants.BlobUploadDir, "appending-upload")
		storeDriver := &appendingUploadDriver{Driver: local.New(true), path: src}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			storeDriver, cacheDriver, nil, nil)

		ctx := context.Background()

		// an empty origin, so that the push repairs it from a snapshot of the upload
		So(imgStore.InitRepo(ctx, "repo-empty"), ShouldBeNil)

		emptyOrigin := imgStore.BlobPath("repo-empty", digest)
		So(os.MkdirAll(path.Dir(emptyOrigin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(emptyOrigin, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, emptyOrigin), ShouldBeNil)

		So(imgStore.InitRepo(ctx, "repo-push"), ShouldBeNil)
		So(os.MkdirAll(path.Dir(src), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(src, content, storageConstants.DefaultFilePerms), ShouldBeNil)

		dst := imgStore.BlobPath("repo-push", digest)
		So(os.MkdirAll(path.Dir(dst), storageConstants.DefaultDirPerms), ShouldBeNil)

		done := make(chan error, 1)

		go func() { done <- imgStore.DedupeBlob(src, digest, "repo-push", dst) }()

		select {
		case err := <-done:
			So(err, ShouldBeNil)
		case <-time.After(10 * time.Second):
			So("the repair", ShouldEqual, "finished, not copying for as long as the upload grows")
		}

		// the verified bytes, and nothing appended after them
		data, err := os.ReadFile(emptyOrigin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})
}
