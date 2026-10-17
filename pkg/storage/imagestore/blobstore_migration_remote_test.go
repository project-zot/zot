package imagestore_test

import (
	"context"
	"errors"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// failingAddReferenceCache is a cache whose AddReference fails while failures remain.
type failingAddReferenceCache struct {
	storageTypes.Cache

	failures int
}

func (c *failingAddReferenceCache) AddReference(digest godigest.Digest, blobPath string) error {
	if c.failures > 0 {
		c.failures--

		return errInjectedFault
	}

	return c.Cache.AddReference(digest, blobPath)
}

func TestUpgradeRemoteStoreToGlobalBlobstore(t *testing.T) {
	shared := []byte("remote-legacy-shared")
	sharedDigest := godigest.FromBytes(shared)
	copied := []byte("remote-legacy-copied")
	copiedDigest := godigest.FromBytes(copied)

	repoBlob := func(dir, repo string, digest godigest.Digest) string {
		return path.Join(dir, repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
	}

	globalBlob := func(dir string, digest godigest.Digest) string {
		return repoBlob(dir, storageConstants.GlobalBlobsRepo, digest)
	}

	writeBlob := func(blobPath string, content []byte) {
		So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(blobPath, content, storageConstants.DefaultFilePerms), ShouldBeNil)
	}

	// legacyRemoteStore lays out what an earlier release left on remote storage: a digest whose
	// origin is repo-a's copy and whose repo-b copy is a placeholder, and a digest repo-a and
	// repo-c each hold in full, from a time dedupe was off.
	legacyRemoteStore := func(dir string, cacheDriver storageTypes.Cache) {
		oldStore := imagestore.NewImageStore(dir, dir, false, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, &remoteNamedDriver{Driver: local.New(true)}, nil, nil, nil)

		for _, repo := range []string{"repo-a", "repo-b", "repo-c"} {
			So(oldStore.InitRepo(context.Background(), repo), ShouldBeNil)
		}

		writeBlob(repoBlob(dir, "repo-a", sharedDigest), shared)
		writeBlob(repoBlob(dir, "repo-b", sharedDigest), []byte{})
		So(cacheDriver.PutBlob(sharedDigest, repoBlob(dir, "repo-a", sharedDigest)), ShouldBeNil)
		So(cacheDriver.PutBlob(sharedDigest, repoBlob(dir, "repo-b", sharedDigest)), ShouldBeNil)

		writeBlob(repoBlob(dir, "repo-a", copiedDigest), copied)
		writeBlob(repoBlob(dir, "repo-c", copiedDigest), copied)
	}

	openStore := func(dir string, cacheDriver storageTypes.Cache) storageTypes.ImageStore {
		return imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(), monitoring.NewNopMetricServer(),
			nil, &remoteNamedDriver{Driver: local.New(true)}, cacheDriver, nil, nil)
	}

	markerExists := func(dir string) bool {
		_, err := os.Stat(path.Join(dir, storageConstants.BlobstoreMigratedMarker))

		return err == nil
	}

	fileSize := func(blobPath string) int64 {
		info, err := os.Stat(blobPath)
		So(err, ShouldBeNil)

		return info.Size()
	}

	Convey("The upgrade keeps each remote digest once, in the global blobstore", t, func() {
		dir := t.TempDir()
		cacheDriver := newBoltCacheAbs(dir)
		legacyRemoteStore(dir, cacheDriver)

		imgStore := openStore(dir, cacheDriver)
		So(imgStore, ShouldNotBeNil)
		So(markerExists(dir), ShouldBeTrue)

		for _, testCase := range []struct {
			digest  godigest.Digest
			content []byte
			repos   []string
		}{
			{sharedDigest, shared, []string{"repo-a", "repo-b"}},
			{copiedDigest, copied, []string{"repo-a", "repo-c"}},
		} {
			data, err := os.ReadFile(globalBlob(dir, testCase.digest))
			So(err, ShouldBeNil)
			So(data, ShouldResemble, testCase.content)

			origin, err := cacheDriver.GetBlob(testCase.digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, globalBlob(dir, testCase.digest))

			// every repo owns the payload, and its copy is a placeholder reading it
			refs, err := cacheDriver.GetReferences(testCase.digest)
			So(err, ShouldBeNil)
			So(refs, ShouldHaveLength, len(testCase.repos))

			_, err = cacheDriver.ClaimReclaim(testCase.digest)
			So(errors.Is(err, zerr.ErrDigestReferenced), ShouldBeTrue)

			for _, repo := range testCase.repos {
				So(refs, ShouldContain, repoBlob(dir, repo, testCase.digest))
				So(fileSize(repoBlob(dir, repo, testCase.digest)), ShouldEqual, 0)

				data, err := imgStore.GetBlobContent(repo, testCase.digest)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, testCase.content)
			}
		}
	})

	Convey("A remote upgrade that cannot record an owner keeps every copy's content", t, func() {
		dir := t.TempDir()
		boltCache := newBoltCacheAbs(dir)
		legacyRemoteStore(dir, boltCache)

		So(openStore(dir, &failingAddReferenceCache{Cache: boltCache, failures: 1}), ShouldBeNil)
		So(markerExists(dir), ShouldBeFalse)

		So(fileSize(repoBlob(dir, "repo-a", sharedDigest)), ShouldEqual, len(shared))
		So(fileSize(repoBlob(dir, "repo-a", copiedDigest)), ShouldEqual, len(copied))
		So(fileSize(repoBlob(dir, "repo-c", copiedDigest)), ShouldEqual, len(copied))

		// the next start completes it
		So(openStore(dir, boltCache), ShouldNotBeNil)
		So(markerExists(dir), ShouldBeTrue)
		So(fileSize(repoBlob(dir, "repo-a", sharedDigest)), ShouldEqual, 0)
	})

	Convey("A remote upgrade resumed over placeholders records the payload and its owners", t, func() {
		dir := t.TempDir()
		cacheDriver := newBoltCacheAbs(dir)
		legacyRemoteStore(dir, cacheDriver)

		// what a pass that stopped after placeholdering left: the payload, placeholders only, and
		// no reference index record
		writeBlob(globalBlob(dir, sharedDigest), shared)
		writeBlob(repoBlob(dir, "repo-a", sharedDigest), []byte{})

		So(openStore(dir, cacheDriver), ShouldNotBeNil)

		refs, err := cacheDriver.GetReferences(sharedDigest)
		So(err, ShouldBeNil)
		So(refs, ShouldHaveLength, 2)

		_, err = cacheDriver.ClaimReclaim(sharedDigest)
		So(errors.Is(err, zerr.ErrDigestReferenced), ShouldBeTrue)

		data, err := os.ReadFile(globalBlob(dir, sharedDigest))
		So(err, ShouldBeNil)
		So(data, ShouldResemble, shared)
	})
}
