package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

func TestRestoreRemoteGlobalBlobstore(t *testing.T) {
	content := []byte("remote-restore-content")
	digest := godigest.FromBytes(content)

	openStore := func(dir string, dedupe bool, cacheDriver storageTypes.Cache) storageTypes.ImageStore {
		return imagestore.NewImageStore(dir, dir, dedupe, true, zlog.NewTestLogger(), monitoring.NewNopMetricServer(),
			nil, &remoteNamedDriver{Driver: local.New(true)}, cacheDriver, nil, nil)
	}

	markerPath := func(dir string) string {
		return path.Join(dir, storageConstants.GlobalBlobsRepo, "_reclaim", digest.Algorithm().String(),
			digest.Encoded())
	}

	exists := func(blobPath string) bool {
		_, err := os.Stat(blobPath)

		return err == nil
	}

	Convey("Turning dedupe off restores remote repo copies and leaves the payload to the sweep", t, func() {
		dir := t.TempDir()
		cacheDriver := newBoltCacheAbs(dir)
		ctx := context.Background()

		dedupedStore := openStore(dir, true, cacheDriver)
		So(dedupedStore, ShouldNotBeNil)

		repoPaths := []string{}

		for _, repo := range []string{"repo-a", "repo-b"} {
			_, _, err := dedupedStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			repoPaths = append(repoPaths, dedupedStore.BlobPath(repo, digest))
		}

		globalBlobPath := dedupedStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)

		// what the restore walk runs for the digest, once the store is opened with dedupe off
		store := openStore(dir, false, cacheDriver)
		So(store, ShouldNotBeNil)
		So(store.RunDedupeForDigest(ctx, digest, false, repoPaths), ShouldBeNil)

		for _, repoPath := range repoPaths {
			data, err := os.ReadFile(repoPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		}

		// no repo owns the payload any more, so it is marked, and the sweep may claim it
		refs, err := cacheDriver.GetReferences(digest)
		So(err, ShouldBeNil)
		So(refs, ShouldBeEmpty)
		So(exists(markerPath(dir)), ShouldBeTrue)

		So(sweep(store, 0), ShouldBeNil)
		So(exists(globalBlobPath), ShouldBeFalse)

		for _, repo := range []string{"repo-a", "repo-b"} {
			data, err := store.GetBlobContent(repo, digest)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		}

		Convey("and a second pass, over copies already restored, changes nothing", func() {
			So(store.RunDedupeForDigest(ctx, digest, false, repoPaths), ShouldBeNil)

			_, err := cacheDriver.GetReferences(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})
	})

	Convey("Deleting a copy a remote store holds with dedupe off leaves nothing for the sweep", t, func() {
		dir := t.TempDir()
		cacheDriver := newBoltCacheAbs(dir)
		ctx := context.Background()

		store := openStore(dir, false, cacheDriver)
		So(store, ShouldNotBeNil)

		_, _, err := store.FullBlobUpload(ctx, "repo-a", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		So(store.DeleteBlob("repo-a", digest), ShouldBeNil)
		So(exists(markerPath(dir)), ShouldBeFalse)
	})
}
