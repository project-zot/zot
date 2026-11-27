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

		// the sweep waits for the walk this test runs one digest of
		So(sweep(store, 0), ShouldBeNil)
		So(exists(globalBlobPath), ShouldBeTrue)

		imagestore.FinishDedupeWalk(store)

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

func TestReenablingDedupeUpgradesAgain(t *testing.T) {
	content := []byte("reenable-dedupe-content")
	digest := godigest.FromBytes(content)

	for _, backend := range []struct {
		name      string
		newDriver func() storageTypes.Driver
	}{
		{"local", func() storageTypes.Driver { return local.New(true) }},
		{"remote", func() storageTypes.Driver { return &remoteNamedDriver{Driver: local.New(true)} }},
	} {
		Convey("Turning dedupe off, then on again, brings back the "+backend.name+" global blobstore", t, func() {
			dir := t.TempDir()
			cacheDriver := newBoltCacheAbs(dir)
			ctx := context.Background()

			openStore := func(dedupe bool) storageTypes.ImageStore {
				return imagestore.NewImageStore(dir, dir, dedupe, true, zlog.NewTestLogger(),
					monitoring.NewNopMetricServer(), nil, backend.newDriver(), cacheDriver, nil, nil)
			}

			dedupedStore := openStore(true)
			So(dedupedStore, ShouldNotBeNil)

			repoPaths := []string{}

			for _, repo := range []string{"repo-a", "repo-b"} {
				_, _, err := dedupedStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
				So(err, ShouldBeNil)

				repoPaths = append(repoPaths, dedupedStore.BlobPath(repo, digest))
			}

			globalBlobPath := dedupedStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)

			// with dedupe off the copies get their content back, and a remote payload is reclaimed
			store := openStore(false)
			So(store, ShouldNotBeNil)
			So(store.RunDedupeForDigest(ctx, digest, false, repoPaths), ShouldBeNil)
			imagestore.FinishDedupeWalk(store)
			So(sweep(store, 0), ShouldBeNil)

			_, err := os.Stat(path.Join(dir, storageConstants.BlobstoreMigratedMarker))
			So(errors.Is(err, os.ErrNotExist), ShouldBeTrue)

			// with dedupe on again the upgrade runs, rather than the walk picking a repo copy as origin
			store = openStore(true)
			So(store, ShouldNotBeNil)
			So(store.RunDedupeForDigest(ctx, digest, true, repoPaths), ShouldBeNil)

			data, err := os.ReadFile(globalBlobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)

			origin, err := cacheDriver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, globalBlobPath)

			for _, repo := range []string{"repo-a", "repo-b"} {
				data, err := store.GetBlobContent(repo, digest)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)
			}
		})
	}

	Convey("A restore that cannot remove the migration marker restores no copy", t, func() {
		dir := t.TempDir()
		cacheDriver := newBoltCacheAbs(dir)
		ctx := context.Background()

		dedupedStore := newRemoteStore(dir, true, cacheDriver, local.New(true))
		So(dedupedStore, ShouldNotBeNil)

		repoPaths := []string{}

		for _, repo := range []string{"repo-a", "repo-b"} {
			_, _, err := dedupedStore.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			repoPaths = append(repoPaths, dedupedStore.BlobPath(repo, digest))
		}

		storeDriver := &faultyDriver{Driver: local.New(true), fail: func(op, p string) bool {
			return op == "Delete" && path.Base(p) == storageConstants.BlobstoreMigratedMarker
		}}
		store := newRemoteStore(dir, false, cacheDriver, storeDriver)
		So(store, ShouldNotBeNil)
		So(errors.Is(store.RunDedupeForDigest(ctx, digest, false, repoPaths), errInjectedFault), ShouldBeTrue)

		for _, repoPath := range repoPaths {
			binfo, err := os.Stat(repoPath)
			So(err, ShouldBeNil)
			So(binfo.Size(), ShouldEqual, 0)
		}

		_, err := os.Stat(path.Join(dir, storageConstants.BlobstoreMigratedMarker))
		So(err, ShouldBeNil)
	})
}

func newRemoteStore(dir string, dedupe bool, cacheDriver storageTypes.Cache,
	storeDriver storageTypes.Driver,
) storageTypes.ImageStore {
	return imagestore.NewImageStore(dir, dir, dedupe, true, zlog.NewTestLogger(), monitoring.NewNopMetricServer(),
		nil, &remoteNamedDriver{Driver: storeDriver}, cacheDriver, nil, nil)
}
