package azure_test

// Corrupted-blob reupload repair, parity with S3/GCS's TestGCSReuploadCorruptedBlob.
//
// Unlike GCS, Azure/Azurite is strongly consistent, so this doesn't need GCS's
// eventual-consistency polling/retry machinery (overwriteUntilSizeChanges,
// waitForCorruptionDetection, waitForExpectedBlobSize) - direct assertions suffice.
//
// A single reupload of the same digest does NOT repair in-place corruption of the
// global blobstore copy: DedupeBlob's cache lookup still finds a record for this
// digest, Stat on it still succeeds (the content is corrupted, not missing), and on
// a remote/marker backend the per-repo path is a marker - never SameFile as the
// global blob - so it takes the plain link+ref branch, which never re-verifies
// content. Repair only happens once the stale record is gone (e.g. after GC reclaims
// it, or - as here - a direct delete of the corrupted global blob), which forces the
// next reupload down DedupeBlob's first-writer path. This is the same reason GCS's
// test falls back to a direct delete "in case remote propagation delayed the first
// repair attempt" - the actual cause isn't propagation delay, it's this structural
// gap, present on every remote/marker backend.

import (
	"context"
	"path"
	"testing"

	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/azure"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func TestAzureReuploadCorruptedBlob(t *testing.T) {
	tskip.SkipAzure(t)

	Convey("Reupload repairs a corrupted blob", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		rawDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupAzureStorage(rawDriver, testDir)

		azureDriver := azure.New(rawDriver)

		storeController := storage.StoreController{DefaultStore: imgStore}

		const repoName = "test"

		const tag = "1.0"

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blob := image.Layers[0]
		blobDigest := godigest.FromBytes(blob)
		blobSize := len(blob)
		blobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, blobDigest)

		ok, size, err := imgStore.CheckBlob(context.Background(), repoName, blobDigest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize)

		// corrupt the shared global-blobstore copy in place
		corrupted := make([]byte, blobSize+1)
		_, err = azureDriver.WriteFile(blobPath, corrupted)
		So(err, ShouldBeNil)

		blobInfo, err := azureDriver.Stat(blobPath)
		So(err, ShouldBeNil)
		So(blobInfo.Size(), ShouldEqual, int64(blobSize+1))

		// On a remote/marker backend, ResolveReadPath always resolves to the global
		// blobstore path once it Stats successfully - corruption doesn't surface as a
		// hard error here, it surfaces as CheckBlob successfully reporting the wrong
		// (corrupted) size, since copyBlob just copies whatever content is actually
		// there. (This differs from local storage's hardlink lifecycle, where a
		// corrupted in-place per-repo file is instead caught by the
		// resolvedPath==blobPath descriptor-size comparison branch.)
		ok, size, err = imgStore.CheckBlob(context.Background(), repoName, blobDigest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize+1)

		// A same-digest reupload alone does not repair it (see comment above) - the
		// stale cache record must be invalidated first, which a direct delete of the
		// corrupted global blob does.
		err = WriteImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blobInfo, err = azureDriver.Stat(blobPath)
		So(err, ShouldBeNil)
		So(blobInfo.Size(), ShouldEqual, int64(blobSize+1))

		err = azureDriver.Delete(blobPath)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blobInfo, err = azureDriver.Stat(blobPath)
		So(err, ShouldBeNil)
		So(blobInfo.Size(), ShouldEqual, int64(blobSize))

		ok, size, err = imgStore.CheckBlob(context.Background(), repoName, blobDigest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize)
	})
}
