package azure_test

// Core storage-API parity with S3/GCS's TestS3ManifestImageIndex/TestGCSStorageAPIs.
// This deliberately doesn't re-enumerate every edge case those cover (repo-name
// validation, unsupported digest algorithms, etc.) - that logic lives in
// pkg/storage/imagestore and is backend-agnostic, already exercised heavily by local
// storage's test suite and by the mock-driver-based imagestore tests. What's
// Azure-specific and worth proving end-to-end here is that the driver + wrapper
// correctly round-trip through a real Azure/Azurite backend for the core CRUD surface:
// repo lifecycle, blob upload, manifest put/get/delete, and the ErrBlobReferenced
// guard that stops a still-referenced blob from being deleted.

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"testing"

	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func TestAzureStorageAPIs(t *testing.T) {
	tskip.SkipAzure(t)

	Convey("Repo layout", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupAzureStorage(storeDriver, testDir)

		const repoName = "test"

		Convey("Get all blobs from repo without initialization", func() {
			allBlobs, err := imgStore.GetAllBlobs(repoName)
			So(err, ShouldBeNil)
			So(allBlobs, ShouldBeEmpty)
		})

		Convey("Initialize repo and validate", func() {
			err := imgStore.InitRepo(context.Background(), repoName)
			So(err, ShouldBeNil)

			ok, err := imgStore.ValidateRepo(repoName)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)

			repos, err := imgStore.GetRepositories()
			So(err, ShouldBeNil)
			So(repos, ShouldContain, repoName)
		})

		Convey("Get image tags on an empty repo", func() {
			err := imgStore.InitRepo(context.Background(), repoName)
			So(err, ShouldBeNil)

			tags, err := imgStore.GetImageTags(repoName)
			So(err, ShouldBeNil)
			So(tags, ShouldBeEmpty)
		})

		Convey("Full blob upload and verify", func() {
			body := []byte("this is an azure blob")
			digest := godigest.FromBytes(body)

			upload, size, err := imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(body), digest)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, len(body))
			So(upload, ShouldNotBeEmpty)

			err = imgStore.VerifyBlobDigestValue(repoName, digest)
			So(err, ShouldBeNil)

			ok, size, err := imgStore.CheckBlob(context.Background(), repoName, digest)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
			So(size, ShouldEqual, len(body))

			digests, err := imgStore.GetAllBlobs(repoName)
			So(err, ShouldBeNil)
			So(digests, ShouldContain, digest)
		})

		Convey("Push a manifest, read it back by tag and digest, then delete", func() {
			const tag = "1.0"

			layerContent := []byte("azure storage-apis layer")
			layerDigest := godigest.FromBytes(layerContent)
			_, _, err := imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(layerContent), layerDigest)
			So(err, ShouldBeNil)

			configContent := []byte("{}")
			configDigest := godigest.FromBytes(configContent)
			_, _, err = imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(configContent), configDigest)
			So(err, ShouldBeNil)

			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: "application/vnd.oci.image.config.v1+json",
					Digest:    configDigest,
					Size:      int64(len(configContent)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    layerDigest,
						Size:      int64(len(layerContent)),
					},
				},
			}
			manifest.SchemaVersion = 2

			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			manifestDigest, _, err := imgStore.PutImageManifest(
				context.Background(), repoName, tag, ispec.MediaTypeImageManifest, manifestBuf, nil)
			So(err, ShouldBeNil)

			tags, err := imgStore.GetImageTags(repoName)
			So(err, ShouldBeNil)
			So(tags, ShouldContain, tag)

			buf, digest, _, err := imgStore.GetImageManifest(repoName, tag)
			So(err, ShouldBeNil)
			So(digest, ShouldEqual, manifestDigest)
			So(buf, ShouldResemble, manifestBuf)

			buf, digest, _, err = imgStore.GetImageManifest(repoName, manifestDigest.String())
			So(err, ShouldBeNil)
			So(digest, ShouldEqual, manifestDigest)
			So(buf, ShouldResemble, manifestBuf)

			Convey("Referenced blobs cannot be deleted", func() {
				err := imgStore.DeleteBlob(repoName, layerDigest)
				So(err, ShouldEqual, zerr.ErrBlobReferenced)

				err = imgStore.DeleteBlob(repoName, configDigest)
				So(err, ShouldEqual, zerr.ErrBlobReferenced)

				err = imgStore.DeleteBlob(repoName, manifestDigest)
				So(err, ShouldEqual, zerr.ErrBlobReferenced)
			})

			Convey("Delete the manifest, then its now-unreferenced blobs", func() {
				// Delete by digest, not by tag: deleting by tag only removes that tag
				// reference (the manifest can still be reachable, e.g. untagged, until a
				// GC pass prunes it), while deleting by digest removes the index entry
				// itself, making its blobs immediately eligible for deletion.
				err := imgStore.DeleteImageManifest(context.Background(), repoName, manifestDigest.String(), false)
				So(err, ShouldBeNil)

				tags, err := imgStore.GetImageTags(repoName)
				So(err, ShouldBeNil)
				So(tags, ShouldNotContain, tag)

				err = imgStore.DeleteBlob(repoName, layerDigest)
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob(repoName, configDigest)
				So(err, ShouldBeNil)
			})
		})
	})
}
