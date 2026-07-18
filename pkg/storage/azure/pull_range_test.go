package azure_test

// Pull-range parity with S3/GCS. TestS3PullRange's regression (isDigestReferencedAcrossRepos
// falling back to manifest-only scanning) is what started this session's storage work, so
// leaving this untested against a third real backend was the highest-priority gap.

import (
	"bytes"
	"context"
	"path"
	"testing"

	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func TestAzurePullRange(t *testing.T) {
	tskip.SkipAzure(t)

	Convey("Pull range", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupAzureStorage(storeDriver, testDir)

		upload, err := imgStore.NewBlobUpload(context.Background(), "test")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed(context.Background(), "test", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("test", upload, buf, digest)
		So(err, ShouldBeNil)

		blobReadCloser, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 0, 4)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "test-")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range - "data3" is bytes 5-9 (inclusive) of "test-data3"
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 5, 9)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "data3")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range from negative offset
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", -4, 4)
		So(err, ShouldNotBeNil)
		So(blobReadCloser, ShouldBeNil)
	})
}

// TestAzurePullRangeDedupedBlob is the specific scenario TestS3PullRange's regression
// broke: pulling a byte range of a blob that's deduped across repos, where the range
// read must resolve through the same-repo copy/global-blobstore link, not just whatever
// isDigestReferencedAcrossRepos happens to scan.
func TestAzurePullRangeDedupedBlob(t *testing.T) {
	tskip.SkipAzure(t)

	Convey("Pull range of a deduped blob shared across repos", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupAzureStorage(storeDriver, testDir)

		content := []byte("azure-pull-range-dedupe-content")
		digest := godigest.FromBytes(content)

		_, _, err = imgStore.FullBlobUpload(context.Background(), "repo1", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		_, _, err = imgStore.FullBlobUpload(context.Background(), "repo2", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		for _, repo := range []string{"repo1", "repo2"} {
			blobReadCloser, _, _, err := imgStore.GetBlobPartial(repo, digest,
				"application/vnd.oci.image.layer.v1.tar", 0, 4)
			So(err, ShouldBeNil)

			buf := bytes.NewBuffer(nil)
			_, err = buf.ReadFrom(blobReadCloser)
			So(err, ShouldBeNil)
			So(buf.String(), ShouldEqual, "azure")
			So(blobReadCloser.Close(), ShouldBeNil)
		}
	})
}
