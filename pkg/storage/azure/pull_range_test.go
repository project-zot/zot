package azure_test

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

// TestAzurePullRange covers GetBlobPartial against a real Azure backend: a range read from
// the start, a range read from an interior offset, and a negative offset, which must error.
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

		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 0, 4)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "test-")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// end offset is inclusive: 5-9 of "test-data3" is "data3"
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 5, 9)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "data3")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", -4, 4)
		So(err, ShouldNotBeNil)
		So(blobReadCloser, ShouldBeNil)
	})
}

// TestAzurePullRangeDedupedBlob covers a range read of a blob that's deduped across
// multiple repos, verifying the read resolves correctly for each repo regardless of which
// one holds the underlying global-blobstore copy.
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
