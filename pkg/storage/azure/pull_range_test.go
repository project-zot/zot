package azure_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/azure"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

//nolint:gochecknoglobals
var errAzureMockEndpointNotSet = errors.New("AZURITEMOCK_ENDPOINT must be set for Azure image store tests")

func cleanupAzureStorage(storeDriver driver.StorageDriver, name string) {
	_ = storeDriver.Delete(context.Background(), name)
}

// createAzureObjectsStore mirrors createObjectsStore in s3_test.go/gcs_test.go: a real
// Azurite-backed ImageStore with dedupe enabled and a boltdb dedupe cache.
func createAzureObjectsStore(rootDir, cacheDir string) (driver.StorageDriver, storageTypes.ImageStore, error) {
	endpoint := os.Getenv("AZURITEMOCK_ENDPOINT")
	if endpoint == "" {
		return nil, nil, errAzureMockEndpointNotSet
	}

	ctx := context.Background()

	connStr := fmt.Sprintf(
		"DefaultEndpointsProtocol=http;AccountName=%s;AccountKey=%s;BlobEndpoint=%s;",
		azuriteAccount, azuriteAccessKey, endpoint)

	client, err := azblob.NewClientFromConnectionString(connStr, nil)
	if err != nil {
		return nil, nil, err
	}

	if _, err := client.CreateContainer(ctx, azureContainer, nil); err != nil &&
		!strings.Contains(err.Error(), "ContainerAlreadyExists") {
		return nil, nil, err
	}

	params := map[string]any{
		"name":          "azure",
		"container":     azureContainer,
		"rootdirectory": rootDir,
		"accountname":   azuriteAccount,
		"accountkey":    azuriteAccessKey,
		"serviceurl":    endpoint,
		"credentials":   map[string]any{"type": "shared_key"},
	}

	store, err := factory.Create(ctx, "azure", params)
	if err != nil {
		return nil, nil, err
	}

	log := log.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     cacheDir,
		Name:        "cache",
		UseRelPaths: false,
	}, log)
	if err != nil {
		return nil, nil, err
	}

	imgStore := azure.NewImageStore(rootDir, cacheDir, true, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, imgStore, nil
}

// TestAzurePullRange covers GetBlobPartial against a real Azurite backend: a range read from
// the start, a range read from an interior offset, and a negative offset, which must error.
func TestAzurePullRange(t *testing.T) {
	tskip.SkipAzure(t)

	Convey("Pull range", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			t.Fatalf("failed to generate uuid: %v", err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir)
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
// one holds the original content.
func TestAzurePullRangeDedupedBlob(t *testing.T) {
	tskip.SkipAzure(t)

	Convey("Pull range of a deduped blob shared across repos", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			t.Fatalf("failed to generate uuid: %v", err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir)
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
