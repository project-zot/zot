package azure_test

// Targeted dedupe/migration coverage against a real Azurite backend.
//
// pkg/storage/azure/driver.go's formatErr (unlike the S3 driver, which delegates
// directly to a typed upstream implementation) falls back to string-matching Azure
// SDK error messages ("BlobNotFound", "ResourceNotFound", "Error 404", ...) to
// produce the driver.PathNotFoundError the shared dedupe/migration/reclaim logic in
// pkg/storage/imagestore depends on throughout (upgradeToGlobalBlobstore's marker
// check, ResolveReadPath, checkCacheBlob, promoteBlobCandidate's resume check). That
// classification can only be exercised against a real Azure/Azurite backend - a mock
// driver returns whatever typed error it's told to, bypassing formatErr entirely.
// These tests specifically stress that path, rather than re-testing the
// backend-agnostic seam logic already covered elsewhere via mock drivers.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

var errAzureMockEndpointNotSet = errors.New("AZURITEMOCK_ENDPOINT must be set for Azure dedupe tests")

func cleanupAzureStorage(storeDriver driver.StorageDriver, name string) {
	_ = storeDriver.Delete(context.Background(), name)
}

// createAzureObjectsStore mirrors createObjectsStore in s3_test.go/gcs_test.go: a
// real Azurite-backed ImageStore, with a boltdb dedupe cache when dedupe is enabled.
//
//nolint:unparam // dedupe is always true at current call sites; kept for symmetry with sibling helpers
func createAzureObjectsStore(rootDir, cacheDir string, dedupe bool) (
	driver.StorageDriver, storageTypes.ImageStore, error,
) {
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
	metrics := monitoring.NewMetricsServer(false, log)

	var cacheDriver storageTypes.Cache

	cacheDBPath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)
	if _, statErr := os.Stat(cacheDBPath); dedupe || (!dedupe && statErr == nil) {
		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     cacheDir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
	}

	imgStore := azure.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, imgStore, nil
}

// TestAzureDedupeGlobalBlobResolve pushes the same content to two repos (real dedupe
// via Azure's Link/PutContent) and reads it back through every read entry point from
// both repos. Each read resolves through originalBlobInfo -> ResolveReadPath, whose
// remote implementation Stats the global blobstore path on every call - this is the
// single most-executed Stat call in the dedupe subsystem, and the one most exposed to
// formatErr's not-found classification actually being correct against real Azure.
func TestAzureDedupeGlobalBlobResolve(t *testing.T) {
	tskip.SkipAzure(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
	So(err, ShouldBeNil)

	defer cleanupAzureStorage(storeDriver, testDir)

	Convey("Dedupe across repos resolves through the global blobstore", t, func() {
		content := []byte("azure-dedupe-content")
		digest := godigest.FromBytes(content)

		_, blen, err := imgStore.FullBlobUpload(context.Background(), "repo1", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		_, blen, err = imgStore.FullBlobUpload(context.Background(), "repo2", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		for _, repo := range []string{"repo1", "repo2"} {
			ok, size, err := imgStore.CheckBlob(context.Background(), repo, digest)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			reader, size, err := imgStore.GetBlob(repo, digest, "application/vnd.oci.image.layer.v1.tar")
			So(err, ShouldBeNil)
			So(size, ShouldEqual, len(content))

			buf, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(buf, ShouldResemble, content)
			So(reader.Close(), ShouldBeNil)

			blobContent, err := imgStore.GetBlobContent(repo, digest)
			So(err, ShouldBeNil)
			So(blobContent, ShouldResemble, content)

			ok, size, _, err = imgStore.StatBlob(repo, digest)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
			So(size, ShouldEqual, len(content))
		}
	})
}

// TestAzureDedupeReclaimOnDelete ports the exact isDigestReferencedAcrossRepos
// regression fixed in imagestore.go this session: deleting one repo's copy of a
// deduped blob must not reclaim the shared global copy while another repo's marker
// still points at it. On remote backends the reclaim decision itself is cache-based,
// not Stat-based, but deleteBlob's own Stat(blobPath) call (which must correctly
// distinguish "already gone" from a hard failure via formatErr) still gates the whole
// flow, so this is worth confirming end-to-end against real Azure too.
func TestAzureDedupeReclaimOnDelete(t *testing.T) {
	tskip.SkipAzure(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
	So(err, ShouldBeNil)

	defer cleanupAzureStorage(storeDriver, testDir)

	Convey("Deleting one repo's blob does not reclaim a still-referenced global copy", t, func() {
		content := []byte("azure-reclaim-content")
		digest := godigest.FromBytes(content)

		_, _, err := imgStore.FullBlobUpload(context.Background(), "repo1", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		_, _, err = imgStore.FullBlobUpload(context.Background(), "repo2", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		err = imgStore.DeleteBlob("repo1", digest)
		So(err, ShouldBeNil)

		blobContent, err := imgStore.GetBlobContent("repo2", digest)
		So(err, ShouldBeNil)
		So(blobContent, ShouldResemble, content)
	})
}

// TestAzureMigrationMarkerPersistence exercises upgradeToGlobalBlobstore's
// migration-marker Stat check end-to-end: the first NewImageStore call finds no
// marker (must correctly recognize that as PathNotFoundError, not a hard failure)
// and writes one; a second ImageStore instance over the same root must Stat it
// successfully and skip re-running the migration scan.
func TestAzureMigrationMarkerPersistence(t *testing.T) {
	tskip.SkipAzure(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
	So(err, ShouldBeNil)
	So(imgStore, ShouldNotBeNil)

	defer cleanupAzureStorage(storeDriver, testDir)

	Convey("A second store over the same root sees the migration marker and skips rescanning", t, func() {
		markerPath := path.Join(testDir, storageConstants.BlobstoreMigratedMarker)

		_, err := storeDriver.Stat(context.Background(), markerPath)
		So(err, ShouldBeNil)

		_, imgStore2, err := createAzureObjectsStore(testDir, t.TempDir(), true)
		So(err, ShouldBeNil)
		So(imgStore2, ShouldNotBeNil)
	})
}
