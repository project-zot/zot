package azure_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage/azure"
)

// Well-known Azurite development account (https://github.com/Azure/Azurite).
//
//nolint:gochecknoglobals,gosec // fixed public dev credentials, not a secret
const (
	azuriteAccount   = "devstoreaccount1"
	azuriteAccessKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	azureContainer   = "zot-azure-it"
)

// TestAzureDriverIntegration exercises the Azure storage driver end-to-end against an
// Azurite emulator. It is skipped unless AZURITEMOCK_ENDPOINT is set (e.g.
// http://127.0.0.1:10000/devstoreaccount1), mirroring the S3 (S3MOCK_ENDPOINT) and
// GCS (GCSMOCK_ENDPOINT) integration tests.
func TestAzureDriverIntegration(t *testing.T) {
	endpoint := os.Getenv("AZURITEMOCK_ENDPOINT")
	if endpoint == "" {
		t.Skip("AZURITEMOCK_ENDPOINT not set; skipping Azure Blob integration test")
	}

	ctx := context.Background()

	// Ensure the container exists in Azurite.
	connStr := fmt.Sprintf(
		"DefaultEndpointsProtocol=http;AccountName=%s;AccountKey=%s;BlobEndpoint=%s;",
		azuriteAccount, azuriteAccessKey, endpoint)

	client, err := azblob.NewClientFromConnectionString(connStr, nil)
	if err != nil {
		t.Fatalf("azurite client: %v", err)
	}

	if _, err := client.CreateContainer(ctx, azureContainer, nil); err != nil &&
		!strings.Contains(err.Error(), "ContainerAlreadyExists") {
		t.Fatalf("create container: %v", err)
	}

	params := map[string]any{
		"name":        "azure",
		"container":   azureContainer,
		"accountname": azuriteAccount,
		"accountkey":  azuriteAccessKey,
		"serviceurl":  endpoint,
		"credentials": map[string]any{"type": "shared_key"},
	}

	store, err := factory.Create(ctx, "azure", params)
	if err != nil {
		t.Fatalf("create azure driver: %v", err)
	}

	driver := azure.New(store)

	Convey("Azure Blob round-trip through the zot wrapper", t, func() {
		So(driver.Name(), ShouldEqual, "azure")

		Convey("Write/Read/Stat/List/Move/Delete", func() {
			src := "/repo/blob"
			dst := "/repo/blob2"
			payload := []byte("hello azure blob")

			n, err := driver.WriteFile(src, payload)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(payload))

			content, err := driver.ReadFile(src)
			So(err, ShouldBeNil)
			So(string(content), ShouldEqual, string(payload))

			fi, err := driver.Stat(src)
			So(err, ShouldBeNil)
			So(fi.Size(), ShouldEqual, int64(len(payload)))

			list, err := driver.List("/repo")
			So(err, ShouldBeNil)
			So(list, ShouldContain, src)

			err = driver.Move(src, dst)
			So(err, ShouldBeNil)

			// Source is gone: must surface as PathNotFoundError (our error mapping).
			var pathErr storagedriver.PathNotFoundError

			_, err = driver.ReadFile(src)
			So(errors.As(err, &pathErr), ShouldBeTrue)

			err = driver.Delete(dst)
			So(err, ShouldBeNil)

			// Deleting a missing path is idempotent (no error).
			err = driver.Delete(dst)
			So(err, ShouldBeNil)
		})
	})
}
