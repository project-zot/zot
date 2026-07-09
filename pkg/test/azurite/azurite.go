// Package azurite provides shared setup for tests that run against an Azurite
// (Azure Blob Storage emulator) instance. These tests are gated on the
// AZURITEMOCK_ENDPOINT environment variable, in the same way the S3 tests are
// gated on S3MOCK_ENDPOINT.
package azurite

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// Well-known Azurite development account (https://github.com/Azure/Azurite).
// These are the fixed, publicly documented emulator credentials, not secrets.
const (
	Account = "devstoreaccount1"
	//nolint:gosec // public Azurite development key, not a secret
	AccessKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	Container = "zot-storage-test"
)

// Endpoint returns the Azurite blob endpoint (AZURITEMOCK_ENDPOINT), e.g.
// http://127.0.0.1:10000/devstoreaccount1. It is empty when Azurite is not configured.
func Endpoint() string {
	return os.Getenv("AZURITEMOCK_ENDPOINT")
}

// DriverParams builds the distribution azure driver parameters pointing at
// Azurite, with the given rootdirectory prefix. The shared_key credential type
// uses the emulator account key directly.
func DriverParams(rootDir string) map[string]any {
	return map[string]any{
		"name":          "azure",
		"container":     Container,
		"accountname":   Account,
		"accountkey":    AccessKey,
		"serviceurl":    Endpoint(),
		"rootdirectory": rootDir,
		"credentials":   map[string]any{"type": "shared_key"},
		// Azurite completes server-side copies almost instantly but briefly reports them
		// as pending, so the driver polls every retry_delay. The 100ms default is tuned for
		// real Azure latency and dominates test time (every Move/InitRepo/blob finalize pays
		// it); a short interval against a local emulator keeps the suite fast.
		"retry_delay": "10ms",
	}
}

// EnsureContainer creates the test container in Azurite if it does not already
// exist. It is idempotent, so concurrent test setups can call it safely.
func EnsureContainer() error {
	connStr := fmt.Sprintf(
		"DefaultEndpointsProtocol=http;AccountName=%s;AccountKey=%s;BlobEndpoint=%s;",
		Account, AccessKey, Endpoint())

	client, err := azblob.NewClientFromConnectionString(connStr, nil)
	if err != nil {
		return fmt.Errorf("azurite client: %w", err)
	}

	if _, err := client.CreateContainer(context.Background(), Container, nil); err != nil &&
		!strings.Contains(err.Error(), "ContainerAlreadyExists") {
		return fmt.Errorf("create container: %w", err)
	}

	return nil
}
