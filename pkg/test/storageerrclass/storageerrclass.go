// Package storageerrclass provides the shared plumbing for storage error-class
// integration tests: a hook driver that wraps a real storage backend, the list of
// backends those tests run against, and an image store builder.
//
// The hook driver produces two kinds of failures:
//   - real races (a delete at the moment a concurrent writer could, or a List that
//     omits one live entry once), so Missing always comes from the backend itself;
//   - single-op class injection (a Fault), which returns an errclass-marked error for
//     one operation on one path without touching the backend, for Transient and
//     Permanent outages that real emulators cannot produce on demand.
package storageerrclass

import (
	"context"
	"io"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/gcs"    // register the gcs factory
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws" // register the s3 factory
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/azure"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/azurite"
	"zotregistry.dev/zot/v2/pkg/test/gcsemulator"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

// Op names a storage driver operation a Fault can target.
type Op string

const (
	OpList     Op = "List"
	OpStat     Op = "Stat"
	OpWalk     Op = "Walk"
	OpReadFile Op = "ReadFile"
	OpReader   Op = "Reader"
	OpDelete   Op = "Delete"
)

// Fault makes Op on Path return Err without calling the backend. Times limits how
// many calls fail; zero means every call until the fault is cleared.
type Fault struct {
	Op    Op
	Path  string
	Err   error
	Times int
}

// HookDriver wraps a real storage driver and injects real-driver races and faults.
type HookDriver struct {
	storageTypes.Driver

	// DeleteOnVisit deletes this path when Walk visits it, before the walk callback runs.
	DeleteOnVisit string
	// DeleteAfterListOf deletes DeleteTarget right after a successful List of this path.
	DeleteAfterListOf string
	DeleteTarget      string
	// OmitListEntry is dropped from the next List result that contains it, while the
	// object stays on the backend (eventual-consistency inventory lag).
	OmitListEntry string

	mu     sync.Mutex
	faults []Fault
}

// AddFault arms a fault.
func (d *HookDriver) AddFault(fault Fault) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.faults = append(d.faults, fault)
}

// ClearFaults disarms every fault.
func (d *HookDriver) ClearFaults() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.faults = nil
}

func (d *HookDriver) fault(operation Op, target string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := range d.faults {
		fault := &d.faults[i]
		if fault.Op != operation || fault.Path != target {
			continue
		}

		err := fault.Err

		if fault.Times > 0 {
			fault.Times--

			if fault.Times == 0 {
				d.faults = append(d.faults[:i], d.faults[i+1:]...)
			}
		}

		return err
	}

	return nil
}

func (d *HookDriver) Walk(dir string, walkFn driver.WalkFn) error {
	if err := d.fault(OpWalk, dir); err != nil {
		return err
	}

	return d.Driver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if d.DeleteOnVisit != "" && fileInfo.Path() == d.DeleteOnVisit {
			target := d.DeleteOnVisit
			d.DeleteOnVisit = ""

			if err := d.Driver.Delete(target); err != nil {
				return err
			}
		}

		return walkFn(fileInfo)
	})
}

func (d *HookDriver) List(dir string) ([]string, error) {
	if err := d.fault(OpList, dir); err != nil {
		return nil, err
	}

	entries, err := d.Driver.List(dir)
	if err != nil {
		return entries, err
	}

	if d.DeleteAfterListOf != "" && dir == d.DeleteAfterListOf {
		d.DeleteAfterListOf = ""

		if delErr := d.Driver.Delete(d.DeleteTarget); delErr != nil {
			return nil, delErr
		}
	}

	if d.OmitListEntry != "" {
		filtered := make([]string, 0, len(entries))
		omitted := false

		for _, entry := range entries {
			if entry == d.OmitListEntry {
				omitted = true

				continue
			}

			filtered = append(filtered, entry)
		}

		if omitted {
			d.OmitListEntry = ""

			return filtered, nil
		}
	}

	return entries, nil
}

func (d *HookDriver) Stat(target string) (driver.FileInfo, error) {
	if err := d.fault(OpStat, target); err != nil {
		return nil, err
	}

	return d.Driver.Stat(target)
}

func (d *HookDriver) ReadFile(target string) ([]byte, error) {
	if err := d.fault(OpReadFile, target); err != nil {
		return nil, err
	}

	return d.Driver.ReadFile(target)
}

func (d *HookDriver) Reader(target string, offset int64) (io.ReadCloser, error) {
	if err := d.fault(OpReader, target); err != nil {
		return nil, err
	}

	return d.Driver.Reader(target, offset)
}

func (d *HookDriver) Delete(target string) error {
	if err := d.fault(OpDelete, target); err != nil {
		return err
	}

	return d.Driver.Delete(target)
}

// Backend describes one real storage backend the error-class tests run against.
type Backend struct {
	Name string
	// Build returns the base driver and root directory; it skips the test when the
	// backend is not available.
	Build func(t *testing.T) (storageTypes.Driver, string)
	// WalkAbortsOnNestedMissing: DeleteOnVisit mid-walk aborts as Transient.
	// Local List of a removed dir fails hard. Azure and GCS WalkFallback empty
	// nested List returns PathNotFound and aborts. S3 flat Walk never truncates.
	WalkAbortsOnNestedMissing bool
	// SupportsRealPermanent: the backend can produce a real Permanent error (local
	// chmod 000) in addition to injected ones.
	SupportsRealPermanent bool
}

// IsLocal reports whether the backend is the local filesystem.
func (b Backend) IsLocal() bool {
	return b.Name == "Local"
}

// Local is the local filesystem backend.
func Local() Backend {
	return Backend{Name: "Local", Build: buildLocal, WalkAbortsOnNestedMissing: true, SupportsRealPermanent: true}
}

// S3 is the S3 backend. It skips without S3MOCK_ENDPOINT.
func S3() Backend {
	return Backend{Name: "S3", Build: buildS3}
}

// Azure is the Azure Blob backend. It skips without AZURITEMOCK_ENDPOINT.
func Azure() Backend {
	return Backend{Name: "Azure", Build: buildAzure, WalkAbortsOnNestedMissing: true}
}

// GCS is the Google Cloud Storage backend. It skips without STORAGE_EMULATOR_HOST.
// WalkAbortsOnNestedMissing is true: DeleteOnVisit empties the prefix, so the
// next nested List is PathNotFound and WalkFallback aborts as Transient (same
// as Azure).
func GCS() Backend {
	return Backend{Name: "GCS", Build: buildGCS, WalkAbortsOnNestedMissing: true}
}

// Backends returns Local, S3, Azure and GCS. S3, Azure and GCS skip without
// their emulator endpoints.
func Backends() []Backend {
	return []Backend{Local(), S3(), Azure(), GCS()}
}

func buildLocal(t *testing.T) (storageTypes.Driver, string) {
	t.Helper()

	return local.New(true), t.TempDir()
}

func buildS3(t *testing.T) (storageTypes.Driver, string) {
	t.Helper()
	tskip.SkipS3(t)

	rootDir := path.Join("/oci-repo-test", NewUUID(t))
	bucket := "zot-storage-test"
	endpoint := os.Getenv("S3MOCK_ENDPOINT")

	s3Driver, err := factory.Create(context.Background(), storageConstants.S3StorageDriverName, map[string]any{
		"rootDir":        rootDir,
		"name":           "s3",
		"region":         "us-east-2",
		"bucket":         bucket,
		"regionendpoint": endpoint,
		"accesskey":      "minioadmin",
		"secretkey":      "minioadmin",
		"secure":         false,
		"skipverify":     false,
		"forcepathstyle": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := resty.R().Put("http://" + endpoint + "/" + bucket); err != nil {
		t.Fatal(err)
	}

	return s3.New(s3Driver), rootDir
}

func buildAzure(t *testing.T) (storageTypes.Driver, string) {
	t.Helper()
	tskip.SkipAzure(t)

	params := azurite.DriverParams(path.Join("/oci-repo-test", NewUUID(t)))
	storage.NormalizeRootDirectory(storageConstants.AzureStorageDriverName, params)

	azureDriver, err := factory.Create(context.Background(), storageConstants.AzureStorageDriverName, params)
	if err != nil {
		t.Fatal(err)
	}

	if err := azurite.EnsureContainer(); err != nil {
		t.Fatal(err)
	}

	return azure.New(azureDriver), storage.RootDir(storageConstants.AzureStorageDriverName, params)
}

func buildGCS(t *testing.T) (storageTypes.Driver, string) {
	t.Helper()
	tskip.SkipGCS(t)

	const bucket = "zot-storage-test"

	if err := gcsemulator.CreateBucket(bucket); err != nil {
		t.Fatal(err)
	}

	params := map[string]any{
		"rootdirectory": path.Join("/oci-repo-test", NewUUID(t)),
		"name":          storageConstants.GCSStorageDriverName,
		"bucket":        bucket,
	}
	storage.NormalizeRootDirectory(storageConstants.GCSStorageDriverName, params)

	gcsDriver, err := factory.Create(context.Background(), storageConstants.GCSStorageDriverName, params)
	if err != nil {
		t.Fatal(err)
	}

	return gcs.New(gcsDriver), storage.RootDir(storageConstants.GCSStorageDriverName, params)
}

// NewStore builds an image store on the backend, wrapped in a HookDriver. The root
// directory is deleted when the test ends.
func NewStore(t *testing.T, backend Backend) (storageTypes.ImageStore, *HookDriver) {
	t.Helper()

	base, rootDir := backend.Build(t)

	t.Cleanup(func() { _ = base.Delete(rootDir) })

	hooks := &HookDriver{Driver: base}
	imgStore := imagestore.NewImageStore(rootDir, t.TempDir(), false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, hooks, nil, nil, nil)

	return imgStore, hooks
}

// BlobPath is the storage path of a blob in an OCI layout repository.
func BlobPath(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest) string {
	return path.Join(imgStore.RootDir(), repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
}

// NewUUID returns a random UUID string, failing the test on error.
func NewUUID(t *testing.T) string {
	t.Helper()

	uuid, err := guuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}

	return uuid.String()
}
