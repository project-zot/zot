//go:build sync

package sync //nolint:testpackage // white-box test for unexported preseedLocalBlobs/preseedBlob

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// predictTestTag is the tag used by every synthetic image these helpers write to a test store.
const predictTestTag = "latest"

// newTestBaseService builds a minimal *BaseService with just enough wired up (storeController,
// logger) to call preseedLocalBlobs directly, without a real upstream registry.
func newTestBaseService(t *testing.T, storeCtrl storage.StoreController) *BaseService {
	t.Helper()

	return &BaseService{storeController: storeCtrl, log: log.NewTestLogger()}
}

// mustOCIDirRef builds an ocidir:// regclient ref for repoPath:tag, failing the test on error.
func mustOCIDirRef(t *testing.T, repoPath, tag string) ref.Ref {
	t.Helper()

	imageRef, err := ref.New("ocidir://" + repoPath + ":" + tag)
	require.NoError(t, err, "ref.New")

	return imageRef
}

// newTestStore creates a fresh local ImageStore rooted at a temp directory, for tests that need
// a real local store to write manifests/blobs into and read them back from.
func newTestStore(t *testing.T) (string, stypes.StoreController) {
	t.Helper()

	root := t.TempDir()
	logger := log.NewTestLogger()

	store := local.NewImageStore(root, false, false, logger,
		monitoring.NewNopMetricServer(),
		mocks.MockedLint{
			LintFn: func(repo string, manifestDigest godigest.Digest, imageStore stypes.ImageStore) (bool, error) {
				return true, nil
			},
		},
		mocks.CacheMock{},
		[]compat.MediaCompatibility{compat.DockerManifestV2SchemaV2},
		nil,
	)

	return root, storage.StoreController{DefaultStore: store}
}

// repoPath returns the on-disk path for repo under root.
func repoPath(root, repo string) string {
	return filepath.Join(root, repo)
}

// writeOCISingleManifest writes a single-platform OCI image manifest for repo:tag into storeCtrl.
func writeOCISingleManifest(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	image := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	assert.NoError(t, WriteImageToFileSystem(image, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

// writeDockerSingleManifest is writeOCISingleManifest's Docker schema2 counterpart, for tests
// exercising streaming's Docker media-type support (PreserveDigest keeps whatever media type
// upstream actually served, and Docker registries commonly serve schema2, not OCI).
func writeDockerSingleManifest(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	image := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build().AsDockerImage()
	assert.NoError(t, WriteImageToFileSystem(image, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

// platformImages returns one image per platform for building a multi-arch index/list.
func platformImages() []Image {
	return []Image{
		CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm", "linux").Build(),
	}
}

// writeOCIMultiPlatformIndex writes a multi-arch OCI image index for repo:tag into storeCtrl.
func writeOCIMultiPlatformIndex(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	multiarch := CreateMultiarchWith().Images(platformImages()).Build()
	assert.NoError(t, WriteMultiArchImageToFileSystem(multiarch, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func TestPreseedLocalBlobs(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok)

	service := newTestBaseService(t, concrete)

	regClient := regclient.New()
	srcRef := mustOCIDirRef(t, repoPath(root, "repo-a"), predictTestTag)

	man, err := regClient.ManifestGet(context.Background(), srcRef)
	require.NoError(t, err)

	defer regClient.Close(context.Background(), man.GetRef())

	imager, ok := man.(manifest.Imager)
	require.True(t, ok)

	configDesc, err := imager.GetConfig()
	require.NoError(t, err)

	layers, err := imager.GetLayers()
	require.NoError(t, err)

	presentDigests := []godigest.Digest{configDesc.Digest}
	for _, layer := range layers {
		presentDigests = append(presentDigests, layer.Digest)
	}

	// A digest the local store does not have must be skipped without error, not fail the batch.
	missingDigest := godigest.FromString("this blob was never synced")
	blobDigests := append(append([]godigest.Digest{}, presentDigests...), missingDigest)

	localImageRef := mustOCIDirRef(t, path.Join(t.TempDir(), "repo-a"), predictTestTag)

	seeded := service.preseedLocalBlobs(context.Background(), "repo-a", localImageRef, blobDigests)
	assert.Equal(t, len(presentDigests), seeded, "every locally-present digest must be seeded, the missing one skipped")

	imageStore := concrete.GetImageStore("repo-a")

	for _, digest := range presentDigests {
		destPath := path.Join(localImageRef.Path, "blobs", digest.Algorithm().String(), digest.Encoded())

		written, err := os.ReadFile(destPath)
		require.NoError(t, err, "digest %s must have been written to the temp OCI layout", digest)

		srcReader, _, err := imageStore.GetBlob("repo-a", digest, "")
		require.NoError(t, err)

		expected, err := io.ReadAll(srcReader)
		require.NoError(t, err)
		require.NoError(t, srcReader.Close())

		assert.Equal(t, expected, written, "seeded content for %s must match the real local blob", digest)
	}

	missingPath := path.Join(localImageRef.Path, "blobs", missingDigest.Algorithm().String(), missingDigest.Encoded())
	_, err = os.Stat(missingPath)
	assert.True(t, os.IsNotExist(err), "a digest absent from local storage must not be written")

	// Re-seeding onto a destination that already has the file must be a safe no-op.
	seededAgain := service.preseedLocalBlobs(context.Background(), "repo-a", localImageRef, blobDigests)
	assert.Equal(t, len(presentDigests), seededAgain)
}

// singlePresentBlobDigest writes a single-manifest image into repo and returns one of its blob
// digests (the config), which preseedLocalBlobs will find present via CheckBlob.
func singlePresentBlobDigest(t *testing.T, storeCtrl storage.StoreController, root, repo string) godigest.Digest {
	t.Helper()

	writeOCISingleManifest(t, storeCtrl, root, repo, predictTestTag)

	regClient := regclient.New()
	srcRef := mustOCIDirRef(t, repoPath(root, repo), predictTestTag)

	man, err := regClient.ManifestGet(context.Background(), srcRef)
	require.NoError(t, err)

	defer regClient.Close(context.Background(), man.GetRef())

	imager, ok := man.(manifest.Imager)
	require.True(t, ok)

	configDesc, err := imager.GetConfig()
	require.NoError(t, err)

	return configDesc.Digest
}

func TestPreseedLocalBlobsErrorPathsFailOpen(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok)

	service := newTestBaseService(t, concrete)

	digest := singlePresentBlobDigest(t, concrete, root, "repo-a")

	t.Run("destination directory collides with a plain file", func(t *testing.T) {
		t.Parallel()

		localRoot := t.TempDir()
		localImageRef := mustOCIDirRef(t, path.Join(localRoot, "repo-a"), predictTestTag)

		// preseedBlob's target directory is <path>/blobs/<algo>; pre-creating it as a plain file
		// makes its os.MkdirAll fail, which preseedLocalBlobs must treat as fail-open (skip this
		// digest, keep going) rather than propagate the error to the caller.
		blobsDir := path.Join(localImageRef.Path, "blobs")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))
		require.NoError(t, os.WriteFile(path.Join(blobsDir, digest.Algorithm().String()), []byte("not a directory"), 0o600))

		seeded := service.preseedLocalBlobs(context.Background(), "repo-a", localImageRef, []godigest.Digest{digest})
		assert.Equal(t, 0, seeded, "a digest whose destination cannot be created must be skipped, not fail the batch")
	})

	t.Run("destination directory is not writable", func(t *testing.T) {
		t.Parallel()

		localRoot := t.TempDir()
		localImageRef := mustOCIDirRef(t, path.Join(localRoot, "repo-a"), predictTestTag)

		blobAlgoDir := path.Join(localImageRef.Path, "blobs", digest.Algorithm().String())
		require.NoError(t, os.MkdirAll(blobAlgoDir, 0o755))
		require.NoError(t, os.Chmod(blobAlgoDir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(blobAlgoDir, 0o755) }) // restore so t.TempDir() can clean up

		seeded := service.preseedLocalBlobs(context.Background(), "repo-a", localImageRef, []godigest.Digest{digest})
		assert.Equal(t, 0, seeded, "a digest whose destination file cannot be created must be skipped, not fail the batch")
	})
}

func TestPreseedLocalBlobsNoOpCases(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok)

	service := newTestBaseService(t, concrete)

	t.Run("empty blob digest list is a no-op", func(t *testing.T) {
		t.Parallel()

		localImageRef := mustOCIDirRef(t, path.Join(t.TempDir(), "repo"), predictTestTag)
		assert.Equal(t, 0, service.preseedLocalBlobs(context.Background(), "repo", localImageRef, nil))
	})

	t.Run("a ref with no path is a no-op", func(t *testing.T) {
		t.Parallel()

		digests := []godigest.Digest{godigest.FromString("x")}
		assert.Equal(t, 0, service.preseedLocalBlobs(context.Background(), "repo", ref.Ref{}, digests))
	})
}
