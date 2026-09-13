//go:build sync

package sync //nolint:testpackage // white-box helpers shared by this package's internal tests

import (
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/ref"
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

// writeOCISingleManifest writes a single-platform OCI image manifest for repo:predictTestTag into
// storeCtrl.
func writeOCISingleManifest(t *testing.T, storeCtrl stypes.StoreController, repo string) {
	t.Helper()

	image := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	require.NoError(t, WriteImageToFileSystem(image, repo, predictTestTag, storeCtrl))
}

// writeDockerSingleManifest is writeOCISingleManifest's Docker schema2 counterpart, for tests
// exercising streaming's Docker media-type support (PreserveDigest keeps whatever media type
// upstream actually served, and Docker registries commonly serve schema2, not OCI).
func writeDockerSingleManifest(t *testing.T, storeCtrl stypes.StoreController, repo string) {
	t.Helper()

	image := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build().AsDockerImage()
	require.NoError(t, WriteImageToFileSystem(image, repo, predictTestTag, storeCtrl))
}

// platformImages returns one image per platform for building a multi-arch index/list.
func platformImages() []Image {
	return []Image{
		CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm", "linux").Build(),
	}
}

// writeOCIMultiPlatformIndex writes a multi-arch OCI image index for repo:predictTestTag into
// storeCtrl.
func writeOCIMultiPlatformIndex(t *testing.T, storeCtrl stypes.StoreController, repo string) {
	t.Helper()

	multiarch := CreateMultiarchWith().Images(platformImages()).Build()
	require.NoError(t, WriteMultiArchImageToFileSystem(multiarch, repo, predictTestTag, storeCtrl))
}
