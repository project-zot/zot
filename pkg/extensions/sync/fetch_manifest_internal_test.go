//go:build sync

package sync //nolint:testpackage // white-box test for BaseService.FetchManifest against a local ocidir "remote"

import (
	"context"
	"errors"
	"fmt"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

var errFakeGetImageReference = errors.New("fake: GetImageReference deliberately failed")

// fakeFetchManifestRemote resolves images onto a local ocidir tree, so the real FetchManifest runs
// against a real regclient without a network. FetchManifest only calls GetHostName and
// GetImageReference; the rest are stubs.
type fakeFetchManifestRemote struct {
	root string
	// errRepo, if set, makes GetImageReference fail for that repo.
	errRepo string
}

func (f *fakeFetchManifestRemote) GetHostName() string { return "fake-upstream" }

func (f *fakeFetchManifestRemote) GetImageReference(repo, reference string) (ref.Ref, error) {
	if repo == f.errRepo {
		return ref.Ref{}, errFakeGetImageReference
	}

	if digest, ok := parseReference(reference); ok {
		return ref.New(fmt.Sprintf("ocidir://%s@%s", repoPath(f.root, repo), digest.String()))
	}

	return ref.New(fmt.Sprintf("ocidir://%s:%s", repoPath(f.root, repo), reference))
}

func (f *fakeFetchManifestRemote) GetRepositories(_ context.Context) ([]string, error) {
	return nil, nil
}

func (f *fakeFetchManifestRemote) GetTags(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (f *fakeFetchManifestRemote) HeadManifest(_ context.Context, _, _ string) (godigest.Digest, string, error) {
	return "", "", nil
}

func (f *fakeFetchManifestRemote) HeadManifestRef(_ context.Context, _ ref.Ref) (godigest.Digest, string, error) {
	return "", "", nil
}

func (f *fakeFetchManifestRemote) GetManifestList(_ context.Context, _, _ string) ([]descriptor.Descriptor, error) {
	return nil, nil
}

func newFetchManifestTestService(root string, content []syncconf.Content, onlySigned *bool) *BaseService {
	logger := log.NewTestLogger()

	return &BaseService{
		remote:         &fakeFetchManifestRemote{root: root},
		rc:             regclient.New(),
		contentManager: NewContentManager(content, logger),
		log:            logger,
		tagsCache:      newTagsCache(defaultExpireMinutes),
		config:         syncconf.RegistryConfig{Content: content, OnlySigned: onlySigned},
	}
}

func TestFetchManifestHappyPath(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	service := newFetchManifestTestService(root, nil, nil)

	fetched, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.NoError(t, err)
	assert.NotEmpty(t, fetched.GetDescriptor().Digest)
}

// TestFetchManifestMultiArchFetchesOnlyTheIndex: the index's platform manifests are left for the
// client to request, as with a plain on-demand sync.
func TestFetchManifestMultiArchFetchesOnlyTheIndex(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCIMultiPlatformIndex(t, storeCtrl, "repo-multiarch")

	service := newFetchManifestTestService(root, nil, nil)

	fetched, err := service.FetchManifest(context.Background(), "repo-multiarch", predictTestTag)
	require.NoError(t, err)
	assert.True(t, fetched.IsList())
}

func TestFetchManifestContentFilteredOut(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	// A prefix that never matches repo-a, so the repo is filtered out.
	content := []syncconf.Content{{Prefix: "some-other-prefix/**"}}
	service := newFetchManifestTestService(root, content, nil)

	_, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, zerr.ErrSyncImageFilteredOut)
}

func TestFetchManifestOnlySignedRejectsUnsigned(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	onlySigned := true
	service := newFetchManifestTestService(root, nil, &onlySigned)

	_, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, zerr.ErrSyncImageNotSigned)
}

// TestFetchManifestOnlySignedAllowsDigestPull: like SyncImage, a digest pull skips OnlySigned,
// since a client following a signed index pulls its unsigned platform manifests by digest.
func TestFetchManifestOnlySignedAllowsDigestPull(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	onlySigned := true
	service := newFetchManifestTestService(root, nil, &onlySigned)

	// Resolve the digest with the check off, then pull by digest with it on.
	byTag, err := newFetchManifestTestService(root, nil, nil).
		FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.NoError(t, err)

	digest := byTag.GetDescriptor().Digest

	fetched, err := service.FetchManifest(context.Background(), "repo-a", digest.String())
	require.NoError(t, err)
	assert.Equal(t, digest, fetched.GetDescriptor().Digest)
}

func TestFetchManifestGetImageReferenceError(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	logger := log.NewTestLogger()
	service := &BaseService{
		remote:         &fakeFetchManifestRemote{root: root, errRepo: "repo-a"},
		rc:             regclient.New(),
		contentManager: NewContentManager(nil, logger),
		log:            logger,
	}

	_, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, errFakeGetImageReference)
}

func TestFetchManifestUpstreamManifestMissing(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	service := newFetchManifestTestService(root, nil, nil)

	_, err := service.FetchManifest(context.Background(), "repo-a", "this-tag-was-never-written")
	require.Error(t, err)
}
