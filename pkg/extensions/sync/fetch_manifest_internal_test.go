//go:build sync

package sync //nolint:testpackage // white-box test for BaseService.FetchManifest against a local ocidir "remote"

import (
	"context"
	"errors"
	"fmt"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

var errFakeGetImageReference = errors.New("fake: GetImageReference deliberately failed")

// fakeFetchManifestRemote is a minimal Remote whose GetImageReference resolves onto a local
// ocidir tree (as written by newTestStore/writeOCISingleManifest et al), so FetchManifest's real
// production code (content filtering, OnlySigned enforcement, multi-arch child fetching) can be
// exercised against a real regclient.RegClient without a network listener. Only GetHostName and
// GetImageReference are ever called by FetchManifest; the rest of the Remote interface is unused
// stubs.
type fakeFetchManifestRemote struct {
	root string
	// errRepo, when non-empty, makes GetImageReference fail for that one repo - used to exercise
	// FetchManifest's remote.GetImageReference error path.
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

func (f *fakeFetchManifestRemote) GetOCIDigest(_ context.Context, _, _ string,
) (godigest.Digest, godigest.Digest, bool, []godigest.Digest, error) {
	return "", "", false, nil, nil
}

func (f *fakeFetchManifestRemote) GetDigest(_ context.Context, _, _ string) (godigest.Digest, error) {
	return "", nil
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
	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	service := newFetchManifestTestService(root, nil, nil)

	fetched, children, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.NoError(t, err)
	assert.Empty(t, children, "a single-platform manifest has no child manifests to stream")
	assert.NotEmpty(t, fetched.GetDescriptor().Digest)
}

func TestFetchManifestMultiArchFetchesEveryChild(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCIMultiPlatformIndex(t, storeCtrl, root, "repo-multiarch", predictTestTag)

	service := newFetchManifestTestService(root, nil, nil)

	fetched, children, err := service.FetchManifest(context.Background(), "repo-multiarch", predictTestTag)
	require.NoError(t, err)
	require.True(t, fetched.IsList())

	indexer, ok := fetched.(manifest.Indexer)
	require.True(t, ok)

	descriptors, err := indexer.GetManifestList()
	require.NoError(t, err)

	assert.Len(t, children, len(descriptors),
		"every child manifest referenced by the index must have been fetched")

	for i, child := range children {
		assert.Equal(t, descriptors[i].Digest, child.GetDescriptor().Digest, "child %d digest mismatch", i)
	}
}

func TestFetchManifestContentFilteredOut(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	// A Content rule whose Prefix never matches "repo-a" makes GetRepoSource return "", which
	// FetchManifest must treat as "this repo is filtered out", not attempt to fetch anyway.
	content := []syncconf.Content{{Prefix: "some-other-prefix/**"}}
	service := newFetchManifestTestService(root, content, nil)

	_, _, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, zerr.ErrSyncImageFilteredOut)
}

func TestFetchManifestOnlySignedRejectsUnsigned(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	onlySigned := true
	service := newFetchManifestTestService(root, nil, &onlySigned)

	_, _, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, zerr.ErrSyncImageNotSigned)
}

func TestFetchManifestGetImageReferenceError(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	logger := log.NewTestLogger()
	service := &BaseService{
		remote:         &fakeFetchManifestRemote{root: root, errRepo: "repo-a"},
		rc:             regclient.New(),
		contentManager: NewContentManager(nil, logger),
		log:            logger,
	}

	_, _, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, errFakeGetImageReference)
}

func TestFetchManifestUpstreamManifestMissing(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	service := newFetchManifestTestService(root, nil, nil)

	_, _, err := service.FetchManifest(context.Background(), "repo-a", "this-tag-was-never-written")
	require.Error(t, err)
}
