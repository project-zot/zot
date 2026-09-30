//go:build sync

package sync //nolint:testpackage // white-box test for BaseService.FetchManifest against a local ocidir "remote"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
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

	fetched, children, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.NoError(t, err)
	assert.Empty(t, children, "a single-platform manifest has no child manifests to stream")
	assert.NotEmpty(t, fetched.GetDescriptor().Digest)
}

func TestFetchManifestMultiArchFetchesEveryChild(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCIMultiPlatformIndex(t, storeCtrl, "repo-multiarch")

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
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	// A prefix that never matches repo-a, so the repo is filtered out.
	content := []syncconf.Content{{Prefix: "some-other-prefix/**"}}
	service := newFetchManifestTestService(root, content, nil)

	_, _, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, zerr.ErrSyncImageFilteredOut)
}

func TestFetchManifestOnlySignedRejectsUnsigned(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	onlySigned := true
	service := newFetchManifestTestService(root, nil, &onlySigned)

	_, _, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
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
	byTag, _, err := newFetchManifestTestService(root, nil, nil).
		FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.NoError(t, err)

	digest := byTag.GetDescriptor().Digest

	fetched, _, err := service.FetchManifest(context.Background(), "repo-a", digest.String())
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

	_, _, err := service.FetchManifest(context.Background(), "repo-a", predictTestTag)
	require.ErrorIs(t, err, errFakeGetImageReference)
}

func TestFetchManifestUpstreamManifestMissing(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCISingleManifest(t, storeCtrl, "repo-a")

	service := newFetchManifestTestService(root, nil, nil)

	_, _, err := service.FetchManifest(context.Background(), "repo-a", "this-tag-was-never-written")
	require.Error(t, err)
}

// TestFetchManifestNestedIndexReturnsLeaves: an index whose child is itself an index (a shape sync
// supports) resolves to the leaf image manifests, which are what staging streams.
func TestFetchManifestNestedIndexReturnsLeaves(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	writeOCIMultiPlatformIndex(t, storeCtrl, "repo-nested")

	ctx := context.Background()
	regClient := regclient.New()

	innerRef := mustOCIDirRef(t, repoPath(root, "repo-nested"), predictTestTag)

	inner, err := regClient.ManifestGet(ctx, innerRef)
	require.NoError(t, err)

	innerIndexer, ok := inner.(manifest.Indexer)
	require.True(t, ok)

	leafDescs, err := innerIndexer.GetManifestList()
	require.NoError(t, err)

	// Outer index: the inner index, plus one of its leaves again to check it isn't fetched twice.
	innerDesc := inner.GetDescriptor()
	outerBody, err := json.Marshal(ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{
			{MediaType: innerDesc.MediaType, Digest: innerDesc.Digest, Size: innerDesc.Size},
			{MediaType: leafDescs[0].MediaType, Digest: leafDescs[0].Digest, Size: leafDescs[0].Size},
		},
	})
	require.NoError(t, err)

	outer, err := manifest.New(manifest.WithRaw(outerBody))
	require.NoError(t, err)

	require.NoError(t, regClient.ManifestPut(ctx, mustOCIDirRef(t, repoPath(root, "repo-nested"), "outer"), outer))

	service := newFetchManifestTestService(root, nil, nil)

	fetched, children, err := service.FetchManifest(ctx, "repo-nested", "outer")
	require.NoError(t, err)
	assert.Equal(t, outer.GetDescriptor().Digest, fetched.GetDescriptor().Digest)

	gotDigests := make([]godigest.Digest, 0, len(children))
	for _, child := range children {
		assert.False(t, child.IsList(), "only leaf image manifests may be returned for staging")

		gotDigests = append(gotDigests, child.GetDescriptor().Digest)
	}

	wantDigests := make([]godigest.Digest, 0, len(leafDescs))
	for _, desc := range leafDescs {
		wantDigests = append(wantDigests, desc.Digest)
	}

	assert.ElementsMatch(t, wantDigests, gotDigests)
}
