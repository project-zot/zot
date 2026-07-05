//go:build sync

package sync //nolint:testpackage // white-box tests for unexported predictOCIDigest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dockerList "github.com/distribution/distribution/v3/manifest/manifestlist"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/mod"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

const predictTestTag = "latest"

func TestPredictOCIDigestMatchesRegclient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	regClient := regclient.New()

	storeRoot, storeCtrl := newTestStore(t)

	ociIndexPath := writeOCIMultiPlatformIndex(t, storeCtrl, storeRoot, "oci-index", predictTestTag)
	ociSinglePath := writeOCISingleManifest(t, storeCtrl, storeRoot, "oci-single", predictTestTag)
	ociArtifactPath := writeOCIArtifactManifest(t, storeCtrl, storeRoot, "oci-artifact", predictTestTag)

	cases := []struct {
		name string
		ref  ref.Ref
	}{
		{
			name: "oci multi-platform index",
			ref:  mustOCIDirRef(t, ociIndexPath, predictTestTag),
		},
		{
			name: "oci single manifest",
			ref:  mustOCIDirRef(t, ociSinglePath, predictTestTag),
		},
		{
			name: "oci artifact with oci subject",
			ref:  mustOCIDirRef(t, ociArtifactPath, predictTestTag),
		},
		{
			name: "oci artifact with docker subject",
			ref: mustOCIDirRef(t, writeArtifactWithSubject(t, storeCtrl, storeRoot, "artifact-oci-docker-subject",
				predictTestTag, false, true), predictTestTag),
		},
		{
			name: "docker artifact with oci subject",
			ref: mustOCIDirRef(t, writeArtifactWithSubject(t, storeCtrl, storeRoot, "artifact-docker-oci-subject",
				predictTestTag, true, false), predictTestTag),
		},
		{
			name: "docker artifact with docker subject",
			ref: mustOCIDirRef(t, writeArtifactWithSubject(t, storeCtrl, storeRoot, "artifact-docker-docker-subject",
				predictTestTag, true, true), predictTestTag),
		},
		{
			name: "docker manifest list converted from oci index",
			ref:  dockerConvertedFromOCI(t, regClient, ctx, ociIndexPath, predictTestTag),
		},
		{
			name: "docker single manifest converted from oci",
			ref:  dockerConvertedFromOCI(t, regClient, ctx, ociSinglePath, predictTestTag),
		},
		{
			name: "docker manifest list",
			ref: mustOCIDirRef(t,
				writeDockerMultiPlatformIndex(t, storeCtrl, storeRoot, "docker-list", predictTestTag),
				predictTestTag),
		},
		{
			name: "oci index with docker children",
			ref: mustOCIDirRef(t,
				writeHybridOCIIndexDockerChildren(t, storeCtrl, storeRoot, "hybrid-oci-docker", predictTestTag),
				predictTestTag),
		},
		{
			name: "oci index with oci manifest children and docker interior",
			ref: mustOCIDirRef(t,
				writeHybridOCIIndexOCIChildrenDockerInterior(t, "hybrid-oci-oci-docker-interior", predictTestTag),
				predictTestTag),
		},
		{
			name: "docker manifest list with oci children",
			ref:  mustOCIDirRef(t, writeHybridDockerIndexOCIChildren(t, "hybrid-docker-oci", predictTestTag), predictTestTag),
		},
		{
			name: "oci index with docker referrer annotations",
			ref: mustOCIDirRef(t,
				writeOCIIndexWithDockerReferrerAnnotations(t, "docker-referrer-index", predictTestTag),
				predictTestTag),
		},
		{
			name: "oci index with docker referrer pointing to external subject",
			ref: mustOCIDirRef(t,
				writeOCIIndexWithDockerReferrerExternalSubject(t, "docker-referrer-external-subject", predictTestTag),
				predictTestTag),
		},
		{
			name: "three level nested OCI+OCI+OCI",
			ref:  mustNestedIndexRef(t, "nested-oci-oci-oci", flavorOCI, flavorOCI, flavorOCI),
		},
		{
			name: "three level nested OCI+OCI+Docker",
			ref:  mustNestedIndexRef(t, "nested-oci-oci-docker", flavorOCI, flavorOCI, flavorDocker),
		},
		{
			name: "three level nested OCI+Docker+OCI",
			ref:  mustNestedIndexRef(t, "nested-oci-docker-oci", flavorOCI, flavorDocker, flavorOCI),
		},
		{
			name: "three level nested Docker+OCI+OCI",
			ref:  mustNestedIndexRef(t, "nested-docker-oci-oci", flavorDocker, flavorOCI, flavorOCI),
		},
		{
			name: "three level nested OCI+Docker+Docker",
			ref:  mustNestedIndexRef(t, "nested-oci-docker-docker", flavorOCI, flavorDocker, flavorDocker),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertPredictMatchesRegclientApply(t, ctx, regClient, tc.ref)
		})
	}
}

func TestPredictOCIDigestManifestTreeLimits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	regClient := regclient.New()

	t.Run("manifest tree walk guards", func(t *testing.T) {
		t.Parallel()

		t.Run("rejects child already on path", func(t *testing.T) {
			t.Parallel()

			state := &manifestTreeWalkState{path: map[string]struct{}{"sha256:abc": {}}}

			err := state.checkChild("sha256:abc")
			require.ErrorIs(t, err, errManifestTreeCycle)
		})

		t.Run("rejects depth limit", func(t *testing.T) {
			t.Parallel()

			state := &manifestTreeWalkState{depth: maxManifestTreeDepth}

			err := state.beginNode(false)
			require.ErrorIs(t, err, errManifestTreeLimitExceeded)
			assert.Contains(t, err.Error(), "depth")
		})

		t.Run("rejects node count limit", func(t *testing.T) {
			t.Parallel()

			state := &manifestTreeWalkState{nodeCount: maxManifestTreeNodes}

			err := state.beginNode(true)
			require.ErrorIs(t, err, errManifestTreeLimitExceeded)
			assert.Contains(t, err.Error(), "node count")
		})
	})

	t.Run("depth limit exceeded", func(t *testing.T) {
		t.Parallel()

		srcRef := mustOCIDirRef(t, writeDeepIndexChain(t, "deep-index-chain", predictTestTag, maxManifestTreeDepth+1),
			predictTestTag)

		_, _, _, err := predictOCIDigest(ctx, regClient, srcRef)
		require.Error(t, err)
		require.ErrorIs(t, err, errManifestTreeLimitExceeded)
		assert.Contains(t, err.Error(), "depth")
	})

	t.Run("node count limit exceeded", func(t *testing.T) {
		t.Parallel()

		srcRef := mustOCIDirRef(t, writeWideOCIIndex(t, "wide-index", predictTestTag, maxManifestTreeNodes+1),
			predictTestTag)

		_, _, _, err := predictOCIDigest(ctx, regClient, srcRef)
		require.Error(t, err)
		require.ErrorIs(t, err, errManifestTreeLimitExceeded)
		assert.Contains(t, err.Error(), "node count")
	})

	t.Run("docker referrer annotations still match regclient", func(t *testing.T) {
		t.Parallel()

		srcRef := mustOCIDirRef(t,
			writeOCIIndexWithDockerReferrerAnnotations(t, "docker-referrer-with-limits", predictTestTag),
			predictTestTag)
		assertPredictMatchesRegclientApply(t, ctx, regClient, srcRef)
	})

	t.Run("docker referrer external subject still matches regclient", func(t *testing.T) {
		t.Parallel()

		srcRef := mustOCIDirRef(t,
			writeOCIIndexWithDockerReferrerExternalSubject(t, "docker-referrer-external-with-limits", predictTestTag),
			predictTestTag)
		assertPredictMatchesRegclientApply(t, ctx, regClient, srcRef)
	})

	t.Run("deep valid index within limits", func(t *testing.T) {
		t.Parallel()

		srcRef := mustOCIDirRef(t, writeDeepIndexChain(t, "deep-index-valid", predictTestTag, maxManifestTreeDepth-1),
			predictTestTag)
		assertPredictMatchesRegclientApply(t, ctx, regClient, srcRef)
	})
}

func TestPredictOCIDigestErrorPaths(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	regClient := regclient.New()

	t.Run("unsupported root media type", func(t *testing.T) {
		t.Parallel()

		srcRef := mustOCIDirRef(t, writeUnsupportedRootMediaType(t, "unsupported-root", predictTestTag), predictTestTag)

		_, _, _, err := predictOCIDigest(ctx, regClient, srcRef)
		require.Error(t, err)
		require.True(t, errors.Is(err, zerr.ErrMediaTypeNotSupported) || strings.Contains(err.Error(), "unsupported media type"))
	})

	t.Run("fetchManifestNode rejects digest already on path", func(t *testing.T) {
		t.Parallel()

		storeRoot, storeCtrl := newTestStore(t)
		repoPath := writeOCISingleManifest(t, storeCtrl, storeRoot, "cycle-enter", predictTestTag)
		srcRef := mustOCIDirRef(t, repoPath, predictTestTag)

		man, err := regClient.ManifestGet(ctx, srcRef)
		require.NoError(t, err)
		defer regClient.Close(ctx, man.GetRef())

		walkState := &manifestTreeWalkState{
			path: map[string]struct{}{man.GetDescriptor().Digest.String(): {}},
		}

		_, err = fetchManifestNode(ctx, regClient, srcRef, true, walkState)
		require.ErrorIs(t, err, errManifestTreeCycle)
	})
}

func TestPredictOCIDigestDockerLayerMediaTypes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	regClient := regclient.New()
	srcRef := mustOCIDirRef(t, writeDockerManifestVariedLayers(t, "docker-layer-types", predictTestTag), predictTestTag)

	assertPredictMatchesRegclientApply(t, ctx, regClient, srcRef)
}

func TestManifestNodeHelpers(t *testing.T) {
	t.Parallel()

	t.Run("closeManifestTree nil", func(t *testing.T) {
		t.Parallel()

		closeManifestTree(context.Background(), regclient.New(), nil)
	})

	t.Run("effectiveDesc falls back to origDesc", func(t *testing.T) {
		t.Parallel()

		orig := descriptor.Descriptor{Digest: godigest.FromString("sha256:" + strings.Repeat("a", 64))}
		node := &manifestNode{mod: manifestDeleted, origDesc: orig}

		assert.Equal(t, orig.Digest, node.effectiveDesc().Digest)
	})
}

func mustNestedIndexRef(t *testing.T, repo string, root, mid, leaf indexFlavor) ref.Ref {
	t.Helper()

	return mustOCIDirRef(t, writeThreeLevelNestedIndex(t, repo, root, mid, leaf), predictTestTag)
}

func assertPredictMatchesRegclientApply(
	t *testing.T, ctx context.Context, regClient *regclient.RegClient, srcRef ref.Ref,
) {
	t.Helper()

	predicted, original, isConverted, predictErr := predictOCIDigest(ctx, regClient, srcRef)
	applied, applyErr := regclientApplyOCIDigest(t, ctx, regClient, srcRef)

	require.Equal(t, predictErr != nil, applyErr != nil,
		"error parity: predictOCIDigest=%v regclient mod.Apply=%v", predictErr, applyErr)

	if predictErr != nil {
		return
	}

	assert.Equal(t, applied.String(), predicted.String(), "digest mismatch")

	if isConverted {
		assert.NotEqual(t, original.String(), predicted.String(), "isConverted true but digest unchanged")
	} else {
		assert.Equal(t, original.String(), predicted.String(), "isConverted false but digest changed")
	}
}

// regclientApplyOCIDigest copies src to a fresh ocidir and runs the same mod.Apply options as sync.
func regclientApplyOCIDigest(
	t *testing.T, ctx context.Context, regClient *regclient.RegClient, srcRef ref.Ref,
) (godigest.Digest, error) {
	t.Helper()

	workDir := t.TempDir()

	repo := srcRef.Repository
	tag := srcRef.Tag
	if tag == "" {
		tag = predictTestTag
	}

	tgtRef, err := ref.New("ocidir://" + filepath.Join(workDir, repo) + ":" + tag)
	if err != nil {
		return "", err
	}

	if err := regClient.ImageCopy(ctx, srcRef, tgtRef); err != nil {
		return "", err
	}

	convertedRef, err := mod.Apply(ctx, regClient, tgtRef,
		mod.WithRefTgt(tgtRef),
		mod.WithManifestToOCI(),
		mod.WithManifestToOCIReferrers(),
	)
	if err != nil {
		return "", err
	}

	man, err := regClient.ManifestGet(ctx, convertedRef)
	if err != nil {
		return "", err
	}
	defer regClient.Close(ctx, man.GetRef())

	return man.GetDescriptor().Digest, nil
}

func dockerConvertedFromOCI(
	t *testing.T, regClient *regclient.RegClient, ctx context.Context, ociRepoPath, tag string,
) ref.Ref {
	t.Helper()

	tempDir := t.TempDir()
	ociRef := mustOCIDirRef(t, ociRepoPath, tag)

	dockerRepoPath := filepath.Join(tempDir, "docker")
	dockerRef := mustOCIDirRef(t, dockerRepoPath, tag)

	if !assert.NoError(t, regClient.ImageCopy(ctx, ociRef, dockerRef), "ImageCopy to docker layout") {
		t.FailNow()
	}

	converted, err := mod.Apply(ctx, regClient, dockerRef,
		mod.WithRefTgt(dockerRef),
		mod.WithManifestToDocker(),
	)
	if !assert.NoError(t, err, "mod.WithManifestToDocker") {
		t.FailNow()
	}

	return converted
}

func mustOCIDirRef(t *testing.T, repoPath, tag string) ref.Ref {
	t.Helper()

	imageRef, err := ref.New("ocidir://" + repoPath + ":" + tag)
	if !assert.NoError(t, err, "ref.New") {
		t.FailNow()
	}

	return imageRef
}

func newTestStore(t *testing.T) (string, stypes.StoreController) {
	t.Helper()

	root := t.TempDir()
	logger := log.NewTestLogger()

	store := local.NewImageStore(root, false, false, logger,
		monitoring.NewMetricsServer(false, logger),
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

func repoPath(root, repo string) string {
	return filepath.Join(root, repo)
}

func platformImages() []Image {
	return []Image{
		CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm", "linux").Build(),
	}
}

func platformImagesPair() []Image {
	return []Image{
		CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build(),
		CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build(),
	}
}

type indexFlavor int

const (
	flavorOCI indexFlavor = iota
	flavorDocker
)

func (f indexFlavor) indexMediaType() string {
	if f == flavorDocker {
		return dockerList.MediaTypeManifestList
	}

	return ispec.MediaTypeImageIndex
}

func writeArtifactWithSubject(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string,
	artifactDocker, subjectDocker bool,
) string {
	t.Helper()

	subject := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	if subjectDocker {
		subject = subject.AsDockerImage()
	}

	assert.NoError(t, WriteImageToFileSystem(subject, repo, subject.DigestStr(), storeCtrl))

	artifact := CreateImageWith().EmptyLayer().EmptyConfig().
		Subject(subject.DescriptorRef()).
		ArtifactType("application/example.sbom").
		Build()
	if artifactDocker {
		artifact = artifact.AsDockerImage()
	}

	assert.NoError(t, WriteImageToFileSystem(artifact, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func writeThreeLevelNestedIndex(t *testing.T, repo string, root, mid, leaf indexFlavor) string {
	t.Helper()

	inner := buildInnerMultiarch(mid, leaf)
	midIndex := wrapIndexDescriptor(inner.IndexDescriptor, mid)
	rootIndex := wrapIndexDescriptor(midIndex, root)

	return writeNestedIndexLayoutDirect(t, t.TempDir(), repo, predictTestTag, inner.Images,
		inner.IndexDescriptor, midIndex, rootIndex)
}

func buildInnerMultiarch(mid, leaf indexFlavor) MultiarchImage {
	images := platformImagesPair()
	if leaf == flavorDocker {
		for i := range images {
			images[i] = images[i].AsDockerImage()
		}
	}

	multiarch := CreateMultiarchWith().Images(images).Build()

	switch {
	case mid == flavorOCI && leaf == flavorDocker:
		multiarch.Index.MediaType = ispec.MediaTypeImageIndex

		for i := range multiarch.Index.Manifests {
			multiarch.Index.Manifests[i].MediaType = images[i].ManifestDescriptor.MediaType
		}
	case mid == flavorDocker && leaf == flavorOCI:
		multiarch.Index.MediaType = dockerList.MediaTypeManifestList

		for i := range multiarch.Index.Manifests {
			multiarch.Index.Manifests[i].MediaType = images[i].ManifestDescriptor.MediaType
		}
	case mid == flavorDocker && leaf == flavorDocker:
		multiarch = multiarch.AsDockerImage()
	}

	recomputeMultiarchIndexDescriptor(&multiarch)

	return multiarch
}

func recomputeMultiarchIndexDescriptor(multiarch *MultiarchImage) {
	indexBlob, err := json.Marshal(multiarch.Index)
	if err != nil {
		panic("marshal inner index: " + err.Error())
	}

	multiarch.IndexDescriptor = ispec.Descriptor{
		MediaType: multiarch.Index.MediaType,
		Digest:    godigest.FromBytes(indexBlob),
		Size:      int64(len(indexBlob)),
		Data:      indexBlob,
	}
}

func wrapIndexDescriptor(child ispec.Descriptor, flavor indexFlavor) ispec.Descriptor {
	index := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: flavor.indexMediaType(),
		Manifests: []ispec.Descriptor{
			{
				MediaType: child.MediaType,
				Digest:    child.Digest,
				Size:      child.Size,
				Platform:  child.Platform,
			},
		},
	}

	indexBlob, err := json.Marshal(index)
	if err != nil {
		panic("marshal wrapped index: " + err.Error())
	}

	return ispec.Descriptor{
		MediaType: index.MediaType,
		Digest:    godigest.FromBytes(indexBlob),
		Size:      int64(len(indexBlob)),
		Data:      indexBlob,
	}
}

func writeNestedIndexLayoutDirect(t *testing.T, root, repo, tag string, images []Image,
	innerIndex, midIndex, rootIndex ispec.Descriptor,
) string {
	t.Helper()

	repoDir := filepath.Join(root, repo)
	blobDir := filepath.Join(repoDir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(blobDir, storageConstants.DefaultDirPerms))

	writeBlob := func(data []byte) {
		dgst := godigest.FromBytes(data)
		require.NoError(t, os.WriteFile(filepath.Join(blobDir, dgst.Encoded()), data, storageConstants.DefaultFilePerms))
	}

	for _, image := range images {
		configBlob := image.ConfigDescriptor.Data
		if len(configBlob) == 0 {
			var err error

			configBlob, err = json.Marshal(image.Config)
			require.NoError(t, err)
		}

		writeBlob(configBlob)

		for _, layer := range image.Layers {
			writeBlob(layer)
		}

		manifestBlob := image.ManifestDescriptor.Data
		if len(manifestBlob) == 0 {
			var err error

			manifestBlob, err = json.Marshal(image.Manifest)
			require.NoError(t, err)
		}

		writeBlob(manifestBlob)
	}

	writeBlob(innerIndex.Data)
	writeBlob(midIndex.Data)
	writeBlob(rootIndex.Data)

	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`),
		storageConstants.DefaultFilePerms))

	indexFile := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: rootIndex.MediaType,
		Manifests: []ispec.Descriptor{
			{
				MediaType: rootIndex.MediaType,
				Digest:    rootIndex.Digest,
				Size:      rootIndex.Size,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": tag,
				},
			},
		},
	}
	indexFileData, err := json.Marshal(indexFile)
	assert.NoError(t, err)

	assert.NoError(t, os.WriteFile(filepath.Join(repoDir, "index.json"), indexFileData, storageConstants.DefaultFilePerms))

	return repoDir
}

func writeOCIMultiPlatformIndex(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	multiarch := CreateMultiarchWith().Images(platformImages()).Build()
	assert.NoError(t, WriteMultiArchImageToFileSystem(multiarch, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func writeOCISingleManifest(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	image := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	assert.NoError(t, WriteImageToFileSystem(image, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func writeOCIArtifactManifest(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	subject := CreateImageWith().DefaultLayers().DefaultConfig().Build()
	assert.NoError(t, WriteImageToFileSystem(subject, repo, subject.DigestStr(), storeCtrl))

	artifact := CreateImageWith().EmptyLayer().EmptyConfig().
		Subject(subject.DescriptorRef()).
		ArtifactType("application/example.sbom").
		Build()
	assert.NoError(t, WriteImageToFileSystem(artifact, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func writeDockerMultiPlatformIndex(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	multiarch := CreateMultiarchWith().Images(platformImages()).Build().AsDockerImage()
	assert.NoError(t, WriteMultiArchImageToFileSystem(multiarch, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func writeHybridOCIIndexOCIChildrenDockerInterior(t *testing.T, repo, tag string) string {
	t.Helper()

	images := make([]Image, len(platformImages()))
	for i, platformImage := range platformImages() {
		images[i] = ociManifestDescriptorWithDockerInterior(platformImage.AsDockerImage())
	}

	multiarch := CreateMultiarchWith().Images(images).Build()

	// zot manifest validation may reject oci manifest descriptors whose bodies use docker media types
	return writeMultiarchLayoutDirect(t, t.TempDir(), repo, tag, multiarch)
}

func ociManifestDescriptorWithDockerInterior(img Image) Image {
	img.Manifest.MediaType = ispec.MediaTypeImageManifest

	manifestBlob, err := json.Marshal(img.Manifest)
	if err != nil {
		panic("unreachable: ispec.Manifest should always be marshable")
	}

	img.ManifestDescriptor = ispec.Descriptor{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    godigest.FromBytes(manifestBlob),
		Size:      int64(len(manifestBlob)),
		Data:      manifestBlob,
		Platform:  img.ConfigDescriptor.Platform,
	}

	return img
}

func writeHybridOCIIndexDockerChildren(t *testing.T, storeCtrl stypes.StoreController, root, repo, tag string) string {
	t.Helper()

	dockerImages := make([]Image, len(platformImages()))
	for i, image := range platformImages() {
		dockerImages[i] = image.AsDockerImage()
	}

	multiarch := CreateMultiarchWith().Images(dockerImages).Build()
	multiarch.Index.MediaType = ispec.MediaTypeImageIndex

	for i := range multiarch.Index.Manifests {
		multiarch.Index.Manifests[i].MediaType = dockerImages[i].ManifestDescriptor.MediaType
	}

	indexBlob, err := json.Marshal(multiarch.Index)
	assert.NoError(t, err)

	multiarch.IndexDescriptor = ispec.Descriptor{
		MediaType: ispec.MediaTypeImageIndex,
		Digest:    godigest.FromBytes(indexBlob),
		Size:      int64(len(indexBlob)),
		Data:      indexBlob,
	}

	assert.NoError(t, WriteMultiArchImageToFileSystem(multiarch, repo, tag, storeCtrl))

	return repoPath(root, repo)
}

func writeHybridDockerIndexOCIChildren(t *testing.T, repo, tag string) string {
	t.Helper()

	ociImages := platformImages()

	multiarch := CreateMultiarchWith().Images(ociImages).Build()
	dockerIndexMT := CreateMultiarchWith().Images(platformImages()).Build().AsDockerImage().Index.MediaType

	multiarch.Index.MediaType = dockerIndexMT

	for i := range multiarch.Index.Manifests {
		multiarch.Index.Manifests[i].MediaType = ociImages[i].ManifestDescriptor.MediaType
	}

	indexBlob, err := json.Marshal(multiarch.Index)
	assert.NoError(t, err)

	multiarch.IndexDescriptor = ispec.Descriptor{
		MediaType: dockerIndexMT,
		Digest:    godigest.FromBytes(indexBlob),
		Size:      int64(len(indexBlob)),
		Data:      indexBlob,
	}

	// zot manifest validation rejects a docker manifest list that references oci child manifests
	return writeMultiarchLayoutDirect(t, t.TempDir(), repo, tag, multiarch)
}

func writeOCIIndexWithDockerReferrerAnnotations(t *testing.T, repo, tag string) string {
	t.Helper()

	platform := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	referrer := CreateImageWith().EmptyLayer().EmptyConfig().Build()

	multiarch := CreateMultiarchWith().Images([]Image{platform, referrer}).Build()
	multiarch.Index.Manifests[1].Annotations = map[string]string{
		"vnd.docker.reference.type":   "builder",
		"vnd.docker.reference.digest": multiarch.Index.Manifests[0].Digest.String(),
	}
	multiarch.Index.Manifests[1].Platform = &ispec.Platform{
		Architecture: "unknown",
		OS:           "unknown",
	}

	recomputeMultiarchIndexDescriptor(&multiarch)

	return writeMultiarchLayoutDirect(t, t.TempDir(), repo, tag, multiarch)
}

// writeOCIIndexWithDockerReferrerExternalSubject builds a referrers-style index whose sole
// entry annotates vnd.docker.reference.digest to a subject manifest that is stored on disk
// but not listed in the index (external to the fetched manifest tree).
func writeOCIIndexWithDockerReferrerExternalSubject(t *testing.T, repo, tag string) string {
	t.Helper()

	subject := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	referrer := CreateImageWith().EmptyLayer().EmptyConfig().Build()

	referrerDesc := referrer.ManifestDescriptor
	referrerDesc.Annotations = map[string]string{
		"vnd.docker.reference.type":   "builder",
		"vnd.docker.reference.digest": subject.ManifestDescriptor.Digest.String(),
	}
	referrerDesc.Platform = &ispec.Platform{
		Architecture: "unknown",
		OS:           "unknown",
	}

	index := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{referrerDesc},
	}

	indexBlob, err := json.Marshal(index)
	require.NoError(t, err)

	multiarch := MultiarchImage{
		Images: []Image{subject, referrer},
		Index:  index,
		IndexDescriptor: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromBytes(indexBlob),
			Size:      int64(len(indexBlob)),
			Data:      indexBlob,
		},
	}

	return writeMultiarchLayoutDirect(t, t.TempDir(), repo, tag, multiarch)
}

func writeMultiarchLayoutDirect(t *testing.T, root, repo, tag string, multiarch MultiarchImage) string {
	t.Helper()

	repoDir := filepath.Join(root, repo)
	blobDir := filepath.Join(repoDir, "blobs", "sha256")
	assert.NoError(t, os.MkdirAll(blobDir, storageConstants.DefaultDirPerms))

	writeBlob := func(data []byte) godigest.Digest {
		dgst := godigest.FromBytes(data)
		assert.NoError(t, os.WriteFile(filepath.Join(blobDir, dgst.Encoded()), data, storageConstants.DefaultFilePerms))

		return dgst
	}

	for _, image := range multiarch.Images {
		configBlob := image.ConfigDescriptor.Data
		if len(configBlob) == 0 {
			var err error

			configBlob, err = json.Marshal(image.Config)
			assert.NoError(t, err)
		}

		writeBlob(configBlob)

		for _, layer := range image.Layers {
			writeBlob(layer)
		}

		manifestBlob := image.ManifestDescriptor.Data
		if len(manifestBlob) == 0 {
			var err error

			manifestBlob, err = json.Marshal(image.Manifest)
			assert.NoError(t, err)
		}

		writeBlob(manifestBlob)
	}

	indexBlob := multiarch.IndexDescriptor.Data
	if len(indexBlob) == 0 {
		var err error

		indexBlob, err = json.Marshal(multiarch.Index)
		assert.NoError(t, err)
	}

	indexDigest := writeBlob(indexBlob)

	assert.NoError(t, os.WriteFile(filepath.Join(repoDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`),
		storageConstants.DefaultFilePerms))

	indexFile := ispec.Index{
		Versioned: multiarch.Index.Versioned,
		MediaType: multiarch.Index.MediaType,
		Manifests: []ispec.Descriptor{
			{
				MediaType: multiarch.IndexDescriptor.MediaType,
				Digest:    indexDigest,
				Size:      int64(len(indexBlob)),
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": tag,
				},
			},
		},
	}
	indexFileData, err := json.Marshal(indexFile)
	assert.NoError(t, err)

	assert.NoError(t, os.WriteFile(filepath.Join(repoDir, "index.json"), indexFileData, storageConstants.DefaultFilePerms))

	return repoDir
}

func writeDeepIndexChain(t *testing.T, repo, tag string, depth int) string {
	t.Helper()

	platform := CreateImageWith().EmptyLayer().EmptyConfig().Build()
	child := platform.ManifestDescriptor
	indexBlobs := make([]ispec.Descriptor, 0, depth)

	for range depth {
		child = wrapIndexDescriptor(child, flavorOCI)
		indexBlobs = append(indexBlobs, child)
	}

	return writeCyclicIndexLayoutDirect(t, t.TempDir(), repo, tag, []Image{platform}, child, ispec.Descriptor{}, indexBlobs...)
}

func writeWideOCIIndex(t *testing.T, repo, tag string, entries int) string {
	t.Helper()

	platform := CreateImageWith().EmptyLayer().EmptyConfig().Build()
	manifests := make([]ispec.Descriptor, entries)
	for i := range manifests {
		manifests[i] = platform.ManifestDescriptor
	}

	index := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: manifests,
	}
	indexBlob, err := json.Marshal(index)
	require.NoError(t, err)

	rootIndex := ispec.Descriptor{
		MediaType: ispec.MediaTypeImageIndex,
		Digest:    godigest.FromBytes(indexBlob),
		Size:      int64(len(indexBlob)),
		Data:      indexBlob,
	}

	return writeCyclicIndexLayoutDirect(t, t.TempDir(), repo, tag, []Image{platform}, rootIndex, ispec.Descriptor{})
}

func writeCyclicIndexLayoutDirect(t *testing.T, root, repo, tag string, images []Image,
	rootIndex, secondaryIndex ispec.Descriptor, extraIndexes ...ispec.Descriptor,
) string {
	t.Helper()

	repoDir := filepath.Join(root, repo)
	blobDir := filepath.Join(repoDir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(blobDir, storageConstants.DefaultDirPerms))

	writeBlob := func(data []byte) {
		dgst := godigest.FromBytes(data)
		require.NoError(t, os.WriteFile(filepath.Join(blobDir, dgst.Encoded()), data, storageConstants.DefaultFilePerms))
	}

	for _, image := range images {
		configBlob := image.ConfigDescriptor.Data
		if len(configBlob) == 0 {
			var err error

			configBlob, err = json.Marshal(image.Config)
			require.NoError(t, err)
		}

		writeBlob(configBlob)

		for _, layer := range image.Layers {
			writeBlob(layer)
		}

		manifestBlob := image.ManifestDescriptor.Data
		if len(manifestBlob) == 0 {
			var err error

			manifestBlob, err = json.Marshal(image.Manifest)
			require.NoError(t, err)
		}

		writeBlob(manifestBlob)
	}

	writeBlob(rootIndex.Data)

	if secondaryIndex.Digest != "" {
		writeBlob(secondaryIndex.Data)
	}

	for _, indexDesc := range extraIndexes {
		if indexDesc.Digest != "" {
			writeBlob(indexDesc.Data)
		}
	}

	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`),
		storageConstants.DefaultFilePerms))

	indexFile := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: rootIndex.MediaType,
		Manifests: []ispec.Descriptor{
			{
				MediaType: rootIndex.MediaType,
				Digest:    rootIndex.Digest,
				Size:      rootIndex.Size,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": tag,
				},
			},
		},
	}
	indexFileData, err := json.Marshal(indexFile)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "index.json"), indexFileData, storageConstants.DefaultFilePerms))

	return repoDir
}

func writeUnsupportedRootMediaType(t *testing.T, repo, tag string) string {
	t.Helper()

	image := CreateImageWith().EmptyLayer().EmptyConfig().Build()
	const unsupportedMT = "application/vnd.test.unsupported+json"

	manifestBlob, err := json.Marshal(image.Manifest)
	require.NoError(t, err)

	rootDesc := ispec.Descriptor{
		MediaType: unsupportedMT,
		Digest:    godigest.FromBytes(manifestBlob),
		Size:      int64(len(manifestBlob)),
		Data:      manifestBlob,
	}
	image.ManifestDescriptor = rootDesc

	repoDir := writeCyclicIndexLayoutDirect(t, t.TempDir(), repo, tag, []Image{image}, rootDesc, ispec.Descriptor{})

	// Tag descriptor media type is what regclient exposes from index.json.
	indexPath := filepath.Join(repoDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	require.NoError(t, err)

	var layoutIndex ispec.Index
	require.NoError(t, json.Unmarshal(indexData, &layoutIndex))
	layoutIndex.Manifests[0].MediaType = unsupportedMT

	indexData, err = json.Marshal(layoutIndex)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, indexData, storageConstants.DefaultFilePerms))

	return repoDir
}

func writeDockerManifestVariedLayers(t *testing.T, repo, tag string) string {
	t.Helper()

	image := CreateImageWith().RandomLayers(4, 8).RandomConfig().Build().AsDockerImage()
	require.GreaterOrEqual(t, len(image.Manifest.Layers), 4)

	layerTypes := []string{
		mediatype.Docker2Layer,
		mediatype.Docker2LayerGzip,
		mediatype.Docker2LayerZstd,
		mediatype.Docker2ForeignLayer,
	}

	for i, layerType := range layerTypes {
		image.Manifest.Layers[i].MediaType = layerType
	}

	manifestBlob, err := json.Marshal(image.Manifest)
	require.NoError(t, err)

	rootDesc := ispec.Descriptor{
		MediaType: mediatype.Docker2Manifest,
		Digest:    godigest.FromBytes(manifestBlob),
		Size:      int64(len(manifestBlob)),
		Data:      manifestBlob,
	}
	image.ManifestDescriptor = rootDesc

	return writeCyclicIndexLayoutDirect(t, t.TempDir(), repo, tag, []Image{image}, rootDesc, ispec.Descriptor{})
}
