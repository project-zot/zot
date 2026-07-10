//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"slices"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
)

const (
	dockerReferenceType   = "vnd.docker.reference.type"
	dockerReferenceDigest = "vnd.docker.reference.digest"

	maxManifestTreeDepth = 32
	maxManifestTreeNodes = 256
)

var (
	errManifestListDescriptorNotFound = errors.New("could not find descriptor in manifest list")
	errManifestTreeCycle              = errors.New("manifest tree cycle detected")
	errManifestTreeLimitExceeded      = errors.New("manifest tree limit exceeded")
	errDockerReferrerRequiresManifest = errors.New("docker referrer entry requires child manifest")
	errDockerReferrerSubjectNotFound  = errors.New("could not find digest, convert referrers before other mod actions")
	errDockerReferenceNoSubject       = errors.New("docker reference type does not support subject")
	errDockerReferenceNoAnnotations   = errors.New("docker reference type does not support annotations")
	errNotEnoughChildManifests        = errors.New("manifest does not have enough child manifests")
)

type manifestChange int

const (
	manifestUnchanged manifestChange = iota
	manifestReplaced
	manifestDeleted
)

// manifestNode is a minimal in-memory manifest tree used to predict the OCI digest
// produced by regclient mod.WithManifestToOCI and mod.WithManifestToOCIReferrers.
type manifestNode struct {
	top         bool
	mod         manifestChange
	origDesc    descriptor.Descriptor
	newDesc     descriptor.Descriptor
	m           manifest.Manifest // nil only after manifestDeleted in referrer conversion
	manifestRef ref.Ref           // ref from ManifestGet; close this, not node.m after in-memory replacement
	children    []*manifestNode
}

type manifestTreeWalkState struct {
	path      map[string]struct{}
	nodeCount int
	depth     int
}

func (walkState *manifestTreeWalkState) beginNode(top bool) error {
	if walkState.nodeCount >= maxManifestTreeNodes {
		return fmt.Errorf("%w: node count", errManifestTreeLimitExceeded)
	}

	if !top && walkState.depth >= maxManifestTreeDepth {
		return fmt.Errorf("%w: depth", errManifestTreeLimitExceeded)
	}

	walkState.nodeCount++
	walkState.depth++

	return nil
}

func (walkState *manifestTreeWalkState) undoBegin() {
	walkState.depth--
}

func (walkState *manifestTreeWalkState) checkChild(childDigest string) error {
	if _, onPath := walkState.path[childDigest]; onPath {
		return fmt.Errorf("%w: digest %s", errManifestTreeCycle, childDigest)
	}

	return nil
}

func (walkState *manifestTreeWalkState) enterPath(digest string) error {
	if err := walkState.checkChild(digest); err != nil {
		return err
	}

	walkState.path[digest] = struct{}{}

	return nil
}

func (walkState *manifestTreeWalkState) leavePath(digest string) {
	delete(walkState.path, digest)
	walkState.depth--
}

// predictOCIDigest returns the digest regclient mod.WithManifestToOCI would produce,
// the original remote digest, and whether mod.Apply would modify the image.
func predictOCIDigest(ctx context.Context, regClient *regclient.RegClient, imageRef ref.Ref) (
	godigest.Digest, godigest.Digest, bool, error,
) {
	walkState := &manifestTreeWalkState{
		path: make(map[string]struct{}),
	}

	root, err := fetchManifestNode(ctx, regClient, imageRef, true, walkState)
	if err != nil {
		return "", "", false, err
	}

	defer closeManifestTree(ctx, regClient, root)

	originalDigest := root.origDesc.Digest

	switch root.origDesc.MediaType {
	case mediatype.Docker2Manifest, mediatype.Docker2ManifestList,
		mediatype.OCI1Manifest, mediatype.OCI1ManifestList:
	default:
		return "", "", false, zerr.ErrMediaTypeNotSupported
	}

	if err := root.applyManifestToOCI(); err != nil {
		return "", "", false, err
	}

	if err := root.applyOCIReferrers(); err != nil {
		return "", "", false, err
	}

	if err := root.finalize(); err != nil {
		return "", "", false, err
	}

	predictedDigest := root.effectiveDesc().Digest
	// Conversion is needed whenever regclient would change any manifest in the tree
	// (e.g. docker children under an oci index), not only when the root is docker.
	isConverted := root.mod != manifestUnchanged || predictedDigest != originalDigest

	return predictedDigest, originalDigest, isConverted, nil
}

func fetchManifestNode(ctx context.Context, regClient *regclient.RegClient, imageRef ref.Ref, top bool,
	walkState *manifestTreeWalkState,
) (*manifestNode, error) {
	if err := walkState.beginNode(top); err != nil {
		return nil, err
	}

	man, err := regClient.ManifestGet(ctx, imageRef)
	if err != nil {
		walkState.undoBegin()

		return nil, err
	}

	digest := man.GetDescriptor().Digest.String()
	if err := walkState.enterPath(digest); err != nil {
		regClient.Close(ctx, man.GetRef())
		walkState.undoBegin()

		return nil, err
	}

	defer walkState.leavePath(digest)

	node := &manifestNode{
		top:         top,
		m:           man,
		manifestRef: man.GetRef(),
		origDesc:    man.GetDescriptor(),
		mod:         manifestUnchanged,
	}

	if mi, ok := man.(manifest.Indexer); ok {
		manifestList, err := mi.GetManifestList()
		if err != nil {
			closeManifestTree(ctx, regClient, node)

			return nil, err
		}

		for _, desc := range manifestList {
			childDigest := desc.Digest.String()
			if err := walkState.checkChild(childDigest); err != nil {
				closeManifestTree(ctx, regClient, node)

				return nil, err
			}

			childRef := imageRef.SetDigest(childDigest)

			child, err := fetchManifestNode(ctx, regClient, childRef, false, walkState)
			if err != nil {
				closeManifestTree(ctx, regClient, node)

				return nil, err
			}

			node.children = append(node.children, child)
		}
	}

	return node, nil
}

func closeManifestTree(ctx context.Context, regClient *regclient.RegClient, node *manifestNode) {
	if node == nil {
		return
	}

	for _, child := range node.children {
		closeManifestTree(ctx, regClient, child)
	}

	if !node.manifestRef.IsZero() {
		regClient.Close(ctx, node.manifestRef)
	}
}

func (node *manifestNode) effectiveDesc() descriptor.Descriptor {
	if node.newDesc.Digest != "" {
		return node.newDesc
	}

	if node.m != nil {
		return node.m.GetDescriptor()
	}

	return node.origDesc
}

// applyManifestToOCI mirrors regclient mod.WithManifestToOCI (children first).
func (node *manifestNode) applyManifestToOCI() error {
	for _, child := range node.children {
		if err := child.applyManifestToOCI(); err != nil {
			return err
		}
	}

	if node.m == nil || node.mod == manifestDeleted {
		return nil
	}

	changed := false

	origManifest := node.m.GetOrig()

	if node.m.IsList() {
		ociIndex, err := manifest.OCIIndexFromAny(origManifest)
		if err != nil {
			return err
		}

		if node.m.GetDescriptor().MediaType != mediatype.OCI1ManifestList {
			changed = true
			origManifest = ociIndex
		}
	} else {
		ociManifest, err := manifest.OCIManifestFromAny(origManifest)
		if err != nil {
			return err
		}

		if node.m.GetDescriptor().MediaType != mediatype.OCI1Manifest {
			changed = true
		}

		if ociManifest.Config.MediaType == mediatype.Docker2ImageConfig {
			ociManifest.Config.MediaType = mediatype.OCI1ImageConfig
			changed = true
		}

		for i, layer := range ociManifest.Layers {
			switch layer.MediaType {
			case mediatype.Docker2Layer:
				ociManifest.Layers[i].MediaType = mediatype.OCI1Layer
			case mediatype.Docker2LayerGzip:
				ociManifest.Layers[i].MediaType = mediatype.OCI1LayerGzip
			case mediatype.Docker2LayerZstd:
				ociManifest.Layers[i].MediaType = mediatype.OCI1LayerZstd
			case mediatype.Docker2ForeignLayer:
				ociManifest.Layers[i].MediaType = mediatype.OCI1ForeignLayerGzip
			default:
				continue
			}

			changed = true
		}

		if changed {
			origManifest = ociManifest
		}
	}

	if !changed {
		return nil
	}

	newManifest, err := manifest.New(manifest.WithOrig(origManifest))
	if err != nil {
		return err
	}

	node.m = newManifest
	node.newDesc = node.m.GetDescriptor()

	if node.mod == manifestUnchanged {
		node.mod = manifestReplaced
	}

	return nil
}

// applyOCIReferrers mirrors regclient mod.WithManifestToOCIReferrers (children first).
func (node *manifestNode) applyOCIReferrers() error {
	for _, child := range node.children {
		if err := child.applyOCIReferrers(); err != nil {
			return err
		}
	}

	if node.mod == manifestDeleted {
		return nil
	}

	indexer, ok := node.m.(manifest.Indexer)
	if !ok {
		return nil
	}

	changed := false

	childByDigest := map[string]*manifestNode{
		node.origDesc.Digest.String(): node,
	}

	for _, child := range node.children {
		childByDigest[child.origDesc.Digest.String()] = child
	}

	manifestList, err := indexer.GetManifestList()
	if err != nil {
		return fmt.Errorf("failed to get manifest list: %w", err)
	}

	mlIndex := 0

	for _, child := range node.children {
		if child.mod == manifestDeleted {
			mlIndex++

			continue
		}

		if mlIndex >= len(manifestList) {
			return fmt.Errorf("%w, index=%d, digest=%s",
				errManifestListDescriptorNotFound, mlIndex, node.origDesc.Digest.String())
		}

		desc := manifestList[mlIndex]
		mlIndex++

		if len(desc.Annotations) == 0 || desc.Annotations[dockerReferenceType] == "" ||
			desc.Annotations[dockerReferenceDigest] == "" {
			continue
		}

		if child.m == nil {
			return fmt.Errorf("%w, digest=%s", errDockerReferrerRequiresManifest, desc.Digest.String())
		}

		subjectNode, ok := childByDigest[desc.Annotations[dockerReferenceDigest]]
		if !ok || subjectNode == nil {
			return fmt.Errorf("%w, digest=%s",
				errDockerReferrerSubjectNotFound, desc.Annotations[dockerReferenceDigest])
		}

		subjecter, ok := child.m.(manifest.Subjecter)
		if !ok {
			return fmt.Errorf("%w, mt=%s",
				errDockerReferenceNoSubject, child.m.GetDescriptor().MediaType)
		}

		if subj, err := subjecter.GetSubject(); err != nil || subj == nil ||
			subj.Digest.String() != desc.Annotations[dockerReferenceDigest] {
			annotator, ok := child.m.(manifest.Annotator)
			if !ok {
				return fmt.Errorf("%w, mt=%s",
					errDockerReferenceNoAnnotations, child.m.GetDescriptor().MediaType)
			}

			if err := annotator.SetAnnotation(dockerReferenceType, desc.Annotations[dockerReferenceType]); err != nil {
				return fmt.Errorf("failed to set annotations: %w", err)
			}
		}

		changed = true
		child.mod = manifestDeleted
		child.m = nil
	}

	if changed && node.mod == manifestUnchanged {
		node.mod = manifestReplaced
	}

	return nil
}

// finalize rebuilds manifest lists from converted children, mirroring regclient mod dagPut.
func (node *manifestNode) finalize() error {
	if node.m == nil {
		return nil
	}

	if !node.m.IsList() {
		if node.mod == manifestReplaced {
			node.newDesc = node.m.GetDescriptor()
		}

		return nil
	}

	changed := false

	origManifest := node.m.GetOrig()

	ociIndex, err := manifest.OCIIndexFromAny(origManifest)
	if err != nil {
		return err
	}

	for i, child := range node.children {
		if i >= len(ociIndex.Manifests) && child.mod != manifestDeleted {
			return errNotEnoughChildManifests
		}

		if child.mod == manifestDeleted {
			continue
		}

		if err := child.finalize(); err != nil {
			return err
		}

		desc := child.effectiveDesc()

		if child.mod == manifestReplaced || ociIndex.Manifests[i].Digest != desc.Digest ||
			ociIndex.Manifests[i].Size != desc.Size ||
			ociIndex.Manifests[i].MediaType != desc.MediaType {
			ociIndex.Manifests[i].Digest = desc.Digest
			ociIndex.Manifests[i].Size = desc.Size
			ociIndex.Manifests[i].MediaType = desc.MediaType
			changed = true
		}
	}

	for i := range slices.Backward(node.children) {
		if node.children[i].mod != manifestDeleted {
			continue
		}

		ociIndex.Manifests = slices.Delete(ociIndex.Manifests, i, i+1)
		changed = true
	}

	if !changed && node.mod != manifestReplaced {
		return nil
	}

	if err := manifest.OCIIndexToAny(ociIndex, &origManifest); err != nil {
		return err
	}

	if err := node.m.SetOrig(origManifest); err != nil {
		return err
	}

	node.mod = manifestReplaced
	node.newDesc = node.m.GetDescriptor()

	return nil
}
