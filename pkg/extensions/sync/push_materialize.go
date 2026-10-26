//go:build sync

package sync

import (
	"context"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// newPushStaging creates the empty oci layout that receives the local tree before it is
// copied out, and returns both the layout reference and an ImageStore over it.
//
// The pull path stages in the same place for the opposite reason (regclient writes, zot
// commits); here zot writes and regclient reads. Going through the ImageStore instead of
// copying files keeps the layout digest-verified and identical in shape to a stored repo,
// which is what regclient's ocidir driver expects.
func (service *BaseService) newPushStaging(repo, reference string) (ref.Ref, storageTypes.ImageStore, error) {
	stagingRef, err := service.destination.GetImageReference(repo, reference)
	if err != nil {
		return ref.Ref{}, nil, err
	}

	tempStore, err := getImageStoreFromImageReference(repo, stagingRef, service.log)
	if err != nil {
		return ref.Ref{}, nil, err
	}

	return stagingRef, tempStore, nil
}

// materializeTree writes digest and everything it references into the staging layout, reading
// from the local store only. Nothing is fetched from a network: a push source is the store.
//
// platforms is the OS/arch allowlist for index children. An empty list materializes every
// child; a non-empty one produces a sparse index on the destination, the same trade the pull
// path makes (see README_sparse_multiarch_sync.md).
func (service *BaseService) materializeTree(ctx context.Context, source, staging storageTypes.ImageStore,
	repo string, digest godigest.Digest, mediaType string, platforms []string,
) error {
	return service.materializeInto(ctx, source, staging, repo, digest, mediaType, platforms,
		map[godigest.Digest]struct{}{})
}

// materializeInto is materializeTree with the set of manifests this walk already handled. Digest
// addressing makes a cycle infeasible, but a diamond-shaped index would otherwise be walked once
// per path, and nothing stops a repository from containing a deeply nested chain of indexes.
func (service *BaseService) materializeInto(ctx context.Context, source, staging storageTypes.ImageStore,
	repo string, digest godigest.Digest, mediaType string, platforms []string,
	seen map[godigest.Digest]struct{},
) error {
	if _, handled := seen[digest]; handled {
		return nil
	}

	seen[digest] = struct{}{}

	if present, _, _, err := staging.StatBlob(repo, digest); err == nil && present {
		return nil
	}

	raw, err := service.localManifestContent(source, repo, digest)
	if err != nil {
		return err
	}

	man, err := manifest.New(manifest.WithRaw(raw),
		manifest.WithDesc(descriptor.Descriptor{Digest: digest, MediaType: mediaType}))
	if err != nil {
		return fmt.Errorf("failed to parse manifest %s: %w", digest, err)
	}

	// Children and blobs go first: PutImageManifest validates the tree it is handed, so a
	// manifest written before its content would be rejected by the store itself.
	if err := service.materializeChildren(ctx, source, staging, repo, man, platforms, seen); err != nil {
		return err
	}

	if _, _, err := staging.PutImageManifest(ctx, repo, digest.String(), mediaType, raw, nil); err != nil {
		return fmt.Errorf("failed to stage manifest %s: %w", digest, err)
	}

	return nil
}

// materializeChildren walks one parsed manifest and materializes everything it references.
func (service *BaseService) materializeChildren(ctx context.Context, source, staging storageTypes.ImageStore,
	repo string, man manifest.Manifest, platforms []string, seen map[godigest.Digest]struct{},
) error {
	// Every regclient manifest type implements exactly one of Indexer and Imager.
	switch typed := man.(type) {
	case manifest.Indexer:
		children, err := typed.GetManifestList()
		if err != nil {
			return err
		}

		for _, child := range children {
			if len(platforms) > 0 {
				matches, err := descriptorMatchesPlatforms(child.Platform, platforms)
				if err != nil {
					return err
				}

				if !matches {
					continue
				}
			}

			err := service.materializeInto(ctx, source, staging, repo, child.Digest, child.MediaType, platforms, seen)
			if err != nil {
				return err
			}
		}
	case manifest.Imager:
		layers, err := typed.GetLayers()
		if err != nil {
			return err
		}

		for _, layer := range layers {
			if storageCommon.IsNonDistributable(layer.MediaType) {
				continue
			}

			if err := service.materializeBlob(ctx, source, staging, repo, layer); err != nil {
				return err
			}
		}

		config, err := typed.GetConfig()
		if err != nil {
			return err
		}

		if err := service.materializeBlob(ctx, source, staging, repo, config); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: mediaType %q", zerr.ErrMediaTypeNotSupported, man.GetDescriptor().MediaType)
	}

	return nil
}

// materializeBlob streams one blob from the local store into the staging layout, skipping it
// when the layout already holds the digest.
func (service *BaseService) materializeBlob(ctx context.Context, source, staging storageTypes.ImageStore,
	repo string, desc descriptor.Descriptor,
) error {
	if desc.Digest == "" {
		return nil
	}

	if present, _, _, err := staging.StatBlob(repo, desc.Digest); err == nil && present {
		return nil
	}

	blob, _, err := source.GetBlob(repo, desc.Digest, desc.MediaType)
	if err != nil {
		return fmt.Errorf("failed to read blob %s from storage: %w", desc.Digest, err)
	}
	defer blob.Close()

	// FullBlobUpload verifies the digest while writing, so a corrupt store entry fails here
	// instead of producing a layout regclient would refuse.
	if _, _, err := staging.FullBlobUpload(ctx, repo, blob, desc.Digest); err != nil {
		return fmt.Errorf("failed to stage blob %s: %w", desc.Digest, err)
	}

	return nil
}

// localManifestContent reads a manifest from the store, taking the read lock GetBlobContent
// requires its caller to hold.
func (service *BaseService) localManifestContent(imageStore storageTypes.ImageStore, repo string,
	digest godigest.Digest,
) ([]byte, error) {
	var content []byte

	err := imageStore.WithRepoReadLock(repo, func() error {
		var err error

		content, err = imageStore.GetBlobContent(repo, digest)

		return err
	})

	return content, err
}

// pushReferrers copies the referrers of subject, then their referrers, to one destination.
// Signatures are referrers, so this is the step that keeps the dhi/secureblue signature chain
// intact: an error here fails the push instead of leaving an unsigned image behind.
func (service *BaseService) pushReferrers(ctx context.Context, source, staging storageTypes.ImageStore,
	stagingRef ref.Ref, repo string, destination pushDestination, subject godigest.Digest, platforms []string,
) error {
	seen := map[godigest.Digest]struct{}{subject: {}}

	return service.pushReferrersFor(ctx, source, staging, stagingRef, repo, destination, subject, platforms, seen)
}

func (service *BaseService) pushReferrersFor(ctx context.Context, source, staging storageTypes.ImageStore,
	stagingRef ref.Ref, repo string, destination pushDestination, subject godigest.Digest,
	platforms []string, seen map[godigest.Digest]struct{},
) error {
	referrers, err := service.localReferrers(source, repo, subject)
	if err != nil {
		return err
	}

	for _, desc := range referrers.Manifests {
		if _, ok := seen[desc.Digest]; ok {
			continue
		}

		seen[desc.Digest] = struct{}{}

		if err := service.materializeTree(ctx, source, staging, repo, desc.Digest, desc.MediaType, platforms); err != nil {
			return err
		}

		skip, err := destination.CanSkipImage(ctx, repo, desc.Digest.String(), desc.Digest)
		if err != nil {
			return err
		}

		if !skip {
			targetRef, err := destination.GetImageReference(repo, desc.Digest.String())
			if err != nil {
				return err
			}

			if err := destination.CopyImage(ctx, stagingRef.SetDigest(desc.Digest.String()), targetRef); err != nil {
				return err
			}

			destination.Close(ctx, targetRef)

			service.log.Info().Str("repo", repo).Str("referrer", desc.Digest.String()).
				Str("subject", subject.String()).Str("destination", destination.URL()).
				Msg("pushed referrer to destination")
		}

		// A referrer can itself be a subject (a signature of an SBOM, for example).
		if err := service.pushReferrersFor(ctx, source, staging, stagingRef, repo, destination, desc.Digest,
			platforms, seen); err != nil {
			return err
		}
	}

	return nil
}
