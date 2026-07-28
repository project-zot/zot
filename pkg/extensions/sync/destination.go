//go:build sync

package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

var (
	errSyncTempImageReferenceNoPath       = errors.New("sync temp image reference has no path")
	errSyncTempImageReferenceNoLayoutPath = errors.New("sync temp image reference has no layout path")
	errSyncTempLayoutPathRepoMismatch     = errors.New("sync temp layout path does not end with repo")
	errSyncTempImageStoreCreateFailed     = errors.New("failed to create temp sync image store")
)

type DestinationRegistry struct {
	storeController storage.StoreController
	tempStorage     OciLayoutStorage
	metaDB          mTypes.MetaDB
	log             log.Logger
}

func NewDestinationRegistry(
	storeController storage.StoreController, // local store controller
	tempStoreController storage.StoreController, // temp store controller
	metaDB mTypes.MetaDB,
	log log.Logger,
) Destination {
	return &DestinationRegistry{
		storeController: storeController,
		tempStorage:     NewOciLayoutStorage(tempStoreController),
		metaDB:          metaDB,
		// first we sync from remote (using containers/image copy from docker:// to oci:) to a temp imageStore
		// then we copy the image from tempStorage to zot's storage using ImageStore APIs
		log: log,
	}
}

// CanSkipImage checks if image is already synced.
func (registry *DestinationRegistry) CanSkipImage(repo, tag string, digest godigest.Digest) (bool, error) {
	// check image already synced
	imageStore := registry.storeController.GetImageStore(repo)

	_, localImageManifestDigest, _, err := imageStore.GetImageManifest(repo, tag)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", tag).
			Err(err).Msg("couldn't get local image manifest")

		return false, err
	}

	if localImageManifestDigest != digest {
		registry.log.Info().Str("repo", repo).Str("reference", tag).
			Str("localDigest", localImageManifestDigest.String()).
			Str("remoteDigest", digest.String()).
			Msg("remote image digest changed, syncing again")

		return false, nil
	}

	return true, nil
}

func (registry *DestinationRegistry) GetImageReference(repo, reference string) (ref.Ref, error) {
	return registry.tempStorage.GetImageReference(repo, reference)
}

// CommitAll finalizes a syncing image.
func (registry *DestinationRegistry) CommitAll(repo string, imageReference ref.Ref) error {
	tempImageStore, err := getImageStoreFromImageReference(repo, imageReference, registry.log)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("repo", repo).Str("reference", imageReference.Reference).
			Msg("failed to open temp sync image store")

		return err
	}

	defer os.RemoveAll(tempImageStore.RootDir())

	repoDir := path.Join(tempImageStore.RootDir(), repo)

	// Check if directory is empty before attempting to get index
	entries, err := os.ReadDir(repoDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Directory doesn't exist - nothing to commit (image was skipped)
			return nil
		}

		// Other directory read errors should be reported
		registry.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", repoDir).Str("repo", repo).
			Msg("failed to read temp sync dir")

		return err
	}

	// If directory is empty, nothing was synced (e.g., image was skipped)
	if len(entries) == 0 {
		return nil
	}

	registry.log.Info().Str("syncTempDir", repoDir).Str("repository", repo).
		Msg("pushing synced local image to local registry")

	index, err := storageCommon.GetIndex(tempImageStore, repo, registry.log)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", repoDir).Str("repo", repo).
			Msg("failed to get repo index from temp sync dir")

		return err
	}

	seen := &[]godigest.Digest{}

	for _, desc := range index.Manifests {
		reference := GetDescriptorReference(desc)

		if err := registry.copyManifest(repo, desc, reference, tempImageStore, seen); err != nil {
			if errors.Is(err, zerr.ErrImageLintAnnotations) {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("failed to upload manifest because of missing annotations")

				return nil
			}

			return err
		}
	}

	return nil
}

func (registry *DestinationRegistry) CleanupImage(imageReference ref.Ref, repo string) error {
	sessionRoot, err := syncTempSessionRoot(repo, imageReference)
	if err != nil {
		registry.log.Debug().Err(err).Str("repo", repo).
			Msg("failed to resolve temp sync session root for cleanup")

		return nil
	}

	if _, err = os.Stat(sessionRoot); err == nil {
		if err := os.RemoveAll(sessionRoot); err != nil {
			registry.log.Error().Err(err).Msg("failed to cleanup image from temp storage")

			return err
		}
	}

	return nil
}

func (registry *DestinationRegistry) copyManifest(repo string, desc ispec.Descriptor,
	reference string, tempImageStore storageTypes.ImageStore, seen *[]godigest.Digest,
) error {
	var err error

	// seen
	if slices.Contains(*seen, desc.Digest) {
		return nil
	}

	*seen = append(*seen, desc.Digest)

	imageStore := registry.storeController.GetImageStore(repo)
	isReferrersRef := common.IsReferrersTag(reference)

	manifestContent := desc.Data
	if manifestContent == nil {
		manifestContent, _, _, err = tempImageStore.GetImageManifest(repo, reference)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("repo", repo).Str("reference", reference).
				Msg("failed to get manifest from temporary sync dir")

			return err
		}
	}

	// is image manifest
	switch desc.MediaType {
	case ispec.MediaTypeImageManifest, mediatype.Docker2Manifest:
		if isReferrersRef {
			return nil
		}

		var manifest ispec.Manifest

		if err := json.Unmarshal(manifestContent, &manifest); err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).
				Msg("invalid JSON")

			return err
		}

		for _, blob := range manifest.Layers {
			if storageCommon.IsNonDistributable(blob.MediaType) {
				continue
			}

			err := registry.copyBlob(repo, blob.Digest, blob.MediaType, tempImageStore)
			if err != nil {
				return err
			}
		}

		err := registry.copyBlob(repo, manifest.Config.Digest, manifest.Config.MediaType, tempImageStore)
		if err != nil {
			return err
		}

		digest, _, err := imageStore.PutImageManifest(context.Background(), repo, reference,
			desc.MediaType, manifestContent, nil)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't upload manifest")

			return err
		}

		if registry.metaDB != nil {
			err = meta.SetImageMetaFromInput(context.Background(), repo, reference, desc.MediaType,
				digest, manifestContent, imageStore, registry.metaDB, registry.log)
			if err != nil {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("couldn't set metadata from input")

				return err
			}

			registry.log.Debug().Str("repo", repo).Str("reference", reference).Msg("successfully set metadata for image")
		}

	case ispec.MediaTypeImageIndex, mediatype.Docker2ManifestList:
		// is image index
		var indexManifest ispec.Index

		if err := json.Unmarshal(manifestContent, &indexManifest); err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).
				Msg("invalid JSON")

			return err
		}

		var firstMissingErr error

		for _, manifest := range indexManifest.Manifests {
			reference := GetDescriptorReference(manifest)

			manifestBuf, err := tempImageStore.GetBlobContent(repo, manifest.Digest)
			if err != nil {
				// Handle missing manifest blobs gracefully - log warning and continue with other manifests
				var pathNotFoundErr driver.PathNotFoundError
				if errors.Is(err, zerr.ErrBlobNotFound) || errors.As(err, &pathNotFoundErr) {
					if firstMissingErr == nil {
						firstMissingErr = err
					}

					registry.log.Warn().Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).
						Str("digest", manifest.Digest.String()).
						Msg("skipping missing manifest blob in image index, continuing sync with other manifests")

					continue
				}

				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("digest", manifest.Digest.String()).
					Msg("failed find manifest which is part of an image index")

				return err
			}

			manifest.Data = manifestBuf

			if err := registry.copyManifest(repo, manifest, reference,
				tempImageStore, seen); err != nil {
				if errors.Is(err, zerr.ErrImageLintAnnotations) {
					registry.log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msg("failed to upload manifest because of missing annotations")

					return nil
				}

				return err
			}
		}

		// Return error if we encountered any missing manifests
		if firstMissingErr != nil {
			return firstMissingErr
		}

		// Referrers indexes are a transport convention in the temp ocidir layout; persist child
		// manifests only, not the referrers index entry itself.
		if isReferrersRef {
			return nil
		}

		_, _, err := imageStore.PutImageManifest(context.Background(), repo, reference, desc.MediaType, manifestContent, nil)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
				Err(err).Msg("failed to upload manifest")

			return err
		}

		if registry.metaDB != nil {
			err = meta.SetImageMetaFromInput(context.Background(), repo, reference, desc.MediaType,
				desc.Digest, manifestContent, imageStore, registry.metaDB, registry.log)
			if err != nil {
				return fmt.Errorf("metaDB: failed to set metadata for image '%s %s': %w", repo, reference, err)
			}

			registry.log.Debug().Str("repo", repo).Str("reference", reference).
				Msg("metaDB: successfully set metadata for image")
		}
	}

	return nil
}

// Copy a blob from one image store to another image store.
func (registry *DestinationRegistry) copyBlob(repo string, blobDigest godigest.Digest, blobMediaType string,
	tempImageStore storageTypes.ImageStore,
) error {
	imageStore := registry.storeController.GetImageStore(repo)
	ctx := context.Background()
	if found, _, _ := imageStore.CheckBlob(ctx, repo, blobDigest); found {
		// Blob is already at destination, nothing to do
		return nil
	}

	blobReadCloser, _, err := tempImageStore.GetBlob(repo, blobDigest, blobMediaType)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("dir", path.Join(tempImageStore.RootDir(), repo)).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't read blob")

		return err
	}
	defer blobReadCloser.Close()

	_, _, err = imageStore.FullBlobUpload(ctx, repo, blobReadCloser, blobDigest)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't upload blob")
	}

	return err
}

// ocidirLayoutPath returns the on-disk OCI layout directory for a temp sync ref.
// regclient may clear Path after mod.Apply while Reference still holds the ocidir URL.
func ocidirLayoutPath(imageReference ref.Ref) (string, error) {
	if imageReference.Path != "" {
		return imageReference.Path, nil
	}

	if imageReference.Reference == "" {
		return "", errSyncTempImageReferenceNoPath
	}

	parsed, err := ref.New(imageReference.Reference)
	if err != nil {
		return "", fmt.Errorf("parse sync temp image reference: %w", err)
	}

	if parsed.Path == "" {
		return "", errSyncTempImageReferenceNoLayoutPath
	}

	return parsed.Path, nil
}

// syncTempSessionRoot maps a temp ocidir ref to the session directory that contains the repo layout.
func syncTempSessionRoot(repo string, imageReference ref.Ref) (string, error) {
	layoutPath, err := ocidirLayoutPath(imageReference)
	if err != nil {
		return "", err
	}

	repoSuffix := path.Join("/", repo)
	if sessionRoot, ok := strings.CutSuffix(layoutPath, repoSuffix); ok {
		return sessionRoot, nil
	}

	return "", fmt.Errorf("%w: layout=%q repo=%q", errSyncTempLayoutPathRepoMismatch, layoutPath, repo)
}

// use only with local imageReferences.
func getImageStoreFromImageReference(repo string, imageReference ref.Ref, log log.Logger,
) (storageTypes.ImageStore, error) {
	sessionRootDir, err := syncTempSessionRoot(repo, imageReference)
	if err != nil {
		return nil, err
	}

	store := getImageStore(sessionRootDir, log)
	if store == nil {
		return nil, fmt.Errorf("%w: %q", errSyncTempImageStoreCreateFailed, sessionRootDir)
	}

	return store, nil
}

func getImageStore(rootDir string, log log.Logger) storageTypes.ImageStore {
	metrics := monitoring.NewMetricsServer(false, log)

	return local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)
}
