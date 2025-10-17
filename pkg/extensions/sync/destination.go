//go:build sync
// +build sync

package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

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

// Check if image is already synced.
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

// finalize a syncing image.
func (registry *DestinationRegistry) CommitAll(repo string, imageReference ref.Ref) error {
	tempImageStore := getImageStoreFromImageReference(repo, imageReference, registry.log)

	defer os.RemoveAll(tempImageStore.RootDir())

	registry.log.Info().Str("syncTempDir", path.Join(tempImageStore.RootDir(), repo)).Str("repository", repo).
		Msg("pushing synced local image to local registry")

	index, err := storageCommon.GetIndex(tempImageStore, repo, registry.log)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("repo", repo).
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
	var err error

	dir := strings.TrimSuffix(imageReference.Path, repo)
	if _, err = os.Stat(dir); err == nil {
		if err := os.RemoveAll(strings.TrimSuffix(imageReference.Path, repo)); err != nil {
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
	if common.Contains(*seen, desc.Digest) {
		return nil
	}

	*seen = append(*seen, desc.Digest)

	imageStore := registry.storeController.GetImageStore(repo)

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

		digest, _, err := imageStore.PutImageManifest(repo, reference,
			desc.MediaType, manifestContent)
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

		for _, manifest := range indexManifest.Manifests {
			reference := GetDescriptorReference(manifest)

			manifestBuf, err := tempImageStore.GetBlobContent(repo, manifest.Digest)
			if err != nil {
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

		_, _, err := imageStore.PutImageManifest(repo, reference, desc.MediaType, manifestContent)
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
	if found, _, _ := imageStore.CheckBlob(repo, blobDigest); found {
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

	_, _, err = imageStore.FullBlobUpload(repo, blobReadCloser, blobDigest)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't upload blob")
	}

	return err
}

// use only with local imageReferences.
func getImageStoreFromImageReference(repo string, imageReference ref.Ref, log log.Logger) storageTypes.ImageStore {
	sessionRootDir := strings.TrimSuffix(imageReference.Path, repo)

	return getImageStore(sessionRootDir, log)
}

func getImageStore(rootDir string, log log.Logger) storageTypes.ImageStore {
	metrics := monitoring.NewMetricsServer(false, log)

	return local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)
}
