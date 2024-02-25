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
	"time"

	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	storageCommon "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
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

func (registry *DestinationRegistry) CanSkipImage(repo, tag string, imageDigest digest.Digest) (bool, error) {
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

	if localImageManifestDigest != imageDigest {
		registry.log.Info().Str("repo", repo).Str("reference", tag).
			Str("localDigest", localImageManifestDigest.String()).
			Str("remoteDigest", imageDigest.String()).
			Msg("remote image digest changed, syncing again")

		return false, nil
	}

	return true, nil
}

func (registry *DestinationRegistry) GetContext() *types.SystemContext {
	return registry.tempStorage.GetContext()
}

func (registry *DestinationRegistry) GetImageReference(repo, reference string) (types.ImageReference, error) {
	return registry.tempStorage.GetImageReference(repo, reference)
}

// finalize a syncing image.
func (registry *DestinationRegistry) CommitImage(imageReference types.ImageReference, repo, reference string) error {
	imageStore := registry.storeController.GetImageStore(repo)

	tempImageStore := getImageStoreFromImageReference(imageReference, repo, reference)

	defer os.RemoveAll(tempImageStore.RootDir())

	registry.log.Info().Str("syncTempDir", path.Join(tempImageStore.RootDir(), repo)).Str("reference", reference).
		Msg("pushing synced local image to local registry")

	var lockLatency time.Time

	manifestBlob, manifestDigest, mediaType, err := tempImageStore.GetImageManifest(repo, reference)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("repo", repo).Str("reference", reference).
			Msg("couldn't find synced manifest in temporary sync dir")

		return err
	}

	// is image manifest
	switch mediaType {
	case ispec.MediaTypeImageManifest:
		if err := registry.copyManifest(repo, manifestBlob, reference, tempImageStore); err != nil {
			if errors.Is(err, zerr.ErrImageLintAnnotations) {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("couldn't upload manifest because of missing annotations")

				return nil
			}

			return err
		}
	case ispec.MediaTypeImageIndex:
		// is image index
		var indexManifest ispec.Index

		if err := json.Unmarshal(manifestBlob, &indexManifest); err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).
				Msg("invalid JSON")

			return err
		}

		for _, manifest := range indexManifest.Manifests {
			tempImageStore.RLock(&lockLatency)
			manifestBuf, err := tempImageStore.GetBlobContent(repo, manifest.Digest)
			tempImageStore.RUnlock(&lockLatency)

			if err != nil {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("digest", manifest.Digest.String()).
					Msg("couldn't find manifest which is part of an image index")

				return err
			}

			if err := registry.copyManifest(repo, manifestBuf, manifest.Digest.String(),
				tempImageStore); err != nil {
				if errors.Is(err, zerr.ErrImageLintAnnotations) {
					registry.log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msg("couldn't upload manifest because of missing annotations")

					return nil
				}

				return err
			}
		}

		_, _, err = imageStore.PutImageManifest(repo, reference, mediaType, manifestBlob)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
				Err(err).Msg("couldn't upload manifest")

			return err
		}

		if registry.metaDB != nil {
			err = meta.SetImageMetaFromInput(context.Background(), repo, reference, mediaType,
				manifestDigest, manifestBlob, imageStore, registry.metaDB, registry.log)
			if err != nil {
				return fmt.Errorf("failed to set metadata for image '%s %s': %w", repo, reference, err)
			}

			registry.log.Debug().Str("repo", repo).Str("reference", reference).Str("component", "metadb").
				Msg("successfully set metadata for image")
		}
	}

	registry.log.Info().Str("image", fmt.Sprintf("%s:%s", repo, reference)).Msg("successfully synced image")

	return nil
}

func (registry *DestinationRegistry) CleanupImage(imageReference types.ImageReference, repo, reference string) error {
	tmpDir := getTempRootDirFromImageReference(imageReference, repo, reference)

	return os.RemoveAll(tmpDir)
}

func (registry *DestinationRegistry) copyManifest(repo string, manifestContent []byte, reference string,
	tempImageStore storageTypes.ImageStore,
) error {
	imageStore := registry.storeController.GetImageStore(repo)

	var manifest ispec.Manifest

	var err error

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

		err = registry.copyBlob(repo, blob.Digest, blob.MediaType, tempImageStore)
		if err != nil {
			return err
		}
	}

	err = registry.copyBlob(repo, manifest.Config.Digest, manifest.Config.MediaType, tempImageStore)
	if err != nil {
		return err
	}

	digest, _, err := imageStore.PutImageManifest(repo, reference,
		ispec.MediaTypeImageManifest, manifestContent)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't upload manifest")

		return err
	}

	if registry.metaDB != nil {
		err = meta.SetImageMetaFromInput(context.Background(), repo, reference, ispec.MediaTypeImageManifest,
			digest, manifestContent, imageStore, registry.metaDB, registry.log)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't set metadata from input")

			return err
		}

		registry.log.Debug().Str("repo", repo).Str("reference", reference).Msg("successfully set metadata for image")
	}

	return nil
}

// Copy a blob from one image store to another image store.
func (registry *DestinationRegistry) copyBlob(repo string, blobDigest digest.Digest, blobMediaType string,
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
func getImageStoreFromImageReference(imageReference types.ImageReference, repo, reference string,
) storageTypes.ImageStore {
	tmpRootDir := getTempRootDirFromImageReference(imageReference, repo, reference)

	return getImageStore(tmpRootDir)
}

func getTempRootDirFromImageReference(imageReference types.ImageReference, repo, reference string) string {
	var tmpRootDir string

	if strings.HasSuffix(imageReference.StringWithinTransport(), reference) {
		tmpRootDir = strings.ReplaceAll(imageReference.StringWithinTransport(), fmt.Sprintf("%s:%s", repo, reference), "")
	} else {
		tmpRootDir = strings.ReplaceAll(imageReference.StringWithinTransport(), fmt.Sprintf("%s:", repo), "")
	}

	return tmpRootDir
}

func getImageStore(rootDir string) storageTypes.ImageStore {
	metrics := monitoring.NewMetricsServer(false, log.Logger{})

	return local.NewImageStore(rootDir, false, false, log.Logger{}, metrics, nil, nil)
}
