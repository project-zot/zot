//go:build sync
// +build sync

package sync

import (
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

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	storageCommon "zotregistry.io/zot/pkg/storage/common"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

type LocalRegistry struct {
	storeController storage.StoreController
	tempStorage     OciLayoutStorage
	metaDB          metaTypes.MetaDB
	log             log.Logger
}

func NewLocalRegistry(storeController storage.StoreController, metaDB metaTypes.MetaDB, log log.Logger) Local {
	return &LocalRegistry{
		storeController: storeController,
		metaDB:          metaDB,
		// first we sync from remote (using containers/image copy from docker:// to oci:) to a temp imageStore
		// then we copy the image from tempStorage to zot's storage using ImageStore APIs
		tempStorage: NewOciLayoutStorage(storeController),
		log:         log,
	}
}

func (registry *LocalRegistry) CanSkipImage(repo, tag string, imageDigest digest.Digest) (bool, error) {
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

func (registry *LocalRegistry) GetContext() *types.SystemContext {
	return registry.tempStorage.GetContext()
}

func (registry *LocalRegistry) GetImageReference(repo, reference string) (types.ImageReference, error) {
	return registry.tempStorage.GetImageReference(repo, reference)
}

// finalize a syncing image.
func (registry *LocalRegistry) CommitImage(imageReference types.ImageReference, repo, reference string) error {
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
			err = meta.SetImageMetaFromInput(repo, reference, mediaType,
				manifestDigest, manifestBlob, imageStore, registry.metaDB, registry.log)
			if err != nil {
				return fmt.Errorf("metaDB: failed to set metadata for image '%s %s': %w", repo, reference, err)
			}

			registry.log.Debug().Str("repo", repo).Str("reference", reference).Msg("metaDB: successfully set metadata for image")
		}
	}

	registry.log.Info().Str("image", fmt.Sprintf("%s:%s", repo, reference)).Msg("successfully synced image")

	return nil
}

func (registry *LocalRegistry) copyManifest(repo string, manifestContent []byte, reference string,
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
		err = meta.SetImageMetaFromInput(repo, reference, ispec.MediaTypeImageManifest,
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
func (registry *LocalRegistry) copyBlob(repo string, blobDigest digest.Digest, blobMediaType string,
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

func getImageStoreFromImageReference(imageReference types.ImageReference, repo, reference string,
) storageTypes.ImageStore {
	var tempRootDir string

	if strings.HasSuffix(imageReference.StringWithinTransport(), reference) {
		tempRootDir = strings.ReplaceAll(imageReference.StringWithinTransport(), fmt.Sprintf("%s:%s", repo, reference), "")
	} else {
		tempRootDir = strings.ReplaceAll(imageReference.StringWithinTransport(), fmt.Sprintf("%s:", repo), "")
	}

	metrics := monitoring.NewMetricsServer(false, log.Logger{})

	tempImageStore := local.NewImageStore(tempRootDir, false,
		storageConstants.DefaultGCDelay, false, false, log.Logger{}, metrics, nil, nil)

	return tempImageStore
}
