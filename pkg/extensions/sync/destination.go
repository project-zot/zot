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

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	storageCommon "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

// Platform represents an OS/architecture/variant combination
type Platform struct {
	OS           string
	Architecture string
	Variant      string
}

// ParsePlatform parses a platform string into a Platform struct
// The string can be in the following formats:
// - "arch" (e.g., "amd64")
// - "os/arch" (e.g., "linux/amd64")
// - "os/arch/variant" (e.g., "linux/arm/v7")
func ParsePlatform(platform string) Platform {
	parts := strings.Split(platform, "/")
	if len(parts) == 3 {
		return Platform{
			OS:           parts[0],
			Architecture: parts[1],
			Variant:      parts[2],
		}
	} else if len(parts) == 2 {
		return Platform{
			OS:           parts[0],
			Architecture: parts[1],
		}
	}
	// For any other case, assume only architecture is specified
	return Platform{
		OS:           "",
		Architecture: platform,
	}
}

// MatchesPlatform checks if the given platform matches any of the platform specifications
// Platform specs can be in format "os/arch/variant", "os/arch", or just "arch"
func MatchesPlatform(platform *ispec.Platform, platformSpecs []string) bool {
	if platform == nil || len(platformSpecs) == 0 {
		return true
	}

	for _, spec := range platformSpecs {
		specPlatform := ParsePlatform(spec)

		// Check if architecture matches
		if specPlatform.Architecture != "" &&
			specPlatform.Architecture != platform.Architecture {
			continue
		}

		// Check if OS matches (if specified)
		if specPlatform.OS != "" &&
			specPlatform.OS != platform.OS {
			continue
		}

		// Check if variant matches (if specified)
		if specPlatform.Variant != "" && platform.Variant != "" &&
			specPlatform.Variant != platform.Variant {
			continue
		}

		// If we got here, it's a match
		return true
	}

	return false
}

type DestinationRegistry struct {
	storeController storage.StoreController
	tempStorage     OciLayoutStorage
	metaDB          mTypes.MetaDB
	log             log.Logger
	config          *syncconf.RegistryConfig // Config used for filtering architectures
}

func NewDestinationRegistry(
	storeController storage.StoreController, // local store controller
	tempStoreController storage.StoreController, // temp store controller
	metaDB mTypes.MetaDB,
	log log.Logger,
	config ...*syncconf.RegistryConfig, // optional config for filtering
) Destination {
	var cfg *syncconf.RegistryConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	return &DestinationRegistry{
		storeController: storeController,
		tempStorage:     NewOciLayoutStorage(tempStoreController),
		metaDB:          metaDB,
		// first we sync from remote (using containers/image copy from docker:// to oci:) to a temp imageStore
		// then we copy the image from tempStorage to zot's storage using ImageStore APIs
		log:    log,
		config: cfg,
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

		// Filter manifests based on platforms/architectures if configured
		var filteredManifests []ispec.Descriptor

		// Determine which platform specifications to use
		var platformSpecs []string
		if registry.config != nil {
			if len(registry.config.Platforms) > 0 {
				platformSpecs = registry.config.Platforms
				registry.log.Info().
					Strs("platforms", registry.config.Platforms).
					Str("repository", repo).
					Str("reference", reference).
					Msg("filtering manifest list by platforms")
			}
		}

		// Apply filtering if we have platform specifications
		if len(platformSpecs) > 0 {
			for _, manifest := range indexManifest.Manifests {
				if manifest.Platform != nil {
					// Check if this platform should be included
					if MatchesPlatform(manifest.Platform, platformSpecs) {
						filteredManifests = append(filteredManifests, manifest)
					} else {
						platformDesc := manifest.Platform.Architecture
						if manifest.Platform.OS != "" {
							platformDesc = manifest.Platform.OS + "/" + manifest.Platform.Architecture
							if manifest.Platform.Variant != "" {
								platformDesc += "/" + manifest.Platform.Variant
							}
						}

						registry.log.Info().
							Str("repository", repo).
							Str("platform", platformDesc).
							Msg("skipping platform during sync")
					}
				} else {
					// No platform info, include the manifest
					filteredManifests = append(filteredManifests, manifest)
				}
			}

			// If we have no filtered manifests but had original ones, warn
			if len(filteredManifests) == 0 && len(indexManifest.Manifests) > 0 {
				registry.log.Warn().
					Str("repository", repo).
					Str("reference", reference).
					Msg("no platform matched the configured filters, manifest list might be empty")
			}
		} else {
			// No filtering, use all manifests
			filteredManifests = indexManifest.Manifests
		}

		// Process the filtered manifests
		for _, manifest := range filteredManifests {
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

		// If we've filtered the manifest list, we need to update it
		if registry.config != nil &&
			len(registry.config.Platforms) > 0 &&
			len(filteredManifests) != len(indexManifest.Manifests) && len(filteredManifests) > 0 {
			// Create a new index with the filtered manifests
			indexManifest.Manifests = filteredManifests

			// Update the manifest content with the filtered list
			updatedContent, err := json.Marshal(indexManifest)
			if err != nil {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("repository", repo).
					Msg("failed to marshal updated index manifest")
				return err
			}

			manifestContent = updatedContent
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
