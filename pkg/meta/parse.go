package meta

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/convert"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

const (
	CosignType   = "cosign"
	NotationType = "notation"
)

// parseStats tracks per-repo outcomes of a storage walk.
type parseStats struct {
	failedRepos  int // skipped on a StatIndex or ParseRepo error
	partialRepos int // parsed, but a manifest blob was missing
}

// complete reports whether the walk fully populated the metaDB.
func (s parseStats) complete() bool {
	return s.failedRepos == 0 && s.partialRepos == 0
}

// ParseStorage will sync all repos found in the rootdirectory of the oci layout that zot was deployed on with the
// ParseStorage database.
func ParseStorage(metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger) error {
	_, err := parseStorage(metaDB, storeController, log)

	return err
}

// parseStorage runs the storage walk, returning per-repo outcomes in parseStats.
// Per-repo failures are logged and skipped. Only enumeration or deletion errors
// abort the walk and return a non-nil error.
func parseStorage(metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger) (parseStats, error) {
	log.Info().Str("component", "metadb").Msg("parsing storage and initializing")

	var stats parseStats

	allStorageRepos, err := getAllRepos(storeController, log)
	if err != nil {
		return parseStats{}, err
	}

	allMetaDBRepos, err := metaDB.GetAllRepoNames()
	if err != nil {
		rootDir := storeController.GetDefaultImageStore().RootDir()
		log.Error().Err(err).Str("component", "metadb").Str("rootDir", rootDir).
			Msg("failed to get all repo names present under rootDir")

		return parseStats{}, err
	}

	for _, repo := range getReposToBeDeleted(allStorageRepos, allMetaDBRepos) {
		err := metaDB.DeleteRepoMeta(repo)
		if err != nil {
			log.Error().Err(err).Str("rootDir", storeController.GetImageStore(repo).RootDir()).Str("component", "metadb").
				Str("repo", repo).Msg("failed to delete repo meta")

			return parseStats{}, err
		}
	}

	for i, repo := range allStorageRepos {
		log.Info().Int("total", len(allStorageRepos)).Int("progress", i).Str("current-repo", repo).
			Msgf("parsing next repo '%s'", repo)

		imgStore := storeController.GetImageStore(repo)

		_, _, storageLastUpdated, err := imgStore.StatIndex(repo)
		if err != nil {
			log.Error().Err(err).Str("rootDir", imgStore.RootDir()).
				Str("repo", repo).Msg("failed to sync repo")

			stats.failedRepos++

			continue
		}

		metaLastUpdated := metaDB.GetRepoLastUpdated(repo)

		// If repo metadata doesn't exist (zero time), always parse it
		// Otherwise, only parse if storage is newer than metadata
		if !metaLastUpdated.IsZero() && storageLastUpdated.Before(metaLastUpdated) {
			continue
		}

		partial, err := parseRepo(repo, metaDB, storeController, log)
		if err != nil {
			log.Error().Err(err).Str("repo", repo).Str("rootDir", imgStore.RootDir()).Msg("failed to sync repo")

			stats.failedRepos++

			continue
		}

		if partial {
			stats.partialRepos++
		}
	}

	log.Info().Str("component", "metadb").Msg("successfully initialized")

	return stats, nil
}

// FastRestartStamp combines this binary's identity (binaryVersion, from version.CurrentBinaryVersion)
// with a fingerprint of the storage config into the stamp used to gate a fast restart.
func FastRestartStamp(binaryVersion, storageFingerprint string) string {
	if binaryVersion == "" || storageFingerprint == "" {
		return ""
	}

	return binaryVersion + "|" + storageFingerprint
}

// MaybeParseStorage conditionally runs ParseStorage based on a fast-restart stamp stored in metaDB.
// When fastRestart is true and the metaDB carries a stamp matching this binary and storage config,
// the full walk is skipped under the assumption that metaDB is consistent with storage from the
// previous run.
func MaybeParseStorage(metaDB mTypes.MetaDB, storeController stypes.StoreController,
	fastRestart bool, fastRestartStamp string, log log.Logger,
) error {
	if fastRestart {
		if fastRestartStamp == "" {
			log.Info().Str("component", "metadb").
				Msg("fast-restart enabled but no stamp is available; falling back to full parse")
		} else {
			storedStamp, err := metaDB.GetFastRestartStamp()
			switch {
			case err != nil:
				log.Warn().Err(err).Str("component", "metadb").
					Msg("failed to read fast-restart stamp, falling back to full parse")
			case storedStamp == fastRestartStamp:
				log.Info().Str("component", "metadb").Str("fastRestartStamp", storedStamp).
					Msg("metaDB fast-restart stamp matches, skipping full storage parse")

				return nil
			case storedStamp == "":
				log.Info().Str("component", "metadb").
					Msg("metaDB has no fast-restart stamp, running full parse")
			default:
				log.Info().Str("component", "metadb").
					Str("storedStamp", storedStamp).Str("currentStamp", fastRestartStamp).
					Msg("metaDB fast-restart stamp differs, running full parse")
			}
		}
	}

	stats, err := parseStorage(metaDB, storeController, log)
	if err != nil {
		return err
	}

	if fastRestartStamp == "" {
		// go run/go test builds have no stamp, so always reparse.
		return nil
	}

	// Leave the stamp untouched on an incomplete walk so the next restart
	// reparses and can recover.
	if !stats.complete() {
		log.Warn().Str("component", "metadb").
			Int("failedRepos", stats.failedRepos).Int("partialRepos", stats.partialRepos).
			Msg("storage parse incomplete; skipping fast-restart stamp so the next restart reparses")

		return nil
	}

	if err := metaDB.SetFastRestartStamp(fastRestartStamp); err != nil {
		log.Warn().Err(err).Str("component", "metadb").
			Msg("failed to write fast-restart stamp; next restart will reparse")
	}

	return nil
}

// getReposToBeDeleted will return all repos that are found in metaDB but not found in storage anymore.
func getReposToBeDeleted(allStorageRepos []string, allMetaDBRepos []string) []string {
	toBeDeleted := []string{}

	storageRepoNameSet := make(map[string]struct{}, len(allStorageRepos))

	for i := range allStorageRepos {
		storageRepoNameSet[allStorageRepos[i]] = struct{}{}
	}

	for _, metaDBRepo := range allMetaDBRepos {
		if _, found := storageRepoNameSet[metaDBRepo]; !found {
			toBeDeleted = append(toBeDeleted, metaDBRepo)
		}
	}

	return toBeDeleted
}

// ParseRepo reads the contents of a repo and syncs all images and signatures found.
func ParseRepo(repo string, metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger) error {
	_, err := parseRepo(repo, metaDB, storeController, log)

	return err
}

// parseRepo syncs all images and signatures in a repo. It returns partial=true
// when a manifest was skipped because its blob is missing, so the caller knows
// the metaDB is incomplete even though no error was returned.
func parseRepo(repo string, metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger,
) (bool, error) {
	imageStore := storeController.GetImageStore(repo)

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	indexBlob, err := imageStore.GetIndexContent(repo)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Msg("failed to read index.json for repo")

		return false, err
	}

	var indexContent ispec.Index

	err = json.Unmarshal(indexBlob, &indexContent)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Msg("failed to unmarshal index.json for repo")

		return false, err
	}

	// Collect tags that exist in storage to preserve them
	tagsToKeep := make(map[string]bool)

	for _, manifest := range indexContent.Manifests {
		tag := manifest.Annotations[ispec.AnnotationRefName]
		if tag != "" && !zcommon.IsReferrersTag(tag) {
			tagsToKeep[tag] = true
		}
	}

	err = metaDB.ResetRepoReferences(repo, tagsToKeep)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Str("repository", repo).Msg("failed to reset tag field in RepoMetadata for repo")

		return false, err
	}

	partial := false

	for _, manifest := range indexContent.Manifests {
		tag := manifest.Annotations[ispec.AnnotationRefName]

		if zcommon.IsReferrersTag(tag) {
			continue
		}

		manifestBlob, err := imageStore.GetBlobContent(repo, manifest.Digest)
		if err != nil {
			// Handle missing blobs gracefully - log warning and continue with other manifests
			var pathNotFoundErr driver.PathNotFoundError
			if errors.Is(err, zerr.ErrBlobNotFound) || errors.As(err, &pathNotFoundErr) {
				log.Warn().Err(err).Str("repository", repo).Str("digest", manifest.Digest.String()).
					Msg("skipping missing manifest blob, continuing repo parse")

				partial = true

				continue
			}

			log.Error().Err(err).Str("repository", repo).Str("digest", manifest.Digest.String()).
				Msg("failed to get blob for image")

			return false, err
		}

		reference := tag

		if tag == "" {
			reference = manifest.Digest.String()
		}

		err = SetImageMetaFromInput(context.Background(), repo, reference, manifest.MediaType, manifest.Digest, manifestBlob,
			imageStore, metaDB, log)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", tag).
				Msg("failed to set metadata for image")

			return false, err
		}
	}

	return partial, nil
}

func getAllRepos(storeController stypes.StoreController, log log.Logger) ([]string, error) {
	allRepos := make([]string, 0)
	repoSet := make(map[string]struct{})

	// Process substores first
	if storeController.GetImageSubStores() != nil {
		for _, store := range storeController.GetImageSubStores() {
			substoreRepos, err := store.GetRepositories()
			if err != nil {
				log.Error().Err(err).Str("rootDir", store.RootDir()).
					Msg("failed to get all repo names present under rootDir")

				return nil, err
			}

			for _, repo := range substoreRepos {
				if _, exists := repoSet[repo]; !exists {
					allRepos = append(allRepos, repo)
					repoSet[repo] = struct{}{}
				}
			}
		}
	}

	// Process default store, skipping repos already in the set
	defaultRepos, err := storeController.GetDefaultImageStore().GetRepositories()
	if err != nil {
		log.Error().Err(err).Str("rootDir", storeController.GetDefaultImageStore().RootDir()).
			Msg("failed to get all repo names present under rootDir")

		return nil, err
	}

	for _, repo := range defaultRepos {
		if _, exists := repoSet[repo]; !exists {
			allRepos = append(allRepos, repo)
			repoSet[repo] = struct{}{}
		}
	}

	return allRepos, nil
}

func GetSignatureLayersInfo(repo, tag, manifestDigest, signatureType string, manifestBlob []byte,
	imageStore stypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	switch signatureType {
	case zcommon.CosignSignature:
		return getCosignSignatureLayersInfo(repo, tag, manifestDigest, manifestBlob, imageStore, log)
	case zcommon.NotationSignature:
		return getNotationSignatureLayersInfo(repo, manifestDigest, manifestBlob, imageStore, log)
	default:
		return []mTypes.LayerInfo{}, nil
	}
}

func getCosignSignatureLayersInfo(
	repo, tag, manifestDigest string, manifestBlob []byte, imageStore stypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	layers := []mTypes.LayerInfo{}

	var manifestContent ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("digest", manifestDigest).Msg(
			"failed to marshal blob index")

		return layers, err
	}

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	for _, layer := range manifestContent.Layers {
		layerContent, err := imageStore.GetBlobContent(repo, layer.Digest)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("layerDigest", layer.Digest.String()).Msg(
				"failed to get cosign signature layer content")

			return layers, err
		}

		layerSigKey, ok := layer.Annotations[zcommon.CosignSigKey]
		if !ok {
			log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("layerDigest", layer.Digest.String()).Msg(
				"failed to get specific annotation of cosign signature")
		}

		layers = append(layers, mTypes.LayerInfo{
			LayerDigest:  layer.Digest.String(),
			LayerContent: layerContent,
			SignatureKey: layerSigKey,
		})
	}

	return layers, nil
}

func getNotationSignatureLayersInfo(
	repo, manifestDigest string, manifestBlob []byte, imageStore stypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	layers := []mTypes.LayerInfo{}

	var manifestContent ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", manifestDigest).Msg(
			"failed to marshal blob index")

		return layers, err
	}

	// skip if is a notation index
	if manifestContent.MediaType == ispec.MediaTypeImageIndex {
		return []mTypes.LayerInfo{}, nil
	}

	if len(manifestContent.Layers) != 1 {
		log.Error().Err(zerr.ErrBadManifest).Str("repository", repo).Str("reference", manifestDigest).
			Msg("notation signature manifest requires exactly one layer but it does not")

		return layers, zerr.ErrBadManifest
	}

	layer := manifestContent.Layers[0].Digest

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	layerContent, err := imageStore.GetBlobContent(repo, layer)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", manifestDigest).Str("layerDigest", layer.String()).Msg(
			"failed to get notation signature blob content")

		return layers, err
	}

	layerSigKey := manifestContent.Layers[0].MediaType

	layers = append(layers, mTypes.LayerInfo{
		LayerDigest:  layer.String(),
		LayerContent: layerContent,
		SignatureKey: layerSigKey,
	})

	return layers, nil
}

// SetImageMetaFromInput tries to set manifest metadata and update repo metadata by adding the current tag
// (in case the reference is a tag). The function expects image manifests and indexes (multi arch images).
func SetImageMetaFromInput(ctx context.Context, repo, reference, mediaType string, digest godigest.Digest, blob []byte,
	imageStore stypes.ImageStore, metaDB mTypes.MetaDB, log log.Logger,
) error {
	var imageMeta mTypes.ImageMeta

	if mediaType == ispec.MediaTypeImageManifest || compat.IsCompatibleManifestMediaType(mediaType) { //nolint:gocritic,lll // mixing checking mechanisms
		manifestContent := ispec.Manifest{}
		configContent := ispec.Image{}

		err := json.Unmarshal(blob, &manifestContent)
		if err != nil {
			log.Error().Err(err).Str("component", "metadb").Msg("failed to unmarshal image manifest")

			return err
		}

		if manifestContent.Config.MediaType == ispec.MediaTypeImageConfig ||
			compat.IsCompatibleConfigMediaType(manifestContent.Config.MediaType) {
			configBlob, err := imageStore.GetBlobContent(repo, manifestContent.Config.Digest)
			if err != nil {
				return err
			}

			err = json.Unmarshal(configBlob, &configContent)
			if err != nil {
				return err
			}
		}

		if isSig, sigType, signedManifestDigest := isSignature(reference, manifestContent); isSig {
			layers, err := GetSignatureLayersInfo(repo, reference, digest.String(), sigType,
				blob, imageStore, log)
			if err != nil {
				return err
			}

			err = metaDB.AddManifestSignature(repo, signedManifestDigest,
				mTypes.SignatureMetadata{
					SignatureType:   sigType,
					SignatureDigest: digest.String(),
					SignatureTag:    reference,
					LayersInfo:      layers,
				})
			if err != nil {
				log.Error().Err(err).Str("repository", repo).Str("tag", reference).
					Str("manifestDigest", signedManifestDigest.String()).
					Msg("failed set signature meta for signed image")

				return err
			}

			err = metaDB.UpdateSignaturesValidity(ctx, repo, signedManifestDigest)
			if err != nil {
				log.Error().Err(err).Str("repository", repo).Str("reference", reference).Str("digest",
					signedManifestDigest.String()).Msg("failed to verify signature validity for signed image")

				return err
			}

			return nil
		}

		imageMeta = convert.GetImageManifestMeta(manifestContent, configContent, int64(len(blob)), digest)
	} else if mediaType == ispec.MediaTypeImageIndex || compat.IsCompatibleManifestListMediaType(mediaType) {
		indexContent := ispec.Index{}

		err := json.Unmarshal(blob, &indexContent)
		if err != nil {
			return err
		}

		imageMeta = convert.GetImageIndexMeta(indexContent, int64(len(blob)), digest)
	} else {
		return nil
	}

	err := metaDB.SetRepoReference(ctx, repo, reference, imageMeta)
	if err != nil {
		log.Error().Err(err).Str("component", "metadb").Msg("failed to set repo meta")

		return err
	}

	return nil
}

func isSignature(reference string, manifestContent ispec.Manifest) (bool, string, godigest.Digest) {
	manifestArtifactType := zcommon.GetManifestArtifactType(manifestContent)

	// check notation signature
	if manifestArtifactType == zcommon.ArtifactTypeNotation && manifestContent.Subject != nil {
		return true, NotationType, manifestContent.Subject.Digest
	}

	// check cosign signature
	if zcommon.IsArtifactTypeCosign(manifestArtifactType) && manifestContent.Subject != nil {
		return true, CosignType, manifestContent.Subject.Digest
	}

	if tag := reference; zcommon.IsCosignSignature(reference) {
		prefixLen := len("sha256-")
		digestLen := 64
		signedImageManifestDigestEncoded := tag[prefixLen : prefixLen+digestLen]

		signedImageManifestDigest := godigest.NewDigestFromEncoded(godigest.SHA256,
			signedImageManifestDigestEncoded)

		return true, CosignType, signedImageManifestDigest
	}

	return false, "", ""
}
