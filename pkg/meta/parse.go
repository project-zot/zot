package meta

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/convert"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

const (
	CosignType   = "cosign"
	NotationType = "notation"
)

// ParseStorage will sync all repos found in the rootdirectory of the oci layout that zot was deployed on with the
// ParseStorage database.
func ParseStorage(metaDB mTypes.MetaDB, storeController storage.StoreController, log log.Logger) error {
	log.Info().Msg("Started parsing storage and updating MetaDB")

	allRepos, err := getAllRepos(storeController)
	if err != nil {
		rootDir := storeController.DefaultStore.RootDir()
		log.Error().Err(err).Str("rootDir", rootDir).
			Msg("load-local-layout: failed to get all repo names present under rootDir")

		return err
	}

	for i, repo := range allRepos {
		log.Info().Int("total", len(allRepos)).Int("progress", i).Str("current-repo", repo).
			Msgf("parsing next repo '%s'", repo)

		err := ParseRepo(repo, metaDB, storeController, log)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Msg("load-local-layout: failed to sync repo")

			return err
		}
	}

	log.Info().Msg("Done parsing storage and updating MetaDB")

	return nil
}

// ParseRepo reads the contents of a repo and syncs all images and signatures found.
func ParseRepo(repo string, metaDB mTypes.MetaDB, storeController storage.StoreController, log log.Logger) error {
	imageStore := storeController.GetImageStore(repo)

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	indexBlob, err := imageStore.GetIndexContent(repo)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Msg("load-repo: failed to read index.json for repo")

		return err
	}

	var indexContent ispec.Index

	err = json.Unmarshal(indexBlob, &indexContent)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Msg("load-repo: failed to unmarshal index.json for repo")

		return err
	}

	err = metaDB.ResetRepoReferences(repo)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Str("repository", repo).Msg("load-repo: failed to reset tag field in RepoMetadata for repo")

		return err
	}

	for _, manifest := range indexContent.Manifests {
		tag := manifest.Annotations[ispec.AnnotationRefName]

		if zcommon.IsReferrersTag(tag) {
			continue
		}

		manifestBlob, _, _, err := imageStore.GetImageManifest(repo, manifest.Digest.String())
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("digest", manifest.Digest.String()).
				Msg("load-repo: failed to get blob for image")

			return err
		}

		reference := tag

		if tag == "" {
			reference = manifest.Digest.String()
		}

		err = SetImageMetaFromInput(context.Background(), repo, reference, manifest.MediaType, manifest.Digest, manifestBlob,
			imageStore, metaDB, log)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", tag).
				Msg("load-repo: failed to set metadata for image")

			return err
		}
	}

	return nil
}

func getAllRepos(storeController storage.StoreController) ([]string, error) {
	allRepos, err := storeController.DefaultStore.GetRepositories()
	if err != nil {
		return nil, err
	}

	if storeController.SubStore != nil {
		for _, store := range storeController.SubStore {
			substoreRepos, err := store.GetRepositories()
			if err != nil {
				return nil, err
			}

			allRepos = append(allRepos, substoreRepos...)
		}
	}

	return allRepos, nil
}

func GetSignatureLayersInfo(repo, tag, manifestDigest, signatureType string, manifestBlob []byte,
	imageStore storageTypes.ImageStore, log log.Logger,
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
	repo, tag, manifestDigest string, manifestBlob []byte, imageStore storageTypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	layers := []mTypes.LayerInfo{}

	var manifestContent ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("digest", manifestDigest).Msg(
			"load-repo: unable to marshal blob index")

		return layers, err
	}

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	for _, layer := range manifestContent.Layers {
		layerContent, err := imageStore.GetBlobContent(repo, layer.Digest)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("layerDigest", layer.Digest.String()).Msg(
				"load-repo: unable to get cosign signature layer content")

			return layers, err
		}

		layerSigKey, ok := layer.Annotations[zcommon.CosignSigKey]
		if !ok {
			log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("layerDigest", layer.Digest.String()).Msg(
				"load-repo: unable to get specific annotation of cosign signature")
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
	repo, manifestDigest string, manifestBlob []byte, imageStore storageTypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	layers := []mTypes.LayerInfo{}

	var manifestContent ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", manifestDigest).Msg(
			"load-repo: unable to marshal blob index")

		return layers, err
	}

	// skip if is a notation index
	if manifestContent.MediaType == ispec.MediaTypeImageIndex {
		return []mTypes.LayerInfo{}, nil
	}

	if len(manifestContent.Layers) != 1 {
		log.Error().Err(zerr.ErrBadManifest).Str("repository", repo).Str("reference", manifestDigest).
			Msg("load-repo: notation signature manifest requires exactly one layer but it does not")

		return layers, zerr.ErrBadManifest
	}

	layer := manifestContent.Layers[0].Digest

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	layerContent, err := imageStore.GetBlobContent(repo, layer)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", manifestDigest).Str("layerDigest", layer.String()).Msg(
			"load-repo: unable to get notation signature blob content")

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

// SetMetadataFromInput tries to set manifest metadata and update repo metadata by adding the current tag
// (in case the reference is a tag). The function expects image manifests and indexes (multi arch images).
func SetImageMetaFromInput(ctx context.Context, repo, reference, mediaType string, digest godigest.Digest, blob []byte,
	imageStore storageTypes.ImageStore, metaDB mTypes.MetaDB, log log.Logger,
) error {
	var imageMeta mTypes.ImageMeta

	switch mediaType {
	case ispec.MediaTypeImageManifest:
		manifestContent := ispec.Manifest{}
		configContent := ispec.Image{}

		err := json.Unmarshal(blob, &manifestContent)
		if err != nil {
			log.Error().Err(err).Msg("metadb: error while getting image data")

			return err
		}

		if manifestContent.Config.MediaType == ispec.MediaTypeImageConfig {
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
					Msg("load-repo: failed set signature meta for signed image")

				return err
			}

			err = metaDB.UpdateSignaturesValidity(repo, signedManifestDigest)
			if err != nil {
				log.Error().Err(err).Str("repository", repo).Str("reference", reference).Str("digest",
					signedManifestDigest.String()).Msg("load-repo: failed verify signatures validity for signed image")

				return err
			}

			return nil
		}

		imageMeta = convert.GetImageManifestMeta(manifestContent, configContent, int64(len(blob)), digest)
	case ispec.MediaTypeImageIndex:
		indexContent := ispec.Index{}

		err := json.Unmarshal(blob, &indexContent)
		if err != nil {
			return err
		}

		imageMeta = convert.GetImageIndexMeta(indexContent, int64(len(blob)), digest)
	default:
		return nil
	}

	err := metaDB.SetRepoReference(ctx, repo, reference, imageMeta)
	if err != nil {
		log.Error().Err(err).Msg("metadb: error while setting repo meta")

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
	if manifestArtifactType == zcommon.ArtifactTypeCosign && manifestContent.Subject != nil {
		return true, CosignType, manifestContent.Subject.Digest
	}

	if tag := reference; zcommon.IsCosignTag(reference) {
		prefixLen := len("sha256-")
		digestLen := 64
		signedImageManifestDigestEncoded := tag[prefixLen : prefixLen+digestLen]

		signedImageManifestDigest := godigest.NewDigestFromEncoded(godigest.SHA256,
			signedImageManifestDigestEncoded)

		return true, CosignType, signedImageManifestDigest
	}

	return false, "", ""
}
