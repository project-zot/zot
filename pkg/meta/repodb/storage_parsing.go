package repodb

import (
	"encoding/json"
	"errors"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// ParseStorage will sync all repos found in the rootdirectory of the oci layout that zot was deployed on with the
// ParseStorage database.
func ParseStorage(repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	allRepos, err := getAllRepos(storeController)
	if err != nil {
		rootDir := storeController.DefaultStore.RootDir()
		log.Error().Err(err).Str("rootDir", rootDir).
			Msg("load-local-layout: failed to get all repo names present under rootDir")

		return err
	}

	for _, repo := range allRepos {
		err := ParseRepo(repo, repoDB, storeController, log)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Msg("load-local-layout: failed to sync repo")

			return err
		}
	}

	return nil
}

// ParseRepo reads the contents of a repo and syncs all images and signatures found.
func ParseRepo(repo string, repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	imageStore := storeController.GetImageStore(repo)

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

	err = resetRepoMetaTags(repo, repoDB, log)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Str("repository", repo).Msg("load-repo: failed to reset tag field in RepoMetadata for repo")

		return err
	}

	for _, manifest := range indexContent.Manifests {
		tag, hasTag := manifest.Annotations[ispec.AnnotationRefName]

		manifestMetaIsPresent, err := isManifestMetaPresent(repo, manifest, repoDB)
		if err != nil {
			log.Error().Err(err).Msg("load-repo: error checking manifestMeta in RepoDB")

			return err
		}

		// this check helps reduce unecesary reads from storage
		if manifestMetaIsPresent && hasTag {
			err = repoDB.SetRepoReference(repo, tag, manifest.Digest, manifest.MediaType)
			if err != nil {
				log.Error().Err(err).Str("repository", repo).Str("tag", tag).Msg("load-repo: failed to set repo tag")

				return err
			}

			continue
		}

		manifestBlob, digest, _, err := imageStore.GetImageManifest(repo, manifest.Digest.String())
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", tag).
				Msg("load-repo: failed to set repo tag for image")

			return err
		}

		isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo,
			manifestBlob, tag)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", tag).
				Msg("load-repo: failed checking if image is signature for specified image")

			return err
		}

		if isSignature {
			err := repoDB.AddManifestSignature(repo, signedManifestDigest,
				SignatureMetadata{
					SignatureType:   signatureType,
					SignatureDigest: digest.String(),
				})
			if err != nil {
				log.Error().Err(err).Str("repository", repo).Str("tag", tag).
					Str("manifestDigest", signedManifestDigest.String()).
					Msg("load-repo: failed set signature meta for signed image manifest digest")

				return err
			}

			continue
		}

		reference := tag

		if tag == "" {
			reference = manifest.Digest.String()
		}

		err = SetImageMetaFromInput(repo, reference, manifest.MediaType, manifest.Digest, manifestBlob,
			imageStore, repoDB, log)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", tag).
				Msg("load-repo: failed to set metadata for image")

			return err
		}
	}

	return nil
}

// resetRepoMetaTags will delete all tags from a repometadata.
func resetRepoMetaTags(repo string, repoDB RepoDB, log log.Logger) error {
	repoMeta, err := repoDB.GetRepoMeta(repo)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Str("repository", repo).Msg("load-repo: failed to get RepoMeta for repo")

		return err
	}

	if errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Info().Str("repository", repo).Msg("load-repo: RepoMeta not found for repo, new RepoMeta will be created")

		return nil
	}

	return repoDB.SetRepoMeta(repo, RepoMetadata{
		Name:       repoMeta.Name,
		Tags:       map[string]Descriptor{},
		Statistics: repoMeta.Statistics,
		Signatures: map[string]ManifestSignatures{},
		Referrers:  map[string][]ReferrerInfo{},
		Stars:      repoMeta.Stars,
	})
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

// isManifestMetaPresent checks if the manifest with a certain digest is present in a certain repo.
func isManifestMetaPresent(repo string, manifest ispec.Descriptor, repoDB RepoDB) (bool, error) {
	_, err := repoDB.GetManifestMeta(repo, manifest.Digest)
	if err != nil && !errors.Is(err, zerr.ErrManifestMetaNotFound) {
		return false, err
	}

	if errors.Is(err, zerr.ErrManifestMetaNotFound) {
		return false, nil
	}

	return true, nil
}

// NewManifestMeta takes raw data about an image and createa a new ManifestMetadate object.
func NewManifestData(repoName string, manifestBlob []byte, imageStore storage.ImageStore,
) (ManifestData, error) {
	var (
		manifestContent ispec.Manifest
		configContent   ispec.Image
		manifestData    ManifestData
	)

	err := json.Unmarshal(manifestBlob, &manifestContent)
	if err != nil {
		return ManifestData{}, err
	}

	configBlob, err := imageStore.GetBlobContent(repoName, manifestContent.Config.Digest)
	if err != nil {
		return ManifestData{}, err
	}

	err = json.Unmarshal(configBlob, &configContent)
	if err != nil {
		return ManifestData{}, err
	}

	manifestData.ManifestBlob = manifestBlob
	manifestData.ConfigBlob = configBlob

	return manifestData, nil
}

func NewIndexData(repoName string, indexBlob []byte, imageStore storage.ImageStore,
) IndexData {
	indexData := IndexData{}

	indexData.IndexBlob = indexBlob

	return indexData
}

// SetMetadataFromInput tries to set manifest metadata and update repo metadata by adding the current tag
// (in case the reference is a tag). The function expects image manifests and indexes (multi arch images).
func SetImageMetaFromInput(repo, reference, mediaType string, digest godigest.Digest, descriptorBlob []byte,
	imageStore storage.ImageStore, repoDB RepoDB, log log.Logger,
) error {
	switch mediaType {
	case ispec.MediaTypeImageManifest:
		imageData, err := NewManifestData(repo, descriptorBlob, imageStore)
		if err != nil {
			return err
		}

		err = repoDB.SetManifestData(digest, imageData)
		if err != nil {
			log.Error().Err(err).Msg("repodb: error while putting manifest meta")

			return err
		}
	case ispec.MediaTypeImageIndex:
		indexData := NewIndexData(repo, descriptorBlob, imageStore)

		err := repoDB.SetIndexData(digest, indexData)
		if err != nil {
			log.Error().Err(err).Msg("repodb: error while putting index data")

			return err
		}
	}

	refferredDigest, referrerInfo, hasSubject, err := GetReferredSubject(descriptorBlob, digest.String(), mediaType)
	if hasSubject && err == nil {
		err := repoDB.SetReferrer(repo, refferredDigest, referrerInfo)
		if err != nil {
			log.Error().Err(err).Msg("repodb: error while settingg referrer")

			return err
		}
	}

	err = repoDB.SetRepoReference(repo, reference, digest, mediaType)
	if err != nil {
		log.Error().Err(err).Msg("repodb: error while putting repo meta")

		return err
	}

	return nil
}

func GetReferredSubject(descriptorBlob []byte, referrerDigest, mediaType string,
) (godigest.Digest, ReferrerInfo, bool, error) {
	var (
		referrerInfo    ReferrerInfo
		referrerSubject *ispec.Descriptor
	)

	var manifestContent ispec.Manifest

	err := json.Unmarshal(descriptorBlob, &manifestContent)
	if err != nil {
		return "", referrerInfo, false,
			fmt.Errorf("repodb: can't unmarshal manifest for digest %s: %w", referrerDigest, err)
	}

	referrerSubject = manifestContent.Subject

	referrerInfo = ReferrerInfo{
		Digest:       referrerDigest,
		MediaType:    mediaType,
		ArtifactType: zcommon.GetManifestArtifactType(manifestContent),
		Size:         len(descriptorBlob),
		Annotations:  manifestContent.Annotations,
	}

	if referrerSubject == nil || referrerSubject.Digest.String() == "" {
		return "", ReferrerInfo{}, false, nil
	}

	return referrerSubject.Digest, referrerInfo, true, nil
}
