package repodb

import (
	"encoding/json"
	"errors"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// ParseStorage will sync all repos found in the rootdirectory of the oci layout that zot was deployed on with the
// ParseStorage database.
func ParseStorage(repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	allRepos, err := getAllRepos(storeController)
	if err != nil {
		rootDir := storeController.DefaultStore.RootDir()
		log.Error().Err(err).Msgf("load-local-layout: failed to get all repo names present under %s", rootDir)

		return err
	}

	for _, repo := range allRepos {
		err := ParseRepo(repo, repoDB, storeController, log)
		if err != nil {
			log.Error().Err(err).Msgf("load-local-layout: failed to sync repo %s", repo)

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
		log.Error().Err(err).Msgf("load-repo: failed to read index.json for repo %s", repo)

		return err
	}

	var indexContent ispec.Index

	err = json.Unmarshal(indexBlob, &indexContent)
	if err != nil {
		log.Error().Err(err).Msgf("load-repo: failed to unmarshal index.json for repo %s", repo)

		return err
	}

	err = resetRepoMetaTags(repo, repoDB, log)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Msgf("load-repo: failed to reset tag field in RepoMetadata for repo %s", repo)

		return err
	}

	type foundSignatureData struct {
		repo                 string
		tag                  string
		signatureType        string
		signedManifestDigest string
		signatureDigest      string
	}

	var signaturesFound []foundSignatureData

	for _, manifest := range indexContent.Manifests {
		tag, hasTag := manifest.Annotations[ispec.AnnotationRefName]

		manifestMetaIsPresent, err := isManifestMetaPresent(repo, manifest, repoDB)
		if err != nil {
			log.Error().Err(err).Msgf("load-repo: error checking manifestMeta in RepoDB")

			return err
		}

		if manifestMetaIsPresent && hasTag {
			err = repoDB.SetRepoReference(repo, tag, manifest.Digest, manifest.MediaType)
			if err != nil {
				log.Error().Err(err).Msgf("load-repo: failed to set repo tag for %s:%s", repo, tag)

				return err
			}

			continue
		}

		manifestBlob, digest, _, err := imageStore.GetImageManifest(repo, manifest.Digest.String())
		if err != nil {
			log.Error().Err(err).Msgf("load-repo: failed to set repo tag for %s:%s", repo, tag)

			return err
		}

		isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo,
			manifestBlob, tag, storeController)
		if err != nil {
			if errors.Is(err, zerr.ErrOrphanSignature) {
				continue
			} else {
				log.Error().Err(err).Msgf("load-repo: failed checking if image is signature for %s:%s", repo, tag)

				return err
			}
		}

		if isSignature {
			// We'll ignore signatures now because the order in which the signed image and signature are added into
			// the DB matters. First we add the normal images then the signatures
			signaturesFound = append(signaturesFound, foundSignatureData{
				repo:                 repo,
				tag:                  tag,
				signatureType:        signatureType,
				signedManifestDigest: signedManifestDigest.String(),
				signatureDigest:      digest.String(),
			})

			continue
		}

		reference := tag

		if tag == "" {
			reference = manifest.Digest.String()
		}

		err = SetMetadataFromInput(repo, reference, manifest.MediaType, manifest.Digest, manifestBlob,
			imageStore, repoDB, log)
		if err != nil {
			log.Error().Err(err).Msgf("load-repo: failed to set metadata for %s:%s", repo, tag)

			return err
		}
	}

	// manage the signatures found
	for _, sigData := range signaturesFound {
		err := repoDB.AddManifestSignature(repo, godigest.Digest(sigData.signedManifestDigest),
			SignatureMetadata{
				SignatureType:   sigData.signatureType,
				SignatureDigest: sigData.signatureDigest,
			})
		if err != nil {
			log.Error().Err(err).Msgf("load-repo: failed set signature meta for signed image %s:%s manifest digest %s ",
				sigData.repo, sigData.tag, sigData.signedManifestDigest)

			return err
		}
	}

	return nil
}

// resetRepoMetaTags will delete all tags from a repometadata.
func resetRepoMetaTags(repo string, repoDB RepoDB, log log.Logger) error {
	repoMeta, err := repoDB.GetRepoMeta(repo)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Msgf("load-repo: failed to get RepoMeta for repo %s", repo)

		return err
	}

	if errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Info().Msgf("load-repo: RepoMeta not found for repo %s, new RepoMeta will be created", repo)

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

func NewArtifactData(repo string, descriptorBlob []byte, imageStore storage.ImageStore,
) ArtifactData {
	return ArtifactData{
		ManifestBlob: descriptorBlob,
	}
}

// SetMetadataFromInput tries to set manifest metadata and update repo metadata by adding the current tag
// (in case the reference is a tag). The function expects image manifests and indexes (multi arch images).
func SetMetadataFromInput(repo, reference, mediaType string, digest godigest.Digest, descriptorBlob []byte,
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
	case ispec.MediaTypeArtifactManifest:
		artifactData := NewArtifactData(repo, descriptorBlob, imageStore)

		err := repoDB.SetArtifactData(digest, artifactData)
		if err != nil {
			log.Error().Err(err).Msg("repodb: error while putting artifact data")

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

	switch mediaType {
	case ispec.MediaTypeImageManifest:
		var manifestContent ispec.Manifest

		err := json.Unmarshal(descriptorBlob, &manifestContent)
		if err != nil {
			return "", referrerInfo, false,
				fmt.Errorf("repodb: can't unmarhsal manifest for digest %s: %w", referrerDigest, err)
		}

		referrerSubject = manifestContent.Subject

		referrerInfo = ReferrerInfo{
			Digest:       referrerDigest,
			MediaType:    mediaType,
			ArtifactType: manifestContent.Config.MediaType,
			Size:         len(descriptorBlob),
			Annotations:  manifestContent.Annotations,
		}
	case ispec.MediaTypeArtifactManifest:
		manifestContent := ispec.Artifact{}

		err := json.Unmarshal(descriptorBlob, &manifestContent)
		if err != nil {
			return "", referrerInfo, false,
				fmt.Errorf("repodb: can't unmarhsal artifact manifest for digest %s: %w", referrerDigest, err)
		}

		referrerSubject = manifestContent.Subject

		referrerInfo = ReferrerInfo{
			Digest:       referrerDigest,
			MediaType:    manifestContent.MediaType,
			ArtifactType: manifestContent.ArtifactType,
			Size:         len(descriptorBlob),
			Annotations:  manifestContent.Annotations,
		}
	}

	if referrerSubject == nil || referrerSubject.Digest.String() == "" {
		return "", ReferrerInfo{}, false, nil
	}

	return referrerSubject.Digest, referrerInfo, true, nil
}
