package repodb

import (
	"encoding/json"
	"errors"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// SyncRepoDB will sync all repos found in the rootdirectory of the oci layout that zot was deployed on.
func SyncRepoDB(repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	allRepos, err := getAllRepos(storeController)
	if err != nil {
		rootDir := storeController.DefaultStore.RootDir()
		log.Error().Err(err).Msgf("sync-repodb: failed to get all repo names present under %s", rootDir)

		return err
	}

	for _, repo := range allRepos {
		err := SyncRepo(repo, repoDB, storeController, log)
		if err != nil {
			log.Error().Err(err).Msgf("sync-repodb: failed to sync repo %s", repo)

			return err
		}
	}

	return nil
}

// SyncRepo reads the contents of a repo and syncs all images/signatures found. 
func SyncRepo(repo string, repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	imageStore := storeController.GetImageStore(repo)

	indexBlob, err := imageStore.GetIndexContent(repo)
	if err != nil {
		log.Error().Err(err).Msgf("sync-repo: failed to read index.json for repo %s", repo)

		return err
	}

	var indexContent ispec.Index

	err = json.Unmarshal(indexBlob, &indexContent)
	if err != nil {
		log.Error().Err(err).Msgf("sync-repo: failed to unmarshal index.json for repo %s", repo)

		return err
	}

	err = resetRepoMetaTags(repo, repoDB, log)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Error().Err(err).Msgf("sync-repo: failed to reset tag field in RepoMetadata for repo %s", repo)

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

		if !hasTag {
			log.Warn().Msgf("sync-repo: image without tag found, will not be synced into RepoDB")

			continue
		}

		manifestMetaIsPresent, err := isManifestMetaPresent(manifest, repoDB)
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: error checking manifestMeta in RepoDB")

			return err
		}

		if manifestMetaIsPresent {
			err = repoDB.SetRepoTag(repo, tag, manifest.Digest)
			if err != nil {
				log.Error().Err(err).Msgf("sync-repo: failed to set repo tag for %s:%s", repo, tag)

				return err
			}

			continue
		}

		manifestBlob, digest, _, err := imageStore.GetImageManifest(repo, manifest.Digest.String())
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: failed to set repo tag for %s:%s", repo, tag)

			return err
		}

		isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo,
			manifestBlob, tag, storeController)
		if err != nil {
			if errors.Is(err, zerr.ErrOrphanSignature) {
				continue
			} else {
				log.Error().Err(err).Msgf("sync-repo: failed checking if image is signature for %s:%s", repo, tag)

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

		manifestMeta, err := NewManifestMeta(repo, manifestBlob, storeController)
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: failed to create manifest meta for image %s:%s manifest digest %s ",
				repo, tag, manifest.Digest.String())

			return err
		}

		err = repoDB.SetManifestMeta(manifest.Digest, manifestMeta)
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: failed to set manifest meta for image %s:%s manifest digest %s ",
				repo, tag, manifest.Digest.String())

			return err
		}

		err = repoDB.SetRepoTag(repo, tag, manifest.Digest)
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: failed to repo tag for repo %s and tag %s",
				repo, tag)

			return err
		}
	}

	// manage the signatures found
	for _, sigData := range signaturesFound {
		err := repoDB.AddManifestSignature(godigest.Digest(sigData.signedManifestDigest), SignatureMetadata{
			SignatureType:   sigData.signatureType,
			SignatureDigest: godigest.Digest(sigData.signatureDigest),
		})
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: failed set signature meta for signed image %s:%s manifest digest %s ",
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
		log.Error().Err(err).Msgf("sync-repo: failed to get RepoMeta for repo %s", repo)

		return err
	}

	if errors.Is(err, zerr.ErrRepoMetaNotFound) {
		log.Info().Msgf("sync-repo: RepoMeta not found for repo %s, new RepoMeta will be created", repo)

		return nil
	}

	for tag := range repoMeta.Tags {
		// We should have a way to delete all tags at once
		err := repoDB.DeleteRepoTag(repo, tag)
		if err != nil {
			log.Error().Err(err).Msgf("sync-repo: failed to delete tag %s from RepoMeta for repo %s", tag, repo)

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

func isManifestMetaPresent(manifest ispec.Descriptor, repoDB RepoDB) (bool, error) {
	_, err := repoDB.GetManifestMeta(manifest.Digest)
	if err != nil && !errors.Is(err, zerr.ErrManifestMetaNotFound) {
		return false, err
	}

	if errors.Is(err, zerr.ErrManifestMetaNotFound) {
		return false, nil
	}

	return true, nil
}

// NewManifestMeta takes raw data about an image and createa a new ManifestMetadate object.
func NewManifestMeta(repoName string, manifestBlob []byte, storeController storage.StoreController,
) (ManifestMetadata, error) {
	const (
		configCount   = 1
		manifestCount = 1
	)

	var (
		manifestContent ispec.Manifest
		configContent   ispec.Image
		manifestMeta    ManifestMetadata
	)

	imgStore := storeController.GetImageStore(repoName)

	err := json.Unmarshal(manifestBlob, &manifestContent)
	if err != nil {
		return ManifestMetadata{}, err
	}

	configBlob, err := imgStore.GetBlobContent(repoName, manifestContent.Config.Digest)
	if err != nil {
		return ManifestMetadata{}, err
	}

	err = json.Unmarshal(configBlob, &configContent)
	if err != nil {
		return ManifestMetadata{}, err
	}

	manifestMeta.BlobsSize = len(configBlob) + len(manifestBlob)
	for _, layer := range manifestContent.Layers {
		manifestMeta.BlobsSize += int(layer.Size)
	}

	manifestMeta.BlobCount = configCount + manifestCount + len(manifestContent.Layers)
	manifestMeta.ManifestBlob = manifestBlob
	manifestMeta.ConfigBlob = configBlob

	return manifestMeta, nil
}
