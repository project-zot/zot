package repodb

import (
	"encoding/json"
	"errors"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func SyncRepoDB(repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	allRepos, err := getAllRepos(storeController)
	if err != nil {
		return err
	}

	for _, repo := range allRepos {
		err := SyncRepo(repo, repoDB, storeController, log)
		if err != nil {
			return err
		}
	}

	return nil
}

func SyncRepo(repo string, repoDB RepoDB, storeController storage.StoreController, log log.Logger) error {
	imageStore := storeController.GetImageStore(repo)

	indexBlob, err := imageStore.GetIndexContent(repo)
	if err != nil {
		return err
	}

	var indexContent ispec.Index

	err = json.Unmarshal(indexBlob, &indexContent)
	if err != nil {
		return err
	}

	err = resetRepoMetaTags(repo, repoDB)
	if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
		return err
	}

	type foundSignatureData struct {
		signatureType        string
		signedManifestDigest string
		signatureDigest      string
	}

	var signaturesFound []foundSignatureData

	for _, manifest := range indexContent.Manifests {
		tag, hasTag := manifest.Annotations[ispec.AnnotationRefName]

		if !hasTag {
			continue
		}

		manifestMetaIsPresent, err := isManifestMetaPresent(manifest, repoDB)
		if err != nil {
			return err
		}

		if manifestMetaIsPresent {
			err = repoDB.SetRepoTag(repo, tag, manifest.Digest.String())
			if err != nil {
				return err
			}

			continue
		}

		manifestBlob, digest, _, err := imageStore.GetImageManifest(repo, manifest.Digest.String())
		if err != nil {
			return err
		}

		isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo,
			manifestBlob, manifest.Digest.String(), storeController)
		if err != nil {
			return err
		}

		if isSignature {
			// We'll ignore signatures now because the order in which the signed image and signature are added into
			// the DB matters. First we add the normal images then the signatures
			signaturesFound = append(signaturesFound, foundSignatureData{
				signatureType:        signatureType,
				signedManifestDigest: signedManifestDigest,
				signatureDigest:      digest,
			})

			continue
		}

		manifestMeta, err := NewManifestMeta(repo, manifestBlob, storeController)
		if err != nil {
			return err
		}

		err = repoDB.SetManifestMeta(manifest.Digest.String(), manifestMeta)
		if err != nil {
			return err
		}

		err = repoDB.SetRepoTag(repo, tag, manifest.Digest.String())
		if err != nil {
			return err
		}
	}

	// manage the signatures found
	for _, sigData := range signaturesFound {
		err := repoDB.AddManifestSignature(sigData.signedManifestDigest, SignatureMetadata{
			SignatureType:   sigData.signatureType,
			SignatureDigest: sigData.signatureDigest,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func resetRepoMetaTags(repo string, repoDB RepoDB) error {
	repoMeta, err := repoDB.GetRepoMeta(repo)
	if err != nil {
		return err
	}

	for tag := range repoMeta.Tags {
		// We should have a way to delete all tags at once
		err := repoDB.DeleteRepoTag(repo, tag)
		if err != nil {
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
	_, err := repoDB.GetManifestMeta(manifest.Digest.String())
	if err != nil && !errors.Is(err, zerr.ErrManifestMetaNotFound) {
		return false, err
	}

	if errors.Is(err, zerr.ErrManifestMetaNotFound) {
		return false, nil
	}

	return true, nil
}

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

	configBlob, err := imgStore.GetBlobContent(repoName, manifestContent.Config.Digest.String())
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
