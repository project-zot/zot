package meta

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/common"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

// OnUpdateManifest is called when a new manifest is added. It updates repodb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between repodb and the image store.
func OnUpdateManifest(repo, reference, mediaType string, digest godigest.Digest, body []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	imgStore := storeController.GetImageStore(repo)

	// check if image is a signature
	isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo, body, reference)
	if err != nil {
		log.Error().Err(err).Msg("can't check if image is a signature or not")

		if err := imgStore.DeleteImageManifest(repo, reference, false); err != nil {
			log.Error().Err(err).Str("manifest", reference).Str("repository", repo).Msg("couldn't remove image manifest in repo")

			return err
		}

		return err
	}

	metadataSuccessfullySet := true

	if isSignature {
		err = repoDB.AddManifestSignature(repo, signedManifestDigest, repodb.SignatureMetadata{
			SignatureType:   signatureType,
			SignatureDigest: digest.String(),
		})
		if err != nil {
			log.Error().Err(err).Msg("repodb: error while putting repo meta")
			metadataSuccessfullySet = false
		}
	} else {
		err := repodb.SetImageMetaFromInput(repo, reference, mediaType, digest, body,
			imgStore, repoDB, log)
		if err != nil {
			metadataSuccessfullySet = false
		}
	}

	if !metadataSuccessfullySet {
		log.Info().Str("tag", reference).Str("repository", repo).Msg("uploding image meta was unsuccessful for tag in repo")

		if err := imgStore.DeleteImageManifest(repo, reference, false); err != nil {
			log.Error().Err(err).Str("reference", reference).Str("repository", repo).
				Msg("couldn't remove image manifest in repo")

			return err
		}

		return err
	}

	return nil
}

// OnDeleteManifest is called when a manifest is deleted. It updates repodb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between repodb and the image store.
func OnDeleteManifest(repo, reference, mediaType string, digest godigest.Digest, manifestBlob []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	imgStore := storeController.GetImageStore(repo)

	isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo, manifestBlob,
		reference)
	if err != nil {
		log.Error().Err(err).Msg("can't check if image is a signature or not")

		return err
	}

	manageRepoMetaSuccessfully := true

	if isSignature {
		err = repoDB.DeleteSignature(repo, signedManifestDigest, repodb.SignatureMetadata{
			SignatureDigest: digest.String(),
			SignatureType:   signatureType,
		})
		if err != nil {
			log.Error().Err(err).Msg("repodb: can't check if image is a signature or not")
			manageRepoMetaSuccessfully = false
		}
	} else {
		err = repoDB.DeleteRepoTag(repo, reference)
		if err != nil {
			log.Info().Msg("repodb: restoring image store")

			// restore image store
			_, _, err := imgStore.PutImageManifest(repo, reference, mediaType, manifestBlob)
			if err != nil {
				log.Error().Err(err).Msg("repodb: error while restoring image store, database is not consistent")
			}

			manageRepoMetaSuccessfully = false
		}

		if refferredDigest, hasSubject := common.GetReferredSubject(manifestBlob); hasSubject {
			err := repoDB.DeleteReferrer(repo, refferredDigest, digest)
			if err != nil {
				log.Error().Err(err).Msg("repodb: error while deleting referrer")

				return err
			}
		}
	}

	if !manageRepoMetaSuccessfully {
		log.Info().Str("tag", reference).Str("repository", repo).
			Msg("repodb: deleting image meta was unsuccessful for tag in repo")

		return err
	}

	return nil
}

// OnDeleteManifest is called when a manifest is downloaded. It increments the download couter on that manifest.
func OnGetManifest(name, reference string, body []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	// check if image is a signature
	isSignature, _, _, err := storage.CheckIsImageSignature(name, body, reference)
	if err != nil {
		log.Error().Err(err).Msg("can't check if manifest is a signature or not")

		return err
	}

	if !isSignature {
		err := repoDB.IncrementImageDownloads(name, reference)
		if err != nil {
			log.Error().Err(err).Str("repository", name).Str("reference", reference).
				Msg("unexpected error for image")

			return err
		}
	}

	return nil
}
