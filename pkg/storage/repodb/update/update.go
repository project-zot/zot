package update

import (
	godigest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/repodb"
)

// OnUpdateManifest is called when a new manifest is added. It updates repodb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between repodb and the image store.
func OnUpdateManifest(name, reference string, digest godigest.Digest, body []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	imgStore := storeController.GetImageStore(name)

	// check if image is a signature
	isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(name, body, reference,
		storeController)
	if err != nil {
		if errors.Is(err, zerr.ErrOrphanSignature) {
			log.Warn().Err(err).Msg("image has signature format but it doesn't sign any image")

			return nil
		}

		log.Error().Err(err).Msg("can't check if image is a signature or not")

		// TODO:
		if err := imgStore.DeleteImageManifest(name, reference, false); err != nil {
			log.Error().Err(err).Msgf("couldn't remove image manifest %s in repo %s", reference, name)

			return err
		}

		return err
	}

	metadataSuccessfullySet := true

	if isSignature {
		err = repoDB.AddManifestSignature(signedManifestDigest, repodb.SignatureMetadata{
			SignatureType:   signatureType,
			SignatureDigest: digest,
		})
		if err != nil {
			log.Error().Err(err).Msg("repodb: error while putting repo meta")
			metadataSuccessfullySet = false
		}
	} else {
		err := setMetadataFromInput(name, reference, digest, body,
			storeController, repoDB, log)
		if err != nil {
			metadataSuccessfullySet = false
		}
	}

	if !metadataSuccessfullySet {
		log.Info().Msgf("uploding image meta was unsuccessful for tag %s in repo %s", reference, name)

		// TODO:
		if err := imgStore.DeleteImageManifest(name, reference, false); err != nil {
			log.Error().Err(err).Msgf("couldn't remove image manifest %s in repo %s", reference, name)

			return err
		}

		return err
	}

	return nil
}

// OnDeleteManifest is called when a manifest is deleted. It updates repodb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between repodb and the image store.
func OnDeleteManifest(name, reference, mediaType string, digest godigest.Digest, manifestBlob []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	imgStore := storeController.GetImageStore(name)

	isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(name, manifestBlob,
		reference, storeController)
	if err != nil {
		if errors.Is(err, zerr.ErrOrphanSignature) {
			log.Warn().Err(err).Msg("image has signature format but it doesn't sign any image")

			return zerr.ErrOrphanSignature
		}

		log.Error().Err(err).Msg("can't check if image is a signature or not")

		return err
	}

	manageRepoMetaSuccessfully := true

	if isSignature {
		err = repoDB.DeleteSignature(signedManifestDigest, repodb.SignatureMetadata{
			SignatureDigest: godigest.Digest(reference),
			SignatureType:   signatureType,
		})
		if err != nil {
			log.Error().Err(err).Msg("repodb: can't check if image is a signature or not")
			manageRepoMetaSuccessfully = false
		}
	} else {
		err = repoDB.DeleteRepoTag(name, reference)
		if err != nil {
			log.Info().Msg("repodb: restoring image store")

			// restore image store
			_, err := imgStore.PutImageManifest(name, reference, mediaType, manifestBlob)
			if err != nil {
				log.Error().Err(err).Msg("repodb: error while restoring image store, database is not consistent")
			}

			manageRepoMetaSuccessfully = false
		}
	}

	if !manageRepoMetaSuccessfully {
		log.Info().Msgf("repodb: deleting image meta was unsuccessful for tag %s in repo %s", reference, name)

		return err
	}

	return nil
}

// OnDeleteManifest is called when a manifest is downloaded. It increments the download couter on that manifest.
func OnGetManifest(name, reference string, digest godigest.Digest, body []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	// check if image is a signature
	isSignature, _, _, err := storage.CheckIsImageSignature(name, body, reference,
		storeController)
	if err != nil {
		if errors.Is(err, zerr.ErrOrphanSignature) {
			log.Warn().Err(err).Msg("image has signature format but it doesn't sign any image")

			return err
		} else {
			log.Error().Err(err).Msg("can't check if manifest is a signature or not")

			return err
		}
	}

	if !isSignature {
		err := repoDB.IncrementManifestDownloads(digest)
		if err != nil {
			log.Error().Err(err).Msg("unexpected error")

			return err
		}
	}

	return nil
}

// setMetadataFromInput recieves raw information about the manifest pushed and tries to set manifest metadata
// and update repo metadata by adding the current tag (in case the reference is a tag).
// The function expects image manifest.
func setMetadataFromInput(repo, reference string, digest godigest.Digest, manifestBlob []byte,
	storeController storage.StoreController, repoDB repodb.RepoDB, log log.Logger,
) error {
	imageMetadata, err := repodb.NewManifestMeta(repo, manifestBlob, storeController)
	if err != nil {
		return err
	}

	err = repoDB.SetManifestMeta(digest, imageMetadata)
	if err != nil {
		log.Error().Err(err).Msg("repodb: error while putting image meta")

		return err
	}

	if refferenceIsDigest(reference) {
		return nil
	}

	err = repoDB.SetRepoTag(repo, reference, digest)
	if err != nil {
		log.Error().Err(err).Msg("repodb: error while putting repo meta")

		return err
	}

	return nil
}

func refferenceIsDigest(reference string) bool {
	_, err := godigest.Parse(reference)

	return err == nil
}
