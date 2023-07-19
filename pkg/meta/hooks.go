package meta

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/common"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

// OnUpdateManifest is called when a new manifest is added. It updates metadb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between metadb and the image store.
func OnUpdateManifest(repo, reference, mediaType string, digest godigest.Digest, body []byte,
	storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
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
		layersInfo, errGetLayers := GetSignatureLayersInfo(repo, reference, digest.String(), signatureType, body,
			imgStore, log)
		if errGetLayers != nil {
			metadataSuccessfullySet = false
			err = errGetLayers
		} else {
			err = metaDB.AddManifestSignature(repo, signedManifestDigest, mTypes.SignatureMetadata{
				SignatureType:   signatureType,
				SignatureDigest: digest.String(),
				LayersInfo:      layersInfo,
			})
			if err != nil {
				log.Error().Err(err).Msg("metadb: error while putting repo meta")
				metadataSuccessfullySet = false
			} else {
				err = metaDB.UpdateSignaturesValidity(repo, signedManifestDigest)
				if err != nil {
					log.Error().Err(err).Str("repository", repo).Str("reference", reference).Str("digest",
						signedManifestDigest.String()).Msg("metadb: failed verify signatures validity for signed image")
					metadataSuccessfullySet = false
				}
			}
		}
	} else {
		err = SetImageMetaFromInput(repo, reference, mediaType, digest, body,
			imgStore, metaDB, log)
		if err != nil {
			metadataSuccessfullySet = false
		}
	}

	if !metadataSuccessfullySet {
		log.Info().Str("tag", reference).Str("repository", repo).Msg("uploading image meta was unsuccessful for tag in repo")

		if err := imgStore.DeleteImageManifest(repo, reference, false); err != nil {
			log.Error().Err(err).Str("reference", reference).Str("repository", repo).
				Msg("couldn't remove image manifest in repo")

			return err
		}

		return err
	}

	return nil
}

// OnDeleteManifest is called when a manifest is deleted. It updates metadb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between metadb and the image store.
func OnDeleteManifest(repo, reference, mediaType string, digest godigest.Digest, manifestBlob []byte,
	storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
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
		err = metaDB.DeleteSignature(repo, signedManifestDigest, mTypes.SignatureMetadata{
			SignatureDigest: digest.String(),
			SignatureType:   signatureType,
		})
		if err != nil {
			log.Error().Err(err).Msg("metadb: can't check if image is a signature or not")
			manageRepoMetaSuccessfully = false
		}
	} else {
		err = metaDB.DeleteRepoTag(repo, reference)
		if err != nil {
			log.Info().Msg("metadb: restoring image store")

			// restore image store
			_, _, err := imgStore.PutImageManifest(repo, reference, mediaType, manifestBlob)
			if err != nil {
				log.Error().Err(err).Msg("metadb: error while restoring image store, database is not consistent")
			}

			manageRepoMetaSuccessfully = false
		}

		if referredDigest, hasSubject := common.GetReferredSubject(manifestBlob); hasSubject {
			err := metaDB.DeleteReferrer(repo, referredDigest, digest)
			if err != nil {
				log.Error().Err(err).Msg("metadb: error while deleting referrer")

				return err
			}
		}
	}

	if !manageRepoMetaSuccessfully {
		log.Info().Str("tag", reference).Str("repository", repo).
			Msg("metadb: deleting image meta was unsuccessful for tag in repo")

		return err
	}

	return nil
}

// OnDeleteManifest is called when a manifest is downloaded. It increments the download couter on that manifest.
func OnGetManifest(name, reference string, body []byte,
	storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
) error {
	// check if image is a signature
	isSignature, _, _, err := storage.CheckIsImageSignature(name, body, reference)
	if err != nil {
		log.Error().Err(err).Msg("can't check if manifest is a signature or not")

		return err
	}

	if !isSignature {
		err := metaDB.IncrementImageDownloads(name, reference)
		if err != nil {
			log.Error().Err(err).Str("repository", name).Str("reference", reference).
				Msg("unexpected error for image")

			return err
		}
	}

	return nil
}
