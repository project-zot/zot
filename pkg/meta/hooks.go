package meta

import (
	"context"

	godigest "github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

// OnUpdateManifest is called when a new manifest is added. It updates metadb according to the type
// of image pushed(normal images, signatues, etc.). In care of any errors, it makes sure to keep
// consistency between metadb and the image store.
func OnUpdateManifest(ctx context.Context, repo, reference, mediaType string, digest godigest.Digest, body []byte,
	storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
) error {
	if zcommon.IsReferrersTag(reference) {
		return nil
	}

	imgStore := storeController.GetImageStore(repo)

	err := SetImageMetaFromInput(ctx, repo, reference, mediaType, digest, body,
		imgStore, metaDB, log)
	if err != nil {
		log.Info().Str("tag", reference).Str("repository", repo).Msg("uploading image meta was unsuccessful for tag in repo")

		if err := imgStore.DeleteImageManifest(repo, reference, false); err != nil {
			log.Error().Err(err).Str("reference", reference).Str("repository", repo).
				Msg("failed to remove image manifest in repo")

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
	if zcommon.IsReferrersTag(reference) {
		return nil
	}

	imgStore := storeController.GetImageStore(repo)

	isSignature, signatureType, signedManifestDigest, err := storage.CheckIsImageSignature(repo, manifestBlob,
		reference)
	if err != nil {
		log.Error().Err(err).Msg("failed to check if image is a signature or not")

		return err
	}

	manageRepoMetaSuccessfully := true

	if isSignature {
		err = metaDB.DeleteSignature(repo, signedManifestDigest, mTypes.SignatureMetadata{
			SignatureDigest: digest.String(),
			SignatureType:   signatureType,
		})
		if err != nil {
			log.Error().Err(err).Str("component", "metadb").
				Msg("failed to check if image is a signature or not")
			manageRepoMetaSuccessfully = false
		}
	} else {
		err = metaDB.RemoveRepoReference(repo, reference, digest)
		if err != nil {
			log.Info().Str("component", "metadb").Msg("restoring image store")

			// restore image store
			_, _, err := imgStore.PutImageManifest(repo, reference, mediaType, manifestBlob)
			if err != nil {
				log.Error().Err(err).Str("component", "metadb").
					Msg("failed to restore manifest to image store, database is not consistent")
			}

			manageRepoMetaSuccessfully = false
		}
	}

	if !manageRepoMetaSuccessfully {
		log.Info().Str("tag", reference).Str("repository", repo).Str("component", "metadb").
			Msg("failed to delete image meta was unsuccessful for tag in repo")

		return err
	}

	return nil
}

// OnGetManifest is called when a manifest is downloaded. It increments the download couter on that manifest.
func OnGetManifest(name, reference, mediaType string, body []byte,
	storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
) error {
	// check if image is a signature
	isSignature, _, _, err := storage.CheckIsImageSignature(name, body, reference)
	if err != nil {
		log.Error().Err(err).Msg("failed to check if manifest is a signature or not")

		return err
	}

	if isSignature || zcommon.IsReferrersTag(reference) {
		return nil
	}

	if !(mediaType == v1.MediaTypeImageManifest || mediaType == v1.MediaTypeImageIndex) {
		return nil
	}

	err = metaDB.UpdateStatsOnDownload(name, reference)
	if err != nil {
		log.Error().Err(err).Str("repository", name).Str("reference", reference).
			Msg("failed to update stats on download image")

		return err
	}

	return nil
}
