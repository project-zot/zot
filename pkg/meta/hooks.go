package meta

import (
	"context"
	"errors"

	godigest "github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// priorTagManifest records where MetaDB believed each tag pointed before a digest PUT with tag=
// parameters could move it. Rollback loads manifest bytes from the blob store (GetBlobContent).
type priorTagManifest struct {
	digest    godigest.Digest
	mediaType string
}

// priorTagManifestsFromMetaDB returns digest and media type from RepoMeta for tags that already
// exist in metadb. Omitted tags are new or unknown to metadb. ErrRepoMetaNotFound yields an empty
// map. Rollback reads manifest blobs from storage via GetBlobContent(prior.digest).
// If a tag exists only in the image store and not in metadb, rollback cannot restore a moved tag
// (metadb and storage should stay in sync during normal operation).
func priorTagManifestsFromMetaDB(ctx context.Context, metaDB mTypes.MetaDB, repo string, tags []string,
) (map[string]priorTagManifest, error) {
	empty := map[string]priorTagManifest{}

	if len(tags) == 0 {
		return empty, nil
	}

	repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return empty, nil
		}

		return nil, err
	}

	if len(repoMeta.Tags) == 0 {
		return empty, nil
	}

	out := make(map[string]priorTagManifest, len(tags))

	for _, tag := range tags {
		desc, ok := repoMeta.Tags[tag]
		if !ok || desc.Digest == "" {
			continue
		}

		dgst, parseErr := godigest.Parse(desc.Digest)
		if parseErr != nil {
			continue
		}

		descMediaType := desc.MediaType
		if descMediaType == "" {
			descMediaType = v1.MediaTypeImageManifest
		}

		out[tag] = priorTagManifest{
			digest:    dgst,
			mediaType: descMediaType,
		}
	}

	return out, nil
}

// rollbackDigestManifestTags deletes every tag in tags from the image store (this PUT added them to the
// index). It runs OnDeleteManifest only for tags in appliedMetaTags: those had a successful meta update for
// digest and must be reverted. Calling OnDeleteManifest for other tags is unsafe—RemoveRepoReference can
// drop a tag entry even when metadb still maps that tag to a different digest (e.g. meta not updated yet).
// When priorTagManifests has an entry for a tag, it re-applies that manifest so moved tags point at their
// original digest again.
func rollbackDigestManifestTags(ctx context.Context, repo string, tags, appliedMetaTags []string, mediaType string,
	digest godigest.Digest,
	body []byte, storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
	priorTagManifests map[string]priorTagManifest,
) {
	imgStore := storeController.GetImageStore(repo)

	for i := len(tags) - 1; i >= 0; i-- {
		refTag := tags[i]
		if delErr := imgStore.DeleteImageManifest(context.Background(), repo, refTag, false); delErr != nil &&
			!errors.Is(delErr, zerr.ErrManifestNotFound) {
			log.Error().Err(delErr).Str("repository", repo).Str("tag", refTag).
				Msg("multi-tag digest push: rollback DeleteImageManifest failed")
		}
	}

	for i := len(appliedMetaTags) - 1; i >= 0; i-- {
		refTag := appliedMetaTags[i]

		metaDelErr := OnDeleteManifest(repo, refTag, mediaType, digest, body, storeController, metaDB, log)
		if metaDelErr != nil {
			log.Error().Err(metaDelErr).Str("repository", repo).Str("tag", refTag).
				Msg("multi-tag digest push: rollback OnDeleteManifest failed")
		}
	}

	if len(priorTagManifests) == 0 {
		return
	}

	for _, refTag := range tags {
		prior, ok := priorTagManifests[refTag]
		if !ok {
			continue
		}

		restoreBody, blobErr := imgStore.GetBlobContent(repo, prior.digest)
		if blobErr != nil {
			log.Error().Err(blobErr).Str("repository", repo).Str("tag", refTag).
				Msg("multi-tag digest push: rollback load prior manifest blob failed")

			continue
		}

		if _, _, putErr := imgStore.PutImageManifest(context.Background(), repo, prior.digest.String(), prior.mediaType,
			restoreBody, []string{refTag}); putErr != nil {
			log.Error().Err(putErr).Str("repository", repo).Str("tag", refTag).
				Msg("multi-tag digest push: rollback restore prior manifest in store failed")

			continue
		}

		if metaErr := OnUpdateManifest(ctx, repo, refTag, prior.mediaType, prior.digest, restoreBody,
			storeController, metaDB, log); metaErr != nil {
			log.Error().Err(metaErr).Str("repository", repo).Str("tag", refTag).
				Msg("multi-tag digest push: rollback restore prior metadb failed")
		}
	}
}

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

		if err := imgStore.DeleteImageManifest(ctx, repo, reference, false); err != nil {
			log.Error().Err(err).Str("reference", reference).Str("repository", repo).
				Msg("failed to remove image manifest in repo")

			return err
		}

		return err
	}

	return nil
}

// OnUpdateManifestDigestTags updates metadb for each tag from a digest-addressed manifest push that used
// repeated `tag=` query parameters. It snapshots each tag's prior digest and media type from MetaDB
// (GetRepoMeta) before updates, then calls OnUpdateManifest per tag; on the first failure it removes
// every tag in tags from the image store, reverts MetaDB only for tags that had already completed
// OnUpdateManifest successfully, and restores moved tags using the snapshot (see rollbackDigestManifestTags).
func OnUpdateManifestDigestTags(ctx context.Context, repo string, tags []string, mediaType string,
	digest godigest.Digest, body []byte,
	storeController storage.StoreController, metaDB mTypes.MetaDB, log log.Logger,
) error {
	if len(tags) == 0 {
		return nil
	}

	priorTagManifests, err := priorTagManifestsFromMetaDB(ctx, metaDB, repo, tags)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).
			Msg("multi-tag digest push: failed to snapshot prior tag state from metadb")

		return err
	}

	applied := make([]string, 0, len(tags))

	for _, tag := range tags {
		if err := OnUpdateManifest(ctx, repo, tag, mediaType, digest, body, storeController, metaDB, log); err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", tag).
				Msg("multi-tag digest push: meta update failed; rolling back tag query additions")

			rollbackDigestManifestTags(ctx, repo, tags, applied, mediaType, digest, body, storeController, metaDB, log,
				priorTagManifests)

			return err
		}

		applied = append(applied, tag)
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
			_, _, err := imgStore.PutImageManifest(context.Background(), repo, reference, mediaType, manifestBlob, nil)
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

	if !(mediaType == v1.MediaTypeImageManifest || mediaType == v1.MediaTypeImageIndex ||
		compat.IsCompatibleManifestMediaType(mediaType) || compat.IsCompatibleManifestListMediaType(mediaType)) {
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
