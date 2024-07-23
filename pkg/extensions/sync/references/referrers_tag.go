//go:build sync
// +build sync

package references

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/sync/constants"
	client "zotregistry.dev/zot/pkg/extensions/sync/httpclient"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

type TagReferences struct {
	client          *client.Client
	storeController storage.StoreController
	metaDB          mTypes.MetaDB
	log             log.Logger
}

func NewTagReferences(httpClient *client.Client, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) TagReferences {
	return TagReferences{
		client:          httpClient,
		storeController: storeController,
		metaDB:          metaDB,
		log:             log,
	}
}

func (ref TagReferences) Name() string {
	return constants.Tag
}

func (ref TagReferences) IsSigned(ctx context.Context, remoteRepo, subjectDigestStr string) bool {
	return false
}

func (ref TagReferences) canSkipReferences(localRepo, subjectDigestStr, digest string) (bool, error) {
	imageStore := ref.storeController.GetImageStore(localRepo)

	_, localDigest, _, err := imageStore.GetImageManifest(localRepo, getReferrersTagFromSubjectDigest(subjectDigestStr))
	if err != nil {
		if errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		ref.log.Error().Str("errorType", common.TypeOf(err)).
			Str("repository", localRepo).Str("subject", subjectDigestStr).
			Err(err).Msg("couldn't get local index with referrers tag for image")

		return false, err
	}

	if localDigest.String() != digest {
		return false, nil
	}

	ref.log.Info().Str("repository", localRepo).Str("reference", subjectDigestStr).
		Msg("skipping index with referrers tag for image, already synced")

	return true, nil
}

func (ref TagReferences) SyncReferences(ctx context.Context, localRepo, remoteRepo, subjectDigestStr string) (
	[]godigest.Digest, error,
) {
	refsDigests := make([]godigest.Digest, 0, 10)

	index, indexContent, err := ref.getIndex(ctx, remoteRepo, subjectDigestStr)
	if err != nil {
		return refsDigests, err
	}

	skipTagRefs, err := ref.canSkipReferences(localRepo, subjectDigestStr, string(godigest.FromBytes(indexContent)))
	if err != nil {
		ref.log.Error().Err(err).Str("repository", localRepo).Str("subject", subjectDigestStr).
			Msg("couldn't check if the upstream index with referrers tag for image can be skipped")
	}

	if skipTagRefs {
		return refsDigests, nil
	}

	imageStore := ref.storeController.GetImageStore(localRepo)

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("syncing oci references for image")

	for _, referrer := range index.Manifests {
		referenceBuf, referenceDigest, err := syncManifest(ctx, ref.client, imageStore, localRepo, remoteRepo,
			referrer, subjectDigestStr, ref.log)
		if err != nil {
			return refsDigests, err
		}

		refsDigests = append(refsDigests, referenceDigest)

		if ref.metaDB != nil {
			ref.log.Debug().Str("repository", localRepo).Str("subject", subjectDigestStr).Str("component", "metadb").
				Msg("trying to add oci references for image")

			err = meta.SetImageMetaFromInput(ctx, localRepo, referenceDigest.String(), referrer.MediaType,
				referenceDigest, referenceBuf, ref.storeController.GetImageStore(localRepo),
				ref.metaDB, ref.log)
			if err != nil {
				return refsDigests, fmt.Errorf("failed to set metadata for oci reference in '%s@%s': %w",
					localRepo, subjectDigestStr, err)
			}

			ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).Str("component", "metadb").
				Msg("successfully added oci references to MetaDB for image")
		}
	}

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("syncing index with referrers tag for image")

	referrersTag := getReferrersTagFromSubjectDigest(subjectDigestStr)

	_, _, err = imageStore.PutImageManifest(localRepo, referrersTag, index.MediaType, indexContent)
	if err != nil {
		ref.log.Error().Str("errorType", common.TypeOf(err)).
			Str("repository", localRepo).Str("subject", subjectDigestStr).
			Err(err).Msg("couldn't upload index with referrers tag for image")

		return refsDigests, err
	}

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("successfully synced index with referrers tag for image")

	return refsDigests, nil
}

func (ref TagReferences) getIndex(
	ctx context.Context, repo, subjectDigestStr string,
) (ispec.Index, []byte, error) {
	var index ispec.Index

	content, _, statusCode, err := ref.client.MakeGetRequest(ctx, &index, ispec.MediaTypeImageIndex,
		"v2", repo, "manifests", getReferrersTagFromSubjectDigest(subjectDigestStr))
	if err != nil {
		if statusCode == http.StatusNotFound {
			ref.log.Debug().Str("repository", repo).Str("subject", subjectDigestStr).
				Msg("couldn't find any index with referrers tag for image, skipping")

			return index, []byte{}, zerr.ErrSyncReferrerNotFound
		}

		return index, []byte{}, err
	}

	return index, content, nil
}

func getReferrersTagFromSubjectDigest(digestStr string) string {
	return strings.Replace(digestStr, ":", "-", 1)
}
