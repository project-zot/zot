//go:build sync
// +build sync

package references

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type OciReferences struct {
	client          *client.Client
	storeController storage.StoreController
	metaDB          mTypes.MetaDB
	log             log.Logger
}

func NewOciReferences(httpClient *client.Client, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) OciReferences {
	return OciReferences{
		client:          httpClient,
		storeController: storeController,
		metaDB:          metaDB,
		log:             log,
	}
}

func (ref OciReferences) Name() string {
	return constants.OCI
}

func (ref OciReferences) IsSigned(ctx context.Context, remoteRepo, subjectDigestStr string) bool {
	// use artifactTypeFilter
	index, err := ref.getIndex(ctx, remoteRepo, subjectDigestStr)
	if err != nil {
		return false
	}

	if len(getNotationManifestsFromOCIRefs(index)) > 0 || len(getCosignManifestsFromOCIRefs(index)) > 0 {
		return true
	}

	return false
}

func (ref OciReferences) canSkipReferences(localRepo, subjectDigestStr string, index ispec.Index) (bool, error) {
	imageStore := ref.storeController.GetImageStore(localRepo)
	digest := godigest.Digest(subjectDigestStr)

	// check oci references already synced
	if len(index.Manifests) > 0 {
		localRefs, err := imageStore.GetReferrers(localRepo, digest, nil)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't get local oci references for image")

			return false, err
		}

		if !descriptorsEqual(localRefs.Manifests, index.Manifests) {
			ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("remote oci references for image changed, syncing again")

			return false, nil
		}
	}

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("skipping oci references for image, already synced")

	return true, nil
}

func (ref OciReferences) SyncReferences(ctx context.Context, localRepo, remoteRepo, subjectDigestStr string) (
	[]godigest.Digest, error,
) {
	refsDigests := make([]godigest.Digest, 0, 10)

	index, err := ref.getIndex(ctx, remoteRepo, subjectDigestStr)
	if err != nil {
		return refsDigests, err
	}

	skipOCIRefs, err := ref.canSkipReferences(localRepo, subjectDigestStr, index)
	if err != nil {
		ref.log.Error().Err(err).Str("repository", localRepo).Str("subject", subjectDigestStr).
			Msg("couldn't check if the upstream oci references for image can be skipped")
	}

	if skipOCIRefs {
		/* even if it's skip we need to return the digests,
		because maybe in the meantime a reference pointing to this one was pushed */
		for _, man := range index.Manifests {
			refsDigests = append(refsDigests, man.Digest)
		}

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
		Msg("successfully synced oci references for image")

	return refsDigests, nil
}

func (ref OciReferences) getIndex(ctx context.Context, repo, subjectDigestStr string) (ispec.Index, error) {
	var index ispec.Index

	_, _, statusCode, err := ref.client.MakeGetRequest(ctx, &index, ispec.MediaTypeImageIndex,
		"v2", repo, "referrers", subjectDigestStr)
	if err != nil {
		if statusCode == http.StatusNotFound {
			ref.log.Debug().Str("repository", repo).Str("subject", subjectDigestStr).
				Msg("couldn't find any oci reference for image, skipping")

			return index, zerr.ErrSyncReferrerNotFound
		}

		return index, err
	}

	return index, nil
}

func syncManifest(ctx context.Context, client *client.Client, imageStore storageTypes.ImageStore, localRepo,
	remoteRepo string, desc ispec.Descriptor, subjectDigestStr string, log log.Logger,
) ([]byte, godigest.Digest, error) {
	var manifest ispec.Manifest

	var refDigest godigest.Digest

	OCIRefBuf, _, statusCode, err := client.MakeGetRequest(ctx, &manifest, ispec.MediaTypeImageManifest,
		"v2", remoteRepo, "manifests", desc.Digest.String())
	if err != nil {
		if statusCode == http.StatusNotFound {
			return []byte{}, refDigest, zerr.ErrSyncReferrerNotFound
		}

		log.Error().Str("errorType", common.TypeOf(err)).
			Str("repository", localRepo).Str("subject", subjectDigestStr).
			Err(err).Msg("couldn't get oci reference manifest for image")

		return []byte{}, refDigest, err
	}

	if desc.MediaType == ispec.MediaTypeImageManifest {
		// read manifest
		var manifest ispec.Manifest

		err = json.Unmarshal(OCIRefBuf, &manifest)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't unmarshal oci reference manifest for image")

			return []byte{}, refDigest, err
		}

		for _, layer := range manifest.Layers {
			if err := syncBlob(ctx, client, imageStore, localRepo, remoteRepo, layer.Digest, log); err != nil {
				return []byte{}, refDigest, err
			}
		}

		// sync config blob
		if err := syncBlob(ctx, client, imageStore, localRepo, remoteRepo, manifest.Config.Digest, log); err != nil {
			return []byte{}, refDigest, err
		}
	} else {
		return []byte{}, refDigest, nil
	}

	refDigest, _, err = imageStore.PutImageManifest(localRepo, desc.Digest.String(),
		desc.MediaType, OCIRefBuf)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Str("repository", localRepo).Str("subject", subjectDigestStr).
			Err(err).Msg("couldn't upload oci reference for image")

		return []byte{}, refDigest, err
	}

	return OCIRefBuf, refDigest, nil
}
