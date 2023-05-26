//go:build sync
// +build sync

package references

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/sync/constants"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

type CosignReference struct {
	client          *client.Client
	storeController storage.StoreController
	repoDB          metaTypes.RepoDB
	log             log.Logger
}

func NewCosignReference(httpClient *client.Client, storeController storage.StoreController,
	repoDB metaTypes.RepoDB, log log.Logger,
) CosignReference {
	return CosignReference{
		client:          httpClient,
		storeController: storeController,
		repoDB:          repoDB,
		log:             log,
	}
}

func (ref CosignReference) Name() string {
	return constants.Cosign
}

func (ref CosignReference) IsSigned(upstreamRepo, subjectDigestStr string) bool {
	cosignSignatureTag := getCosignSignatureTagFromSubjectDigest(subjectDigestStr)
	_, err := ref.getManifest(upstreamRepo, cosignSignatureTag)

	return err == nil
}

func (ref CosignReference) canSkipReferences(localRepo, cosignTag string, manifest *ispec.Manifest) (
	bool, error,
) {
	if manifest == nil {
		return true, nil
	}

	imageStore := ref.storeController.GetImageStore(localRepo)
	// check cosign signature already synced

	var localManifest ispec.Manifest

	/* we need to use tag (cosign format: sha256-$IMAGE_TAG.sig) instead of digest to get local cosign manifest
	because of an issue where cosign digests differs between upstream and downstream */

	localManifestBuf, _, _, err := imageStore.GetImageManifest(localRepo, cosignTag)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		ref.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("repository", localRepo).Str("reference", cosignTag).
			Msg("couldn't get local cosign manifest")

		return false, err
	}

	err = json.Unmarshal(localManifestBuf, &localManifest)
	if err != nil {
		ref.log.Error().Str("errorType", common.TypeOf(err)).
			Str("repository", localRepo).Str("reference", cosignTag).
			Err(err).Msg("couldn't unmarshal local cosign signature manifest")

		return false, err
	}

	if !manifestsEqual(localManifest, *manifest) {
		ref.log.Info().Str("repository", localRepo).Str("reference", cosignTag).
			Msg("upstream cosign signatures changed, syncing again")

		return false, nil
	}

	ref.log.Info().Str("repository", localRepo).Str("reference", cosignTag).
		Msg("skipping syncing cosign signature, already synced")

	return true, nil
}

func (ref CosignReference) SyncReferences(localRepo, remoteRepo, subjectDigestStr string) error {
	cosignTags := getCosignTagsFromSubjectDigest(subjectDigestStr)

	for _, cosignTag := range cosignTags {
		manifest, err := ref.getManifest(remoteRepo, cosignTag)
		if err != nil && errors.Is(err, zerr.ErrSyncReferrerNotFound) {
			return err
		}

		skip, err := ref.canSkipReferences(localRepo, cosignTag, manifest)
		if err != nil {
			ref.log.Error().Err(err).Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("couldn't check if the remote image cosign reference can be skipped")
		}

		if skip {
			continue
		}

		imageStore := ref.storeController.GetImageStore(localRepo)

		ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
			Msg("syncing cosign reference for image")

		for _, blob := range manifest.Layers {
			if err := syncBlob(ref.client, imageStore, localRepo, remoteRepo, blob.Digest, ref.log); err != nil {
				return err
			}
		}

		// sync config blob
		if err := syncBlob(ref.client, imageStore, localRepo, remoteRepo, manifest.Config.Digest, ref.log); err != nil {
			return err
		}

		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't marshal cosign reference manifest")

			return err
		}

		// push manifest
		referenceDigest, _, err := imageStore.PutImageManifest(localRepo, cosignTag,
			ispec.MediaTypeImageManifest, manifestBuf)
		if err != nil {
			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't upload cosign reference manifest for image")

			return err
		}

		ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
			Msg("successfully synced cosign reference for image")

		if ref.repoDB != nil {
			ref.log.Debug().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("repoDB: trying to sync cosign reference for image")

			isSig, sigType, signedManifestDig, err := storage.CheckIsImageSignature(localRepo, manifestBuf,
				cosignTag)
			if err != nil {
				return fmt.Errorf("failed to check if cosign reference '%s@%s' is a signature: %w", localRepo,
					cosignTag, err)
			}

			if isSig {
				err = ref.repoDB.AddManifestSignature(localRepo, signedManifestDig, metaTypes.SignatureMetadata{
					SignatureType:   sigType,
					SignatureDigest: referenceDigest.String(),
				})
			} else {
				err = meta.SetImageMetaFromInput(localRepo, cosignTag, manifest.MediaType,
					referenceDigest, manifestBuf, ref.storeController.GetImageStore(localRepo),
					ref.repoDB, ref.log)
			}

			if err != nil {
				return fmt.Errorf("failed to set metadata for cosign reference in '%s@%s': %w", localRepo, subjectDigestStr, err)
			}

			ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("repoDB: successfully added cosign reference for image")
		}
	}

	return nil
}

func (ref CosignReference) getManifest(repo, cosignTag string) (*ispec.Manifest, error) {
	var cosignManifest ispec.Manifest

	_, _, statusCode, err := ref.client.MakeGetRequest(&cosignManifest, ispec.MediaTypeImageManifest,
		"v2", repo, "manifests", cosignTag)
	if err != nil {
		if statusCode == http.StatusNotFound {
			ref.log.Debug().Str("errorType", common.TypeOf(err)).
				Str("repository", repo).Str("tag", cosignTag).
				Err(err).Msg("couldn't find any cosign manifest for image")

			return nil, zerr.ErrSyncReferrerNotFound
		}

		ref.log.Error().Str("errorType", common.TypeOf(err)).
			Str("repository", repo).Str("tag", cosignTag).Int("statusCode", statusCode).
			Err(err).Msg("couldn't get cosign manifest for image")

		return nil, err
	}

	return &cosignManifest, nil
}

func getCosignSignatureTagFromSubjectDigest(digestStr string) string {
	return strings.Replace(digestStr, ":", "-", 1) + "." + remote.SignatureTagSuffix
}

func getCosignSBOMTagFromSubjectDigest(digestStr string) string {
	return strings.Replace(digestStr, ":", "-", 1) + "." + remote.SBOMTagSuffix
}

func getCosignTagsFromSubjectDigest(digestStr string) []string {
	var cosignTags []string

	// signature tag
	cosignTags = append(cosignTags, getCosignSignatureTagFromSubjectDigest(digestStr))
	// sbom tag
	cosignTags = append(cosignTags, getCosignSBOMTagFromSubjectDigest(digestStr))

	return cosignTags
}

// this function will check if tag is a cosign tag (signature or sbom).
func IsCosignTag(tag string) bool {
	if strings.HasPrefix(tag, "sha256-") &&
		(strings.HasSuffix(tag, remote.SignatureTagSuffix) || strings.HasSuffix(tag, remote.SBOMTagSuffix)) {
		return true
	}

	return false
}
