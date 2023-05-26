//go:build sync
// +build sync

package references

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/sync/constants"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

type OciReferences struct {
	client          *client.Client
	storeController storage.StoreController
	repoDB          metaTypes.RepoDB
	log             log.Logger
}

func NewOciReferences(httpClient *client.Client, storeController storage.StoreController,
	repoDB metaTypes.RepoDB, log log.Logger,
) OciReferences {
	return OciReferences{
		client:          httpClient,
		storeController: storeController,
		repoDB:          repoDB,
		log:             log,
	}
}

func (ref OciReferences) Name() string {
	return constants.OCI
}

func (ref OciReferences) IsSigned(remoteRepo, subjectDigestStr string) bool {
	// use artifactTypeFilter
	index, err := ref.getIndex(remoteRepo, subjectDigestStr)
	if err != nil {
		return false
	}

	if len(getNotationManifestsFromOCIRefs(index)) > 0 {
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

func (ref OciReferences) SyncReferences(localRepo, remoteRepo, subjectDigestStr string) error {
	index, err := ref.getIndex(remoteRepo, subjectDigestStr)
	if err != nil {
		return err
	}

	skipOCIRefs, err := ref.canSkipReferences(localRepo, subjectDigestStr, index)
	if err != nil {
		ref.log.Error().Err(err).Str("repository", localRepo).Str("subject", subjectDigestStr).
			Msg("couldn't check if the upstream oci references for image can be skipped")
	}

	if skipOCIRefs {
		return nil
	}

	imageStore := ref.storeController.GetImageStore(localRepo)

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("syncing oci references for image")

	for _, referrer := range index.Manifests {
		var artifactManifest ispec.Manifest

		OCIRefBuf, _, statusCode, err := ref.client.MakeGetRequest(&artifactManifest, ispec.MediaTypeImageManifest,
			"v2", remoteRepo, "manifests", referrer.Digest.String())
		if err != nil {
			if statusCode == http.StatusNotFound {
				return zerr.ErrSyncReferrerNotFound
			}

			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't get oci reference manifest for image")

			return err
		}

		if referrer.MediaType == ispec.MediaTypeImageManifest {
			// read manifest
			var manifest ispec.Manifest

			err = json.Unmarshal(OCIRefBuf, &manifest)
			if err != nil {
				ref.log.Error().Str("errorType", common.TypeOf(err)).
					Str("repository", localRepo).Str("subject", subjectDigestStr).
					Err(err).Msg("couldn't unmarshal oci reference manifest for image")

				return err
			}

			for _, layer := range manifest.Layers {
				if err := syncBlob(ref.client, imageStore, localRepo, remoteRepo, layer.Digest, ref.log); err != nil {
					return err
				}
			}

			// sync config blob
			if err := syncBlob(ref.client, imageStore, localRepo, remoteRepo, manifest.Config.Digest, ref.log); err != nil {
				return err
			}
		} else {
			continue
		}

		digest, _, err := imageStore.PutImageManifest(localRepo, referrer.Digest.String(),
			referrer.MediaType, OCIRefBuf)
		if err != nil {
			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't upload oci reference for image")

			return err
		}

		if ref.repoDB != nil {
			ref.log.Debug().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("repoDB: trying to add oci references for image")

			isSig, sigType, signedManifestDig, err := storage.CheckIsImageSignature(localRepo, OCIRefBuf,
				referrer.Digest.String())
			if err != nil {
				return fmt.Errorf("failed to check if oci reference '%s@%s' is a signature: %w", localRepo,
					referrer.Digest.String(), err)
			}

			if isSig {
				err = ref.repoDB.AddManifestSignature(localRepo, signedManifestDig, metaTypes.SignatureMetadata{
					SignatureType:   sigType,
					SignatureDigest: digest.String(),
				})
			} else {
				err = meta.SetImageMetaFromInput(localRepo, digest.String(), referrer.MediaType,
					digest, OCIRefBuf, ref.storeController.GetImageStore(localRepo),
					ref.repoDB, ref.log)
			}

			if err != nil {
				return fmt.Errorf("failed to set metadata for oci reference in '%s@%s': %w", localRepo, subjectDigestStr, err)
			}

			ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("repoDB: successfully added oci references to RepoDB for image")
		}
	}

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("successfully synced oci references for image")

	return nil
}

func (ref OciReferences) getIndex(repo, subjectDigestStr string) (ispec.Index, error) {
	var index ispec.Index

	_, _, statusCode, err := ref.client.MakeGetRequest(&index, ispec.MediaTypeImageIndex,
		"v2", repo, "referrers", subjectDigestStr)
	if err != nil {
		if statusCode == http.StatusNotFound {
			ref.log.Debug().Str("repository", repo).Str("subject", subjectDigestStr).
				Msg("couldn't find any oci reference for image, skipping")

			return index, zerr.ErrSyncReferrerNotFound
		}

		ref.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("repository", repo).Str("subject", subjectDigestStr).Int("statusCode", statusCode).
			Msg("couldn't get oci reference for image")

		return index, err
	}

	return index, nil
}
