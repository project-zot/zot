package sync

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"gopkg.in/resty.v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type signaturesCopier struct {
	client          *resty.Client
	upstreamURL     url.URL
	storeController storage.StoreController
	log             log.Logger
}

func newSignaturesCopier(httpClient *resty.Client, upstreamURL url.URL,
	storeController storage.StoreController, log log.Logger,
) *signaturesCopier {
	return &signaturesCopier{
		client:          httpClient,
		upstreamURL:     upstreamURL,
		storeController: storeController,
		log:             log,
	}
}

func (sig *signaturesCopier) getCosignManifest(repo, digestStr string) (*ispec.Manifest, error) {
	var cosignManifest ispec.Manifest

	cosignTag := getCosignTagFromImageDigest(digestStr)

	getCosignManifestURL := sig.upstreamURL

	getCosignManifestURL.Path = path.Join(getCosignManifestURL.Path, "v2", repo, "manifests", cosignTag)

	getCosignManifestURL.RawQuery = getCosignManifestURL.Query().Encode()

	resp, err := sig.client.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		Get(getCosignManifestURL.String())
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", getCosignManifestURL.String()).
			Msgf("couldn't get cosign manifest: %s", cosignTag)

		return nil, err
	}

	if resp.StatusCode() == http.StatusNotFound {
		sig.log.Info().Msgf("couldn't find any cosign signature from %s, status code: %d skipping",
			getCosignManifestURL.String(), resp.StatusCode())

		return nil, zerr.ErrSyncReferrerNotFound
	} else if resp.IsError() {
		sig.log.Error().Str("errorType", TypeOf(zerr.ErrSyncReferrer)).
			Err(zerr.ErrSyncReferrer).Msgf("couldn't get cosign signature from %s, status code: %d skipping",
			getCosignManifestURL.String(), resp.StatusCode())

		return nil, zerr.ErrSyncReferrer
	}

	err = json.Unmarshal(resp.Body(), &cosignManifest)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", getCosignManifestURL.String()).
			Msgf("couldn't unmarshal cosign manifest %s", cosignTag)

		return nil, err
	}

	return &cosignManifest, nil
}

func (sig *signaturesCopier) getNotarySignatures(repo, digestStr string) (ReferenceList, error) {
	var referrers ReferenceList

	getReferrersURL := sig.upstreamURL

	// based on manifest digest get referrers
	getReferrersURL.Path = path.Join(getReferrersURL.Path, constants.ArtifactSpecRoutePrefix,
		repo, "manifests", digestStr, "referrers")

	getReferrersURL.RawQuery = getReferrersURL.Query().Encode()

	resp, err := sig.client.R().
		SetHeader("Content-Type", "application/json").
		SetQueryParam("artifactType", notreg.ArtifactTypeNotation).
		Get(getReferrersURL.String())
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", getReferrersURL.String()).Msg("couldn't get referrers")

		return referrers, err
	}

	if resp.StatusCode() == http.StatusNotFound || resp.StatusCode() == http.StatusBadRequest {
		sig.log.Info().Msgf("couldn't find any notary signature from %s, status code: %d, skipping",
			getReferrersURL.String(), resp.StatusCode())

		return ReferenceList{}, zerr.ErrSyncReferrerNotFound
	} else if resp.IsError() {
		sig.log.Error().Str("errorType", TypeOf(zerr.ErrSyncReferrer)).
			Err(zerr.ErrSyncReferrer).Msgf("couldn't get notary signature from %s, status code: %d skipping",
			getReferrersURL.String(), resp.StatusCode())

		return ReferenceList{}, zerr.ErrSyncReferrer
	}

	err = json.Unmarshal(resp.Body(), &referrers)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", getReferrersURL.String()).
			Msgf("couldn't unmarshal notary signature")

		return referrers, err
	}

	return referrers, nil
}

func (sig *signaturesCopier) getOCIRefs(repo, digestStr string) (ispec.Index, error) {
	var index ispec.Index

	getReferrersURL := sig.upstreamURL
	// based on manifest digest get referrers
	getReferrersURL.Path = path.Join(getReferrersURL.Path, "v2", repo, "referrers", digestStr)

	getReferrersURL.RawQuery = getReferrersURL.Query().Encode()

	resp, err := sig.client.R().
		SetHeader("Content-Type", "application/json").
		Get(getReferrersURL.String())
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", getReferrersURL.String()).Msg("couldn't get referrers")

		return index, err
	}

	if resp.StatusCode() == http.StatusNotFound {
		sig.log.Info().Msgf("couldn't find any oci reference from %s, status code: %d, skipping",
			getReferrersURL.String(), resp.StatusCode())

		return index, zerr.ErrSyncReferrerNotFound
	} else if resp.IsError() {
		sig.log.Error().Str("errorType", TypeOf(zerr.ErrSyncReferrer)).
			Err(zerr.ErrSyncReferrer).Msgf("couldn't get oci reference from %s, status code: %d skipping",
			getReferrersURL.String(), resp.StatusCode())

		return index, zerr.ErrSyncReferrer
	}

	err = json.Unmarshal(resp.Body(), &index)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Str("url", getReferrersURL.String()).
			Msgf("couldn't unmarshal oci reference")

		return index, err
	}

	return index, nil
}

func (sig *signaturesCopier) syncCosignSignature(localRepo, remoteRepo, digestStr string,
	cosignManifest *ispec.Manifest,
) error {
	cosignTag := getCosignTagFromImageDigest(digestStr)

	// if no manifest found
	if cosignManifest == nil {
		return nil
	}

	skipCosignSig, err := sig.canSkipCosignSignature(localRepo, digestStr, cosignManifest)
	if err != nil {
		sig.log.Error().Err(err).Msgf("couldn't check if the upstream image %s:%s cosign signature can be skipped",
			remoteRepo, digestStr)
	}

	if skipCosignSig {
		return nil
	}

	imageStore := sig.storeController.GetImageStore(localRepo)

	sig.log.Info().Msg("syncing cosign signatures")

	for _, blob := range cosignManifest.Layers {
		if err := syncBlob(sig, imageStore, localRepo, remoteRepo, blob.Digest); err != nil {
			return err
		}
	}

	// sync config blob
	if err := syncBlob(sig, imageStore, localRepo, remoteRepo, cosignManifest.Config.Digest); err != nil {
		return err
	}

	cosignManifestBuf, err := json.Marshal(cosignManifest)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msg("couldn't marshal cosign manifest")
	}

	// push manifest
	_, err = imageStore.PutImageManifest(localRepo, cosignTag,
		ispec.MediaTypeImageManifest, cosignManifestBuf)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msg("couldn't upload cosign manifest")

		return err
	}

	sig.log.Info().Msgf("successfully synced cosign signature for repo %s digest %s", localRepo, digestStr)

	return nil
}

func (sig *signaturesCopier) syncNotarySignature(localRepo, remoteRepo, digestStr string, referrers ReferenceList,
) error {
	if len(referrers.References) == 0 {
		return nil
	}

	skipNotarySig, err := sig.canSkipNotarySignature(localRepo, digestStr, referrers)
	if err != nil {
		sig.log.Error().Err(err).Msgf("couldn't check if the upstream image %s:%s notary signature can be skipped",
			remoteRepo, digestStr)
	}

	if skipNotarySig {
		return nil
	}

	imageStore := sig.storeController.GetImageStore(localRepo)

	sig.log.Info().Msg("syncing notary signatures")

	for _, ref := range referrers.References {
		// get referrer manifest
		getRefManifestURL := sig.upstreamURL
		getRefManifestURL.Path = path.Join(getRefManifestURL.Path, "v2", remoteRepo, "manifests", ref.Digest.String())
		getRefManifestURL.RawQuery = getRefManifestURL.Query().Encode()

		resp, err := sig.client.R().
			SetHeader("Content-Type", ref.MediaType).
			Get(getRefManifestURL.String())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get notary manifest: %s", getRefManifestURL.String())

			return err
		}

		// read manifest
		var artifactManifest oras.Manifest

		err = json.Unmarshal(resp.Body(), &artifactManifest)
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't unmarshal notary manifest: %s", getRefManifestURL.String())

			return err
		}

		for _, blob := range artifactManifest.Blobs {
			if err := syncBlob(sig, imageStore, localRepo, remoteRepo, blob.Digest); err != nil {
				return err
			}
		}

		_, err = imageStore.PutImageManifest(localRepo, ref.Digest.String(),
			oras.MediaTypeArtifactManifest, resp.Body())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't upload notary sig manifest")

			return err
		}
	}

	sig.log.Info().Msgf("successfully synced notary signature for repo %s digest %s", localRepo, digestStr)

	return nil
}

func (sig *signaturesCopier) syncOCIRefs(localRepo, remoteRepo, digestStr string, index ispec.Index,
) error {
	if len(index.Manifests) == 0 {
		return nil
	}

	skipOCIRefs, err := sig.canSkipOCIRefs(localRepo, digestStr, index)
	if err != nil {
		sig.log.Error().Err(err).Msgf("couldn't check if the upstream image %s:%s oci references can be skipped",
			remoteRepo, digestStr)
	}

	if skipOCIRefs {
		return nil
	}

	imageStore := sig.storeController.GetImageStore(localRepo)

	sig.log.Info().Msg("syncing oci references")

	for _, ref := range index.Manifests {
		getRefManifestURL := sig.upstreamURL
		getRefManifestURL.Path = path.Join(getRefManifestURL.Path, "v2", remoteRepo, "manifests", ref.Digest.String())
		getRefManifestURL.RawQuery = getRefManifestURL.Query().Encode()

		resp, err := sig.client.R().
			SetHeader("Content-Type", ref.MediaType).
			Get(getRefManifestURL.String())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get oci reference manifest: %s", getRefManifestURL.String())

			return err
		}

		if ref.MediaType == ispec.MediaTypeImageManifest {
			// read manifest
			var manifest ispec.Manifest

			err = json.Unmarshal(resp.Body(), &manifest)
			if err != nil {
				sig.log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("couldn't unmarshal oci reference manifest: %s", getRefManifestURL.String())

				return err
			}

			for _, layer := range manifest.Layers {
				if err := syncBlob(sig, imageStore, localRepo, remoteRepo, layer.Digest); err != nil {
					return err
				}
			}

			// sync config blob
			if err := syncBlob(sig, imageStore, localRepo, remoteRepo, manifest.Config.Digest); err != nil {
				return err
			}
		} else if ref.MediaType == ispec.MediaTypeArtifactManifest {
			// read manifest
			var manifest ispec.Artifact

			err = json.Unmarshal(resp.Body(), &manifest)
			if err != nil {
				sig.log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("couldn't unmarshal oci reference manifest: %s", getRefManifestURL.String())

				return err
			}

			for _, layer := range manifest.Blobs {
				if err := syncBlob(sig, imageStore, localRepo, remoteRepo, layer.Digest); err != nil {
					return err
				}
			}
		}

		_, err = imageStore.PutImageManifest(localRepo, ref.Digest.String(),
			ref.MediaType, resp.Body())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't upload oci reference manifest")

			return err
		}
	}

	sig.log.Info().Msgf("successfully synced oci references for repo %s digest %s", localRepo, digestStr)

	return nil
}

func (sig *signaturesCopier) canSkipNotarySignature(localRepo, digestStr string, refs ReferenceList,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)
	digest := godigest.Digest(digestStr)

	// check notary signature already synced
	if len(refs.References) > 0 {
		localRefs, err := imageStore.GetOrasReferrers(localRepo, digest, notreg.ArtifactTypeNotation)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get local notary signature %s:%s manifest", localRepo, digestStr)

			return false, err
		}

		if !artifactDescriptorsEqual(localRefs, refs.References) {
			sig.log.Info().Msgf("upstream notary signatures %s:%s changed, syncing again", localRepo, digestStr)

			return false, nil
		}
	}

	sig.log.Info().Msgf("skipping notary signature %s:%s, already synced", localRepo, digestStr)

	return true, nil
}

func (sig *signaturesCopier) canSkipCosignSignature(localRepo, digestStr string, cosignManifest *ispec.Manifest,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)
	// check cosign signature already synced
	if cosignManifest != nil {
		var localCosignManifest ispec.Manifest

		/* we need to use tag (cosign format: sha256-$IMAGE_TAG.sig) instead of digest to get local cosign manifest
		because of an issue where cosign digests differs between upstream and downstream */
		cosignManifestTag := getCosignTagFromImageDigest(digestStr)

		localCosignManifestBuf, _, _, err := imageStore.GetImageManifest(localRepo, cosignManifestTag)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get local cosign %s:%s manifest", localRepo, digestStr)

			return false, err
		}

		err = json.Unmarshal(localCosignManifestBuf, &localCosignManifest)
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't unmarshal local cosign signature %s:%s manifest", localRepo, digestStr)

			return false, err
		}

		if !manifestsEqual(localCosignManifest, *cosignManifest) {
			sig.log.Info().Msgf("upstream cosign signatures %s:%s changed, syncing again", localRepo, digestStr)

			return false, nil
		}
	}

	sig.log.Info().Msgf("skipping cosign signature %s:%s, already synced", localRepo, digestStr)

	return true, nil
}

func (sig *signaturesCopier) canSkipOCIRefs(localRepo, digestStr string, index ispec.Index,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)
	digest := godigest.Digest(digestStr)

	// check oci references already synced
	if len(index.Manifests) > 0 {
		localRefs, err := imageStore.GetReferrers(localRepo, digest, "")
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get local ocireferences for %s:%s manifest", localRepo, digestStr)

			return false, err
		}

		if !descriptorsEqual(localRefs.Manifests, index.Manifests) {
			sig.log.Info().Msgf("upstream oci references for %s:%s changed, syncing again", localRepo, digestStr)

			return false, nil
		}
	}

	sig.log.Info().Msgf("skipping oci references %s:%s, already synced", localRepo, digestStr)

	return true, nil
}

func syncBlob(sig *signaturesCopier, imageStore storage.ImageStore, remoteRepo, localRepo string,
	digest godigest.Digest,
) error {
	getBlobURL := sig.upstreamURL
	getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", digest.String())
	getBlobURL.RawQuery = getBlobURL.Query().Encode()

	resp, err := sig.client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).Str("url", getBlobURL.String()).
			Err(err).Msgf("couldn't get blob: %s", getBlobURL.String())

		return err
	}

	defer resp.RawBody().Close()

	if resp.IsError() {
		sig.log.Info().Str("url", getBlobURL.String()).Msgf("couldn't find blob from %s, status code: %d",
			getBlobURL.String(), resp.StatusCode())

		return zerr.ErrSyncReferrer
	}

	_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), digest)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).Str("digest", digest.String()).
			Err(err).Msg("couldn't upload blob")

		return err
	}

	return nil
}

// sync feature will try to pull cosign signature because for sync cosign signature is just an image
// this function will check if tag is a cosign tag.
func isCosignTag(tag string) bool {
	if strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, remote.SignatureTagSuffix) {
		return true
	}

	return false
}

func getCosignTagFromImageDigest(digestStr string) string {
	if !isCosignTag(digestStr) {
		return strings.Replace(digestStr, ":", "-", 1) + "." + remote.SignatureTagSuffix
	}

	return digestStr
}
