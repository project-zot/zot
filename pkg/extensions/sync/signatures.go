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
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
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
		SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
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

		return nil, zerr.ErrSyncSignatureNotFound
	} else if resp.IsError() {
		sig.log.Error().Str("errorType", TypeOf(zerr.ErrSyncSignature)).
			Err(zerr.ErrSyncSignature).Msgf("couldn't get cosign signature from %s, status code: %d skipping",
			getCosignManifestURL.String(), resp.StatusCode())

		return nil, zerr.ErrSyncSignature
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

func (sig *signaturesCopier) getNotaryRefs(repo, digestStr string) (ReferenceList, error) {
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

		return ReferenceList{}, zerr.ErrSyncSignatureNotFound
	} else if resp.IsError() {
		sig.log.Error().Str("errorType", TypeOf(zerr.ErrSyncSignature)).
			Err(zerr.ErrSyncSignature).Msgf("couldn't get notary signature from %s, status code: %d skipping",
			getReferrersURL.String(), resp.StatusCode())

		return ReferenceList{}, zerr.ErrSyncSignature
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
		// get blob
		getBlobURL := sig.upstreamURL
		getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", blob.Digest.String())
		getBlobURL.RawQuery = getBlobURL.Query().Encode()

		resp, err := sig.client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get cosign blob: %s", blob.Digest.String())

			return err
		}

		if resp.IsError() {
			sig.log.Info().Msgf("couldn't find cosign blob from %s, status code: %d", getBlobURL.String(), resp.StatusCode())

			return zerr.ErrSyncSignature
		}

		defer resp.RawBody().Close()

		// push blob
		_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), blob.Digest)
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't upload cosign blob")

			return err
		}
	}

	// get config blob
	getBlobURL := sig.upstreamURL
	getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", cosignManifest.Config.Digest.String())
	getBlobURL.RawQuery = getBlobURL.Query().Encode()

	resp, err := sig.client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't get cosign config blob: %s", getBlobURL.String())

		return err
	}

	if resp.IsError() {
		sig.log.Info().Msgf("couldn't find cosign config blob from %s, status code: %d",
			getBlobURL.String(), resp.StatusCode())

		return zerr.ErrSyncSignature
	}

	defer resp.RawBody().Close()

	// push config blob
	_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), cosignManifest.Config.Digest)
	if err != nil {
		sig.log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msg("couldn't upload cosign config blob")

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
	if skipNotarySig || err != nil {
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
			Get(getRefManifestURL.String())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get notary manifest: %s", getRefManifestURL.String())

			return err
		}

		// read manifest
		var artifactManifest artifactspec.Manifest

		err = json.Unmarshal(resp.Body(), &artifactManifest)
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't unmarshal notary manifest: %s", getRefManifestURL.String())

			return err
		}

		for _, blob := range artifactManifest.Blobs {
			getBlobURL := sig.upstreamURL
			getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", blob.Digest.String())
			getBlobURL.RawQuery = getBlobURL.Query().Encode()

			resp, err := sig.client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
			if err != nil {
				sig.log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("couldn't get notary blob: %s", getBlobURL.String())

				return err
			}

			defer resp.RawBody().Close()

			if resp.IsError() {
				sig.log.Info().Msgf("couldn't find notary blob from %s, status code: %d",
					getBlobURL.String(), resp.StatusCode())

				return zerr.ErrSyncSignature
			}

			_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), blob.Digest)
			if err != nil {
				sig.log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msg("couldn't upload notary sig blob")

				return err
			}
		}

		_, err = imageStore.PutImageManifest(localRepo, ref.Digest.String(),
			artifactspec.MediaTypeArtifactManifest, resp.Body())
		if err != nil {
			sig.log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("couldn't upload notary sig manifest")

			return err
		}
	}

	sig.log.Info().Msgf("successfully synced notary signature for repo %s digest %s", localRepo, digestStr)

	return nil
}

func (sig *signaturesCopier) canSkipNotarySignature(localRepo, digestStr string, refs ReferenceList,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)
	digest := godigest.Digest(digestStr)

	// check notary signature already synced
	if len(refs.References) > 0 {
		localRefs, err := imageStore.GetReferrers(localRepo, digest, notreg.ArtifactTypeNotation)
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
