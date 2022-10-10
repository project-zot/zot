package sync

import (
	"context"
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

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type signaturesCopier struct {
	client          *http.Client
	upstreamURL     url.URL
	storeController storage.StoreController
	credentials     Credentials
	log             log.Logger
}

func newSignaturesCopier(httpClient *http.Client, credentials Credentials, upstreamURL url.URL,
	storeController storage.StoreController, log log.Logger,
) *signaturesCopier {
	return &signaturesCopier{
		client:          httpClient,
		credentials:     credentials,
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

	_, statusCode, err := common.MakeHTTPGetRequest(sig.client, sig.credentials.Username,
		sig.credentials.Password, &cosignManifest,
		getCosignManifestURL.String(), ispec.MediaTypeImageManifest, sig.log)
	if err != nil {
		if statusCode == http.StatusNotFound {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't find any cosign manifest: %s", getCosignManifestURL.String())

			return nil, zerr.ErrSyncReferrerNotFound
		}

		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't get cosign manifest: %s", getCosignManifestURL.String())

		return nil, err
	}

	return &cosignManifest, nil
}

func (sig *signaturesCopier) getORASRefs(repo, digestStr string) (ReferenceList, error) {
	var referrers ReferenceList

	getReferrersURL := sig.upstreamURL

	// based on manifest digest get referrers
	getReferrersURL.Path = path.Join(getReferrersURL.Path, constants.ArtifactSpecRoutePrefix,
		repo, "manifests", digestStr, "referrers")

	getReferrersURL.RawQuery = getReferrersURL.Query().Encode()

	_, statusCode, err := common.MakeHTTPGetRequest(sig.client, sig.credentials.Username,
		sig.credentials.Password, &referrers,
		getReferrersURL.String(), "application/json", sig.log)
	if err != nil {
		if statusCode == http.StatusNotFound {
			sig.log.Info().Err(err).Msg("couldn't find any ORAS artifact")

			return referrers, zerr.ErrSyncReferrerNotFound
		}

		sig.log.Error().Err(err).Msg("couldn't get ORAS artifacts")

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

	_, statusCode, err := common.MakeHTTPGetRequest(sig.client, sig.credentials.Username,
		sig.credentials.Password, &index,
		getReferrersURL.String(), "application/json", sig.log)
	if err != nil {
		if statusCode == http.StatusNotFound {
			sig.log.Info().Msgf("couldn't find any oci reference from %s, status code: %d, skipping",
				getReferrersURL.String(), statusCode)

			return index, zerr.ErrSyncReferrerNotFound
		}

		sig.log.Error().Str("errorType", common.TypeOf(zerr.ErrSyncReferrer)).
			Err(zerr.ErrSyncReferrer).Msgf("couldn't get oci reference from %s, status code: %d skipping",
			getReferrersURL.String(), statusCode)

		return index, zerr.ErrSyncReferrer
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
		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't marshal cosign manifest")
	}

	// push manifest
	_, err = imageStore.PutImageManifest(localRepo, cosignTag,
		ispec.MediaTypeImageManifest, cosignManifestBuf)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't upload cosign manifest")

		return err
	}

	sig.log.Info().Msgf("successfully synced cosign signature for repo %s digest %s", localRepo, digestStr)

	return nil
}

func (sig *signaturesCopier) syncORASRefs(localRepo, remoteRepo, digestStr string, referrers ReferenceList,
) error {
	if len(referrers.References) == 0 {
		return nil
	}

	skipORASRefs, err := sig.canSkipORASRefs(localRepo, digestStr, referrers)
	if err != nil {
		sig.log.Error().Err(err).Msgf("couldn't check if the upstream image %s:%s ORAS artifact can be skipped",
			remoteRepo, digestStr)
	}

	if skipORASRefs {
		return nil
	}

	imageStore := sig.storeController.GetImageStore(localRepo)

	sig.log.Info().Msg("syncing ORAS artifacts")

	for _, ref := range referrers.References {
		// get referrer manifest
		getRefManifestURL := sig.upstreamURL
		getRefManifestURL.Path = path.Join(getRefManifestURL.Path, "v2", remoteRepo, "manifests", ref.Digest.String())
		getRefManifestURL.RawQuery = getRefManifestURL.Query().Encode()

		var artifactManifest oras.Manifest

		body, statusCode, err := common.MakeHTTPGetRequest(sig.client, sig.credentials.Username,
			sig.credentials.Password, &artifactManifest,
			getRefManifestURL.String(), ref.MediaType, sig.log)
		if err != nil {
			if statusCode == http.StatusNotFound {
				sig.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msgf("couldn't find any ORAS manifest: %s", getRefManifestURL.String())

				return zerr.ErrSyncReferrerNotFound
			}

			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get ORAS manifest: %s", getRefManifestURL.String())

			return err
		}

		for _, blob := range artifactManifest.Blobs {
			if err := syncBlob(sig, imageStore, localRepo, remoteRepo, blob.Digest); err != nil {
				return err
			}
		}

		_, err = imageStore.PutImageManifest(localRepo, ref.Digest.String(),
			oras.MediaTypeArtifactManifest, body)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't upload ORAS manifest")

			return err
		}
	}

	sig.log.Info().Msgf("successfully synced ORAS artifacts for repo %s digest %s", localRepo, digestStr)

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

		var artifactManifest oras.Manifest

		body, statusCode, err := common.MakeHTTPGetRequest(sig.client, sig.credentials.Username,
			sig.credentials.Password, &artifactManifest,
			getRefManifestURL.String(), ref.MediaType, sig.log)
		if err != nil {
			if statusCode == http.StatusNotFound {
				sig.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msgf("couldn't find any oci reference manifest: %s", getRefManifestURL.String())

				return zerr.ErrSyncReferrerNotFound
			}

			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get oci reference manifest: %s", getRefManifestURL.String())

			return err
		}

		if ref.MediaType == ispec.MediaTypeImageManifest {
			// read manifest
			var manifest ispec.Manifest

			err = json.Unmarshal(body, &manifest)
			if err != nil {
				sig.log.Error().Str("errorType", common.TypeOf(err)).
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

			err = json.Unmarshal(body, &manifest)
			if err != nil {
				sig.log.Error().Str("errorType", common.TypeOf(err)).
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
			ref.MediaType, body)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't upload oci reference manifest")

			return err
		}
	}

	sig.log.Info().Msgf("successfully synced oci references for repo %s digest %s", localRepo, digestStr)

	return nil
}

func (sig *signaturesCopier) syncOCIArtifact(localRepo, remoteRepo, reference string,
	ociArtifactBuf []byte,
) error {
	var ociArtifact ispec.Artifact

	err := json.Unmarshal(ociArtifactBuf, &ociArtifact)
	if err != nil {
		sig.log.Error().Err(err).Msgf("couldn't unmarshal OCI artifact from %s:%s", remoteRepo, reference)

		return err
	}

	canSkipOCIArtifact, err := sig.canSkipOCIArtifact(localRepo, reference, ociArtifact)
	if err != nil {
		sig.log.Error().Err(err).Msgf("couldn't check if OCI artifact %s:%s can be skipped",
			remoteRepo, reference)
	}

	if canSkipOCIArtifact {
		return nil
	}

	imageStore := sig.storeController.GetImageStore(localRepo)

	sig.log.Info().Msg("syncing OCI artifacts")

	for _, blob := range ociArtifact.Blobs {
		if err := syncBlob(sig, imageStore, localRepo, remoteRepo, blob.Digest); err != nil {
			return err
		}
	}

	artifactManifestBuf, err := json.Marshal(ociArtifact)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't marshal OCI artifact")

		return err
	}

	// push manifest
	_, err = imageStore.PutImageManifest(localRepo, reference,
		ispec.MediaTypeArtifactManifest, artifactManifestBuf)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't upload OCI artifact manifest")

		return err
	}

	sig.log.Info().Msgf("successfully synced OCI artifact for repo %s tag %s", localRepo, reference)

	return nil
}

func (sig *signaturesCopier) canSkipORASRefs(localRepo, digestStr string, refs ReferenceList,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)
	digest := godigest.Digest(digestStr)

	// check oras artifacts already synced
	if len(refs.References) > 0 {
		localRefs, err := imageStore.GetOrasReferrers(localRepo, digest, "")
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get local ORAS artifact %s:%s manifest", localRepo, digestStr)

			return false, err
		}

		if !artifactDescriptorsEqual(localRefs, refs.References) {
			sig.log.Info().Msgf("upstream ORAS artifacts %s:%s changed, syncing again", localRepo, digestStr)

			return false, nil
		}
	}

	sig.log.Info().Msgf("skipping ORAS artifact %s:%s, already synced", localRepo, digestStr)

	return true, nil
}

func (sig *signaturesCopier) canSkipOCIArtifact(localRepo, reference string, artifact ispec.Artifact,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)

	var localArtifactManifest ispec.Artifact

	localArtifactBuf, _, _, err := imageStore.GetImageManifest(localRepo, reference)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't get local OCI artifact %s:%s manifest", localRepo, reference)

		return false, err
	}

	err = json.Unmarshal(localArtifactBuf, &localArtifactManifest)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't unmarshal local OCI artifact %s:%s manifest", localRepo, reference)

		return false, err
	}

	if !artifactsEqual(localArtifactManifest, artifact) {
		sig.log.Info().Msgf("upstream OCI artifact %s:%s changed, syncing again", localRepo, reference)

		return false, nil
	}

	sig.log.Info().Msgf("skipping OCI artifact %s:%s, already synced", localRepo, reference)

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

			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get local cosign %s:%s manifest", localRepo, digestStr)

			return false, err
		}

		err = json.Unmarshal(localCosignManifestBuf, &localCosignManifest)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
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
		localRefs, err := imageStore.GetReferrers(localRepo, digest, nil)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			sig.log.Error().Str("errorType", common.TypeOf(err)).
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

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, getBlobURL.String(), nil)
	if err != nil {
		return err
	}

	resp, err := sig.client.Do(req)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).Str("url", getBlobURL.String()).
			Err(err).Msgf("couldn't get blob: %s", getBlobURL.String())

		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sig.log.Info().Str("url", getBlobURL.String()).Msgf("couldn't find blob from %s, status code: %d",
			getBlobURL.String(), resp.StatusCode)

		return zerr.ErrSyncReferrer
	}

	_, _, err = imageStore.FullBlobUpload(localRepo, resp.Body, digest)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).Str("digest", digest.String()).
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

func getNotationManifestsFromOCIRefs(ociRefs ispec.Index) []ispec.Descriptor {
	notaryManifests := []ispec.Descriptor{}

	for _, ref := range ociRefs.Manifests {
		if ref.ArtifactType == notreg.ArtifactTypeNotation {
			notaryManifests = append(notaryManifests, ref)
		}
	}

	return notaryManifests
}
