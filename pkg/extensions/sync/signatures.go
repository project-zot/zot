package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	syncconf "zotregistry.io/zot/pkg/extensions/config/sync"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

type signaturesCopier struct {
	client          *http.Client
	upstreamURL     url.URL
	credentials     syncconf.Credentials
	repoDB          repodb.RepoDB
	storeController storage.StoreController
	log             log.Logger
}

func newSignaturesCopier(httpClient *http.Client, credentials syncconf.Credentials,
	upstreamURL url.URL, repoDB repodb.RepoDB,
	storeController storage.StoreController, log log.Logger,
) *signaturesCopier {
	return &signaturesCopier{
		client:          httpClient,
		credentials:     credentials,
		upstreamURL:     upstreamURL,
		repoDB:          repoDB,
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
			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("manifest", getCosignManifestURL.String()).Msg("couldn't find any cosign manifest")

			return nil, zerr.ErrSyncReferrerNotFound
		}

		sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("manifest", getCosignManifestURL.String()).Msg("couldn't get cosign manifest")

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
			sig.log.Info().Str("referrers", getReferrersURL.String()).Int("statusCode", statusCode).
				Msg("couldn't find any oci reference from referrers, skipping")

			return index, zerr.ErrSyncReferrerNotFound
		}

		sig.log.Error().Str("errorType", common.TypeOf(zerr.ErrSyncReferrer)).Err(zerr.ErrSyncReferrer).
			Str("referrers", getReferrersURL.String()).Int("statusCode", statusCode).
			Msg("couldn't get oci reference from referrers, skipping")

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
		sig.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", digestStr).
			Msg("couldn't check if the upstream image cosign signature can be skipped")
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

	if sig.repoDB != nil {
		sig.log.Debug().Str("repository", localRepo).Str("digest", digestStr).
			Msg("trying to sync cosign signature for repo digest")

		err = repodb.SetMetadataFromInput(localRepo, cosignTag, ispec.MediaTypeImageManifest,
			godigest.FromBytes(cosignManifestBuf), cosignManifestBuf, sig.storeController.GetImageStore(localRepo),
			sig.repoDB, sig.log)
		if err != nil {
			return fmt.Errorf("failed to set metadata for cosign signature '%s@%s': %w", localRepo, digestStr, err)
		}

		sig.log.Info().Str("repository", localRepo).Str("digest", digestStr).
			Msg("successfully added cosign signature to RepoDB for repo digest")
	}

	return nil
}

func (sig *signaturesCopier) syncORASRefs(localRepo, remoteRepo, digestStr string, referrers ReferenceList,
) error {
	if len(referrers.References) == 0 {
		return nil
	}

	skipORASRefs, err := sig.canSkipORASRefs(localRepo, digestStr, referrers)
	if err != nil {
		sig.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", digestStr).
			Msg("couldn't check if the upstream image ORAS artifact can be skipped")
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
				sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
					Str("manifest", getRefManifestURL.String()).Msg("couldn't find any ORAS manifest")

				return zerr.ErrSyncReferrerNotFound
			}

			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("manifest", getRefManifestURL.String()).Msg("couldn't get ORAS manifest")

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

		// this is for notation signatures
		if sig.repoDB != nil {
			sig.log.Debug().Str("repository", localRepo).Str("digest", digestStr).
				Msg("trying to sync oras artifact for digest")

			err = repodb.SetMetadataFromInput(localRepo, ref.Digest.String(), ref.MediaType,
				ref.Digest, body, sig.storeController.GetImageStore(localRepo), sig.repoDB, sig.log)
			if err != nil {
				return fmt.Errorf("failed to set metadata for oras artifact '%s@%s': %w", localRepo, digestStr, err)
			}

			sig.log.Info().Str("repository", localRepo).Str("digest", digestStr).
				Msg("successfully added oras artifacts to RepoDB for digest")
		}
	}

	sig.log.Info().Str("repository", localRepo).Str("digest", digestStr).
		Msg("successfully synced ORAS artifacts for digest")

	return nil
}

func (sig *signaturesCopier) syncOCIRefs(localRepo, remoteRepo, digestStr string, index ispec.Index,
) error {
	if len(index.Manifests) == 0 {
		return nil
	}

	skipOCIRefs, err := sig.canSkipOCIRefs(localRepo, digestStr, index)
	if err != nil {
		sig.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", digestStr).
			Msg("couldn't check if the upstream image oci references can be skipped")
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

		OCIRefBody, statusCode, err := common.MakeHTTPGetRequest(sig.client, sig.credentials.Username,
			sig.credentials.Password, &artifactManifest,
			getRefManifestURL.String(), ref.MediaType, sig.log)
		if err != nil {
			if statusCode == http.StatusNotFound {
				sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
					Str("manifest", getRefManifestURL.String()).Msg("couldn't find any oci reference manifest")

				return zerr.ErrSyncReferrerNotFound
			}

			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("manifest", getRefManifestURL.String()).Msg("couldn't get oci reference manifest")

			return err
		}

		if ref.MediaType == ispec.MediaTypeImageManifest {
			// read manifest
			var manifest ispec.Manifest

			err = json.Unmarshal(OCIRefBody, &manifest)
			if err != nil {
				sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
					Str("manifest", getRefManifestURL.String()).Msg("couldn't unmarshal oci reference manifest")

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

			err = json.Unmarshal(OCIRefBody, &manifest)
			if err != nil {
				sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
					Str("manifest", getRefManifestURL.String()).Msg("couldn't unmarshal oci reference manifest")

				return err
			}

			for _, layer := range manifest.Blobs {
				if err := syncBlob(sig, imageStore, localRepo, remoteRepo, layer.Digest); err != nil {
					return err
				}
			}
		}

		digest, err := imageStore.PutImageManifest(localRepo, ref.Digest.String(),
			ref.MediaType, OCIRefBody)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't upload oci reference manifest")

			return err
		}

		if sig.repoDB != nil {
			sig.log.Debug().Str("repository", localRepo).Str("digest", digestStr).Msg("trying to add OCI refs for repo digest")

			err = repodb.SetMetadataFromInput(localRepo, digestStr, ref.MediaType,
				digest, OCIRefBody, sig.storeController.GetImageStore(localRepo),
				sig.repoDB, sig.log)
			if err != nil {
				return fmt.Errorf("failed to set metadata for OCI ref in '%s@%s': %w", localRepo, digestStr, err)
			}

			sig.log.Info().Str("repository", localRepo).Str("digest", digestStr).
				Msg("successfully added OCI refs to RepoDB for digest")
		}
	}

	sig.log.Info().Str("repository", localRepo).Str("digest", digestStr).
		Msg("successfully synced OCI refs for digest")

	return nil
}

func (sig *signaturesCopier) syncOCIArtifact(localRepo, remoteRepo, reference string,
	ociArtifactBuf []byte,
) error {
	var ociArtifact ispec.Artifact

	err := json.Unmarshal(ociArtifactBuf, &ociArtifact)
	if err != nil {
		sig.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", reference).
			Msg("couldn't unmarshal OCI artifact")

		return err
	}

	canSkipOCIArtifact, err := sig.canSkipOCIArtifact(localRepo, reference, ociArtifact)
	if err != nil {
		sig.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", reference).
			Msg("couldn't check if OCI artifact can be skipped")
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
	digest, err := imageStore.PutImageManifest(localRepo, reference,
		ispec.MediaTypeArtifactManifest, artifactManifestBuf)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't upload OCI artifact manifest")

		return err
	}

	if sig.repoDB != nil {
		sig.log.Debug().Str("repository", localRepo).Str("digest", digest.String()).
			Msg("trying to OCI refs for repo digest")

		err = repodb.SetMetadataFromInput(localRepo, reference, ispec.MediaTypeArtifactManifest,
			digest, artifactManifestBuf, sig.storeController.GetImageStore(localRepo),
			sig.repoDB, sig.log)
		if err != nil {
			return fmt.Errorf("failed to set metadata for OCI Artifact '%s@%s': %w", localRepo, digest.String(), err)
		}

		sig.log.Info().Str("repository", localRepo).Str("digest", digest.String()).
			Msg("successfully added oci artifacts to RepoDB for repo digest")
	}

	sig.log.Info().Str("repository", localRepo).Str("tag", reference).
		Msg("successfully synced OCI artifact for repo tag")

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

			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("repository", localRepo).Str("reference", digestStr).Msg("couldn't get local ORAS artifact manifest")

			return false, err
		}

		if !artifactDescriptorsEqual(localRefs, refs.References) {
			sig.log.Info().Str("repository", localRepo).Str("reference", digestStr).
				Msg("upstream ORAS artifacts changed, syncing again")

			return false, nil
		}
	}

	sig.log.Info().Str("repository", localRepo).Str("reference", digestStr).
		Msg("skipping ORAS artifact, already synced")

	return true, nil
}

func (sig *signaturesCopier) canSkipOCIArtifact(localRepo, reference string, artifact ispec.Artifact,
) (bool, error) {
	imageStore := sig.storeController.GetImageStore(localRepo)

	var localArtifactManifest ispec.Artifact

	localArtifactBuf, _, _, err := imageStore.GetImageManifest(localRepo, reference)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestNotFound) || errors.Is(err, zerr.ErrRepoNotFound) {
			return false, nil
		}

		sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("repository", localRepo).Str("reference", reference).
			Msg("couldn't get local OCI artifact manifest")

		return false, err
	}

	err = json.Unmarshal(localArtifactBuf, &localArtifactManifest)
	if err != nil {
		sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("repository", localRepo).Str("reference", reference).
			Msg("couldn't unmarshal local OCI artifact manifest")

		return false, err
	}

	if !artifactsEqual(localArtifactManifest, artifact) {
		sig.log.Info().Str("repository", localRepo).Str("reference", reference).
			Msg("upstream OCI artifact changed, syncing again")

		return false, nil
	}

	sig.log.Info().Str("repository", localRepo).Str("reference", reference).
		Msg("skipping OCI artifact, already synced")

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

			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("repository", localRepo).Str("reference", digestStr).
				Msg("couldn't get local cosign manifest")

			return false, err
		}

		err = json.Unmarshal(localCosignManifestBuf, &localCosignManifest)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("repository", localRepo).Str("reference", digestStr).
				Msg("couldn't unmarshal local cosign signature manifest")

			return false, err
		}

		if !manifestsEqual(localCosignManifest, *cosignManifest) {
			sig.log.Info().Str("repository", localRepo).Str("reference", digestStr).
				Msg("upstream cosign signatures changed, syncing again")

			return false, nil
		}
	}

	sig.log.Info().Str("repository", localRepo).Str("reference", digestStr).
		Msg("skipping cosign signature, already synced")

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

			sig.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
				Str("repository", localRepo).Str("reference", digestStr).
				Msg("couldn't get local ocireferences for manifest")

			return false, err
		}

		if !descriptorsEqual(localRefs.Manifests, index.Manifests) {
			sig.log.Info().Str("repository", localRepo).Str("reference", digestStr).
				Msg("upstream oci references for manifest changed, syncing again")

			return false, nil
		}
	}

	sig.log.Info().Str("repository", localRepo).Str("reference", digestStr).
		Msg("skipping oci references, already synced")

	return true, nil
}

func syncBlob(sig *signaturesCopier, imageStore storage.ImageStore, localRepo, remoteRepo string,
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
		sig.log.Error().Str("errorType", common.TypeOf(err)).Str("blob url", getBlobURL.String()).
			Err(err).Msg("couldn't get blob from url")

		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sig.log.Info().Str("url", getBlobURL.String()).Str("blob url", getBlobURL.String()).
			Int("statusCode", resp.StatusCode).Msg("couldn't find blob from url, status code")

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
