package sync

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	notreg "github.com/notaryproject/notation/pkg/registry"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"gopkg.in/resty.v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func getCosignManifest(client *resty.Client, regURL url.URL, repo, digest string,
	log log.Logger,
) (*ispec.Manifest, error) {
	var cosignManifest ispec.Manifest

	cosignTag := getCosignTagFromImageDigest(digest)

	getCosignManifestURL := regURL

	getCosignManifestURL.Path = path.Join(getCosignManifestURL.Path, "v2", repo, "manifests", cosignTag)

	getCosignManifestURL.RawQuery = getCosignManifestURL.Query().Encode()

	resp, err := client.R().Get(getCosignManifestURL.String())
	if err != nil {
		log.Error().Err(err).Str("url", getCosignManifestURL.String()).
			Msgf("couldn't get cosign manifest: %s", cosignTag)

		return nil, err
	}

	if resp.StatusCode() == http.StatusNotFound {
		log.Info().Msgf("couldn't find any cosign signature from %s, status code: %d skipping",
			getCosignManifestURL.String(), resp.StatusCode())

		return nil, zerr.ErrSyncSignatureNotFound
	} else if resp.IsError() {
		log.Error().Err(zerr.ErrSyncSignature).Msgf("couldn't get cosign signature from %s, status code: %d skipping",
			getCosignManifestURL.String(), resp.StatusCode())

		return nil, zerr.ErrSyncSignature
	}

	err = json.Unmarshal(resp.Body(), &cosignManifest)
	if err != nil {
		log.Error().Err(err).Str("url", getCosignManifestURL.String()).
			Msgf("couldn't unmarshal cosign manifest %s", cosignTag)

		return nil, err
	}

	return &cosignManifest, nil
}

func getNotaryRefs(client *resty.Client, regURL url.URL, repo, digest string, log log.Logger) (ReferenceList, error) {
	var referrers ReferenceList

	getReferrersURL := regURL

	// based on manifest digest get referrers
	getReferrersURL.Path = path.Join(getReferrersURL.Path, constants.ArtifactSpecRoutePrefix,
		repo, "manifests", digest, "referrers")

	getReferrersURL.RawQuery = getReferrersURL.Query().Encode()

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetQueryParam("artifactType", notreg.ArtifactTypeNotation).
		Get(getReferrersURL.String())
	if err != nil {
		log.Error().Err(err).Str("url", getReferrersURL.String()).Msg("couldn't get referrers")

		return referrers, err
	}

	if resp.StatusCode() == http.StatusNotFound || resp.StatusCode() == http.StatusBadRequest {
		log.Info().Msgf("couldn't find any notary signature from %s, status code: %d, skipping",
			getReferrersURL.String(), resp.StatusCode())

		return ReferenceList{}, zerr.ErrSyncSignatureNotFound
	} else if resp.IsError() {
		log.Error().Err(zerr.ErrSyncSignature).Msgf("couldn't get notary signature from %s, status code: %d skipping",
			getReferrersURL.String(), resp.StatusCode())

		return ReferenceList{}, zerr.ErrSyncSignature
	}

	err = json.Unmarshal(resp.Body(), &referrers)
	if err != nil {
		log.Error().Err(err).Str("url", getReferrersURL.String()).
			Msgf("couldn't unmarshal notary signature")

		return referrers, err
	}

	return referrers, nil
}

func syncCosignSignature(client *resty.Client, imageStore storage.ImageStore,
	regURL url.URL, localRepo, remoteRepo, digest string, cosignManifest *ispec.Manifest, log log.Logger,
) error {
	cosignTag := getCosignTagFromImageDigest(digest)

	// if no manifest found
	if cosignManifest == nil {
		return nil
	}

	log.Info().Msg("syncing cosign signatures")

	for _, blob := range cosignManifest.Layers {
		// get blob
		getBlobURL := regURL
		getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", blob.Digest.String())
		getBlobURL.RawQuery = getBlobURL.Query().Encode()

		resp, err := client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get cosign blob: %s", blob.Digest.String())

			return err
		}

		if resp.IsError() {
			log.Info().Msgf("couldn't find cosign blob from %s, status code: %d", getBlobURL.String(), resp.StatusCode())

			return zerr.ErrSyncSignature
		}

		defer resp.RawBody().Close()

		// push blob
		_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), blob.Digest.String())
		if err != nil {
			log.Error().Err(err).Msg("couldn't upload cosign blob")

			return err
		}
	}

	// get config blob
	getBlobURL := regURL
	getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", cosignManifest.Config.Digest.String())
	getBlobURL.RawQuery = getBlobURL.Query().Encode()

	resp, err := client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get cosign config blob: %s", getBlobURL.String())

		return err
	}

	if resp.IsError() {
		log.Info().Msgf("couldn't find cosign config blob from %s, status code: %d", getBlobURL.String(), resp.StatusCode())

		return zerr.ErrSyncSignature
	}

	defer resp.RawBody().Close()

	// push config blob
	_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), cosignManifest.Config.Digest.String())
	if err != nil {
		log.Error().Err(err).Msg("couldn't upload cosign config blob")

		return err
	}

	cosignManifestBuf, err := json.Marshal(cosignManifest)
	if err != nil {
		log.Error().Err(err).Msg("couldn't marshal cosign manifest")
	}

	// push manifest
	_, err = imageStore.PutImageManifest(localRepo, cosignTag, ispec.MediaTypeImageManifest, cosignManifestBuf)
	if err != nil {
		log.Error().Err(err).Msg("couldn't upload cosign manifest")

		return err
	}

	log.Info().Msgf("successfully synced cosign signature for repo %s digest %s", localRepo, digest)

	return nil
}

func syncNotarySignature(client *resty.Client, imageStore storage.ImageStore,
	regURL url.URL, localRepo, remoteRepo, digest string, referrers ReferenceList, log log.Logger,
) error {
	if len(referrers.References) == 0 {
		return nil
	}

	log.Info().Msg("syncing notary signatures")

	for _, ref := range referrers.References {
		// get referrer manifest
		getRefManifestURL := regURL
		getRefManifestURL.Path = path.Join(getRefManifestURL.Path, "v2", remoteRepo, "manifests", ref.Digest.String())
		getRefManifestURL.RawQuery = getRefManifestURL.Query().Encode()

		resp, err := client.R().
			Get(getRefManifestURL.String())
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get notary manifest: %s", getRefManifestURL.String())

			return err
		}

		// read manifest
		var artifactManifest artifactspec.Manifest

		err = json.Unmarshal(resp.Body(), &artifactManifest)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't unmarshal notary manifest: %s", getRefManifestURL.String())

			return err
		}

		for _, blob := range artifactManifest.Blobs {
			getBlobURL := regURL
			getBlobURL.Path = path.Join(getBlobURL.Path, "v2", remoteRepo, "blobs", blob.Digest.String())
			getBlobURL.RawQuery = getBlobURL.Query().Encode()

			resp, err := client.R().SetDoNotParseResponse(true).Get(getBlobURL.String())
			if err != nil {
				log.Error().Err(err).Msgf("couldn't get notary blob: %s", getBlobURL.String())

				return err
			}

			defer resp.RawBody().Close()

			if resp.IsError() {
				log.Info().Msgf("couldn't find notary blob from %s, status code: %d",
					getBlobURL.String(), resp.StatusCode())

				return zerr.ErrSyncSignature
			}

			_, _, err = imageStore.FullBlobUpload(localRepo, resp.RawBody(), blob.Digest.String())
			if err != nil {
				log.Error().Err(err).Msg("couldn't upload notary sig blob")

				return err
			}
		}

		_, err = imageStore.PutImageManifest(localRepo, ref.Digest.String(),
			artifactspec.MediaTypeArtifactManifest, resp.Body())
		if err != nil {
			log.Error().Err(err).Msg("couldn't upload notary sig manifest")

			return err
		}
	}

	log.Info().Msgf("successfully synced notary signature for repo %s digest %s", localRepo, digest)

	return nil
}

func canSkipNotarySignature(repo, tag, digest string, refs ReferenceList, imageStore storage.ImageStore,
	log log.Logger,
) (bool, error) {
	// check notary signature already synced
	if len(refs.References) > 0 {
		localRefs, err := imageStore.GetReferrers(repo, digest, notreg.ArtifactTypeNotation)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			log.Error().Err(err).Msgf("couldn't get local notary signature %s:%s manifest", repo, tag)

			return false, err
		}

		if !artifactDescriptorsEqual(localRefs, refs.References) {
			log.Info().Msgf("upstream notary signatures %s:%s changed, syncing again", repo, tag)

			return false, nil
		}
	}

	log.Info().Msgf("skipping notary signature %s:%s, already synced", repo, tag)

	return true, nil
}

func canSkipCosignSignature(repo, tag, digest string, cosignManifest *ispec.Manifest, imageStore storage.ImageStore,
	log log.Logger,
) (bool, error) {
	// check cosign signature already synced
	if cosignManifest != nil {
		var localCosignManifest ispec.Manifest

		/* we need to use tag (cosign format: sha256-$IMAGE_TAG.sig) instead of digest to get local cosign manifest
		because of an issue where cosign digests differs between upstream and downstream */
		cosignManifestTag := getCosignTagFromImageDigest(digest)

		localCosignManifestBuf, _, _, err := imageStore.GetImageManifest(repo, cosignManifestTag)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			log.Error().Err(err).Msgf("couldn't get local cosign %s:%s manifest", repo, tag)

			return false, err
		}

		err = json.Unmarshal(localCosignManifestBuf, &localCosignManifest)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't unmarshal local cosign signature %s:%s manifest", repo, tag)

			return false, err
		}

		if !manifestsEqual(localCosignManifest, *cosignManifest) {
			log.Info().Msgf("upstream cosign signatures %s:%s changed, syncing again", repo, tag)

			return false, nil
		}
	}

	log.Info().Msgf("skipping cosign signature %s:%s, already synced", repo, tag)

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

func getCosignTagFromImageDigest(digest string) string {
	if !isCosignTag(digest) {
		return strings.Replace(digest, ":", "-", 1) + "." + remote.SignatureTagSuffix
	}

	return digest
}
