//go:build sync
// +build sync

package references

import (
	"errors"
	"fmt"
	"net/http"

	godigest "github.com/opencontainers/go-digest"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	apiConstants "zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/sync/constants"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

type ReferenceList struct {
	References []oras.Descriptor `json:"references"`
}

type ORASReferences struct {
	client          *client.Client
	storeController storage.StoreController
	repoDB          repodb.RepoDB
	log             log.Logger
}

func NewORASReferences(httpClient *client.Client, storeController storage.StoreController,
	repoDB repodb.RepoDB, log log.Logger,
) ORASReferences {
	return ORASReferences{
		client:          httpClient,
		storeController: storeController,
		repoDB:          repoDB,
		log:             log,
	}
}

func (ref ORASReferences) Name() string {
	return constants.Oras
}

func (ref ORASReferences) IsSigned(remoteRepo, subjectDigestStr string) bool {
	return false
}

func (ref ORASReferences) canSkipReferences(localRepo, subjectDigestStr string, referrers ReferenceList) (bool, error) {
	imageStore := ref.storeController.GetImageStore(localRepo)
	digest := godigest.Digest(subjectDigestStr)

	// check oras artifacts already synced
	if len(referrers.References) > 0 {
		localRefs, err := imageStore.GetOrasReferrers(localRepo, digest, "")
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return false, nil
			}

			ref.log.Error().Str("errorType", common.TypeOf(err)).Str("repository", localRepo).
				Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't get local ORAS artifact for image")

			return false, err
		}

		if !artifactDescriptorsEqual(localRefs, referrers.References) {
			ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("upstream ORAS artifacts for image changed, syncing again")

			return false, nil
		}
	}

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("skipping ORAS artifact for image, already synced")

	return true, nil
}

func (ref ORASReferences) SyncReferences(localRepo, remoteRepo, subjectDigestStr string) error {
	referrers, err := ref.getReferenceList(remoteRepo, subjectDigestStr)
	if err != nil {
		return err
	}

	skipORASRefs, err := ref.canSkipReferences(localRepo, subjectDigestStr, referrers)
	if err != nil {
		ref.log.Error().Err(err).Str("repository", localRepo).Str("subject", subjectDigestStr).
			Msg("couldn't check if ORAS artifact for image can be skipped")
	}

	if skipORASRefs {
		return nil
	}

	imageStore := ref.storeController.GetImageStore(localRepo)

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("syncing ORAS artifacts for image")

	for _, referrer := range referrers.References {
		var artifactManifest oras.Manifest

		orasBuf, _, statusCode, err := ref.client.MakeGetRequest(&artifactManifest, oras.MediaTypeDescriptor,
			"v2", remoteRepo, "manifests", referrer.Digest.String())
		if err != nil {
			if statusCode == http.StatusNotFound {
				return zerr.ErrSyncReferrerNotFound
			}

			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't get ORAS artifact for image")

			return err
		}

		for _, blob := range artifactManifest.Blobs {
			if err := syncBlob(ref.client, imageStore, localRepo, remoteRepo, blob.Digest, ref.log); err != nil {
				return err
			}
		}

		digest, _, err := imageStore.PutImageManifest(localRepo, referrer.Digest.String(),
			oras.MediaTypeArtifactManifest, orasBuf)
		if err != nil {
			ref.log.Error().Str("errorType", common.TypeOf(err)).
				Str("repository", localRepo).Str("subject", subjectDigestStr).
				Err(err).Msg("couldn't upload ORAS artifact for image")

			return err
		}

		if ref.repoDB != nil {
			ref.log.Debug().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("repoDB: trying to sync oras artifact for image")

			err := repodb.SetImageMetaFromInput(localRepo, digest.String(), referrer.MediaType,
				digest, orasBuf, ref.storeController.GetImageStore(localRepo),
				ref.repoDB, ref.log)
			if err != nil {
				return fmt.Errorf("repoDB: failed to set metadata for oras artifact '%s@%s': %w", localRepo, subjectDigestStr, err)
			}

			ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
				Msg("repoDB: successfully added oras artifacts to RepoDB for image")
		}
	}

	ref.log.Info().Str("repository", localRepo).Str("subject", subjectDigestStr).
		Msg("successfully synced oras artifacts for image")

	return nil
}

func (ref ORASReferences) getReferenceList(repo, subjectDigestStr string) (ReferenceList, error) {
	var referrers ReferenceList

	_, _, statusCode, err := ref.client.MakeGetRequest(&referrers, "application/json",
		apiConstants.ArtifactSpecRoutePrefix, repo, "manifests", subjectDigestStr, "referrers")
	if err != nil {
		if statusCode == http.StatusNotFound || statusCode == http.StatusBadRequest {
			ref.log.Debug().Str("repository", repo).Str("subject", subjectDigestStr).Err(err).
				Msg("couldn't find any ORAS artifact for image")

			return referrers, zerr.ErrSyncReferrerNotFound
		}

		ref.log.Error().Err(err).Str("repository", repo).Str("subject", subjectDigestStr).
			Msg("couldn't get ORAS artifacts for image")

		return referrers, err
	}

	return referrers, nil
}
