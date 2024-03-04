//go:build sync
// +build sync

package references

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/static"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/pkg/extensions/sync/features"
	client "zotregistry.dev/zot/pkg/extensions/sync/httpclient"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type Reference interface {
	// Returns name of reference (OCIReference/CosignReference)
	Name() string
	// Returns whether or not image is signed
	IsSigned(ctx context.Context, upstreamRepo, subjectDigestStr string) bool
	// Sync recursively all references for a subject digest (can be image/artifacts/signatures)
	SyncReferences(ctx context.Context, localRepo, upstreamRepo, subjectDigestStr string) ([]godigest.Digest, error)
}

type References struct {
	referenceList []Reference
	features      *features.Map
	log           log.Logger
}

func NewReferences(httpClient *client.Client, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) References {
	refs := References{features: features.New(), log: log}

	refs.referenceList = append(refs.referenceList, NewCosignReference(httpClient, storeController, metaDB, log))
	refs.referenceList = append(refs.referenceList, NewTagReferences(httpClient, storeController, metaDB, log))
	refs.referenceList = append(refs.referenceList, NewOciReferences(httpClient, storeController, metaDB, log))

	return refs
}

func (refs References) IsSigned(ctx context.Context, upstreamRepo, subjectDigestStr string) bool {
	for _, ref := range refs.referenceList {
		ok := ref.IsSigned(ctx, upstreamRepo, subjectDigestStr)
		if ok {
			return true
		}
	}

	return false
}

func (refs References) SyncAll(ctx context.Context, localRepo, upstreamRepo, subjectDigestStr string) error {
	seen := &[]godigest.Digest{}

	return refs.syncAll(ctx, localRepo, upstreamRepo, subjectDigestStr, seen)
}

func (refs References) syncAll(ctx context.Context, localRepo, upstreamRepo,
	subjectDigestStr string, seen *[]godigest.Digest,
) error {
	var err error

	var syncedRefsDigests []godigest.Digest

	// mark subject digest as seen as soon as it comes in
	*seen = append(*seen, godigest.Digest(subjectDigestStr))

	// for each reference type(cosign/oci reference)
	for _, ref := range refs.referenceList {
		supported, ok := refs.features.Get(ref.Name(), upstreamRepo)
		if !supported && ok {
			continue
		}

		syncedRefsDigests, err = ref.SyncReferences(ctx, localRepo, upstreamRepo, subjectDigestStr)
		if err != nil {
			// for all referrers we can stop querying same repo (for ten minutes) if the errors are different than 404
			if !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
				refs.features.Set(ref.Name(), upstreamRepo, false)
			}

			// in the case of oci referrers, it will return 404 only if the repo is not found or refferers API is not supported
			// no need to continue to make requests to the same repo
			if ref.Name() == constants.OCI && errors.Is(err, zerr.ErrSyncReferrerNotFound) {
				refs.features.Set(ref.Name(), upstreamRepo, false)
			}

			refs.log.Debug().Err(err).
				Str("reference type", ref.Name()).
				Str("image", fmt.Sprintf("%s:%s", upstreamRepo, subjectDigestStr)).
				Msg("couldn't sync image referrer")
		} else {
			refs.features.Set(ref.Name(), upstreamRepo, true)
		}

		// for each synced references
		for _, refDigest := range syncedRefsDigests {
			if !common.Contains(*seen, refDigest) {
				// sync all references pointing to this one
				err = refs.syncAll(ctx, localRepo, upstreamRepo, refDigest.String(), seen)
			}
		}
	}

	return err
}

func (refs References) SyncReference(ctx context.Context, localRepo, upstreamRepo,
	subjectDigestStr, referenceType string,
) error {
	var err error

	var syncedRefsDigests []godigest.Digest

	for _, ref := range refs.referenceList {
		if ref.Name() == referenceType {
			syncedRefsDigests, err = ref.SyncReferences(ctx, localRepo, upstreamRepo, subjectDigestStr)
			if err != nil {
				refs.log.Debug().Err(err).
					Str("reference type", ref.Name()).
					Str("image", fmt.Sprintf("%s:%s", upstreamRepo, subjectDigestStr)).
					Msg("couldn't sync image referrer")

				return err
			}

			for _, refDigest := range syncedRefsDigests {
				err = refs.SyncAll(ctx, localRepo, upstreamRepo, refDigest.String())
			}
		}
	}

	return err
}

func syncBlob(ctx context.Context, client *client.Client, imageStore storageTypes.ImageStore,
	localRepo, remoteRepo string, digest godigest.Digest, log log.Logger,
) error {
	var resultPtr interface{}

	body, _, statusCode, err := client.MakeGetRequest(ctx, resultPtr, "", "v2", remoteRepo, "blobs", digest.String())
	if err != nil {
		if statusCode != http.StatusOK {
			log.Info().Str("repo", remoteRepo).Str("digest", digest.String()).Msg("couldn't get remote blob")

			return err
		}
	}

	_, _, err = imageStore.FullBlobUpload(localRepo, bytes.NewBuffer(body), digest)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).Str("digest", digest.String()).Str("repo", localRepo).
			Err(err).Msg("couldn't upload blob")

		return err
	}

	return nil
}

func manifestsEqual(manifest1, manifest2 ispec.Manifest) bool {
	if manifest1.Config.Digest == manifest2.Config.Digest &&
		manifest1.Config.MediaType == manifest2.Config.MediaType &&
		manifest1.Config.Size == manifest2.Config.Size {
		if descriptorsEqual(manifest1.Layers, manifest2.Layers) {
			return true
		}
	}

	return false
}

func descriptorsEqual(desc1, desc2 []ispec.Descriptor) bool {
	if len(desc1) != len(desc2) {
		return false
	}

	for id, desc := range desc1 {
		if !descriptorEqual(desc, desc2[id]) {
			return false
		}
	}

	return true
}

func descriptorEqual(desc1, desc2 ispec.Descriptor) bool {
	if desc1.Size == desc2.Size &&
		desc1.Digest == desc2.Digest &&
		desc1.MediaType == desc2.MediaType &&
		desc1.Annotations[static.SignatureAnnotationKey] == desc2.Annotations[static.SignatureAnnotationKey] {
		return true
	}

	return false
}

func getNotationManifestsFromOCIRefs(ociRefs ispec.Index) []ispec.Descriptor {
	notaryManifests := []ispec.Descriptor{}

	for _, ref := range ociRefs.Manifests {
		if ref.ArtifactType == common.ArtifactTypeNotation {
			notaryManifests = append(notaryManifests, ref)
		}
	}

	return notaryManifests
}

func getCosignManifestsFromOCIRefs(ociRefs ispec.Index) []ispec.Descriptor {
	cosignManifests := []ispec.Descriptor{}

	for _, ref := range ociRefs.Manifests {
		if ref.ArtifactType == common.ArtifactTypeCosign {
			cosignManifests = append(cosignManifests, ref)
		}
	}

	return cosignManifests
}
