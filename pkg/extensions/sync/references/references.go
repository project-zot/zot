//go:build sync
// +build sync

package references

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/static"

	"zotregistry.io/zot/pkg/common"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

type Reference interface {
	// Returns name of reference (OCIReference/CosignReference/OrasReference)
	Name() string
	// Returns whether or not image is signed
	IsSigned(ctx context.Context, upstreamRepo, subjectDigestStr string) bool
	// Sync recursively all references for a subject digest (can be image/artifacts/signatures)
	SyncReferences(ctx context.Context, localRepo, upstreamRepo, subjectDigestStr string) ([]godigest.Digest, error)
}

type References struct {
	referenceList []Reference
	log           log.Logger
}

func NewReferences(httpClient *client.Client, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) References {
	refs := References{log: log}

	refs.referenceList = append(refs.referenceList, NewCosignReference(httpClient, storeController, metaDB, log))
	refs.referenceList = append(refs.referenceList, NewTagReferences(httpClient, storeController, metaDB, log))
	refs.referenceList = append(refs.referenceList, NewOciReferences(httpClient, storeController, metaDB, log))
	refs.referenceList = append(refs.referenceList, NewORASReferences(httpClient, storeController, metaDB, log))

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

	// for each reference type(cosign/oci/oras reference)
	for _, ref := range refs.referenceList {
		syncedRefsDigests, err = ref.SyncReferences(ctx, localRepo, upstreamRepo, subjectDigestStr)
		if err != nil {
			refs.log.Debug().Err(err).
				Str("reference type", ref.Name()).
				Str("image", fmt.Sprintf("%s:%s", upstreamRepo, subjectDigestStr)).
				Msg("couldn't sync image referrer")
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

func artifactDescriptorsEqual(desc1, desc2 []artifactspec.Descriptor) bool {
	if len(desc1) != len(desc2) {
		return false
	}

	for id, desc := range desc1 {
		if desc.Digest != desc2[id].Digest ||
			desc.Size != desc2[id].Size ||
			desc.MediaType != desc2[id].MediaType ||
			desc.ArtifactType != desc2[id].ArtifactType {
			return false
		}
	}

	return true
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
