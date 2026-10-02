package common

import (
	"context"
	"errors"

	godigest "github.com/opencontainers/go-digest"
	"google.golang.org/protobuf/types/known/timestamppb"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

// signatureLayerKey identifies one signature layer of a manifest. The signature key is part of it because a cosign
// signature manifest holds one layer per signature, and every signature of the same image has the same payload: the
// layers share their digest and only differ in their signature annotation, which is the signature key.
type signatureLayerKey struct {
	signatureType           string
	signatureManifestDigest string
	layerDigest             string
	signatureKey            string
}

type layerValidity struct {
	signer string
	date   *timestamppb.Timestamp // nil if verification found no expiry date: the stored date is kept
}

// SignaturesValidity holds the verification results of the signature layers of one manifest, as returned by
// VerifyManifestSignatures. It only contains the layers that were actually verified.
type SignaturesValidity map[signatureLayerKey]layerValidity

// VerifyManifestSignatures verifies every signature layer of a manifest against the trust store and returns the
// results (Signer, Date), leaving signatures unchanged. The MetaDB implementations call it on a copy of the signatures
// read outside of any write lock, and write the results back with ApplySignaturesValidity. The trust store loads the
// layers from storage; a layer that cannot be loaded right now has no result, so it keeps whatever validity is stored
// when the results are written back. A layer too large to be a signature is not trusted.
func VerifyManifestSignatures(ctx context.Context, imgTrustStore mTypes.ImageTrustStore, repo string,
	manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta, signatures *proto_go.ManifestSignatures,
	log log.Logger,
) (SignaturesValidity, error) {
	validity := SignaturesValidity{}

	for sigType, sigs := range signatures.GetMap() {
		if zcommon.IsContextDone(ctx) {
			return nil, ctx.Err()
		}

		for _, sigInfo := range sigs.GetList() {
			for _, layerInfo := range sigInfo.GetLayersInfo() {
				author, date, isTrusted, err := imgTrustStore.VerifySignatureLayer(sigType,
					godigest.Digest(layerInfo.GetLayerDigest()), layerInfo.GetSignatureKey(), manifestDigest, imageMeta, repo)
				if errors.Is(err, zerr.ErrSignatureLayerUnavailable) {
					log.Warn().Err(err).Str("repo", repo).Str("signatureType", sigType).
						Str("manifestDigest", manifestDigest.String()).Str("layerDigest", layerInfo.GetLayerDigest()).
						Msg("failed to load signature layer, keeping its previous validity")

					continue
				}

				switch {
				case errors.Is(err, zerr.ErrSignatureLayerTooLarge):
					// typically an attestation that an older version recorded as a signature: its layer is an SBOM or a
					// vulnerability report, not a signature, and it stays untrusted until the meta DB is rebuilt
					log.Warn().Err(err).Str("repo", repo).Str("signatureType", sigType).
						Str("manifestDigest", manifestDigest.String()).Str("layerDigest", layerInfo.GetLayerDigest()).
						Msg("signature layer is too large to be a signature, not trusted")
				case err != nil:
					log.Error().Err(err).Str("repo", repo).Str("signatureType", sigType).
						Str("manifestDigest", manifestDigest.String()).
						Str("mediaType", imageMeta.MediaType).
						Msg("failed to verify signature validity")
				}

				result := layerValidity{}

				if isTrusted {
					result.signer = author
				}

				if !date.IsZero() {
					result.date = timestamppb.New(date)
				}

				validity[signatureLayerKey{
					signatureType:           sigType,
					signatureManifestDigest: sigInfo.GetSignatureManifestDigest(),
					layerDigest:             layerInfo.GetLayerDigest(),
					signatureKey:            layerInfo.GetSignatureKey(),
				}] = result
			}
		}
	}

	return validity, nil
}

// ApplySignaturesValidity writes the verification results in validity onto current, the signatures of the same
// manifest as they are stored now. Only layers with a result are updated: signatures added since they were verified,
// and layers that could not be verified, are left as they are.
func ApplySignaturesValidity(current *proto_go.ManifestSignatures, validity SignaturesValidity) {
	for sigType, sigs := range current.GetMap() {
		for _, sigInfo := range sigs.GetList() {
			for _, layerInfo := range sigInfo.GetLayersInfo() {
				result, ok := validity[signatureLayerKey{
					signatureType:           sigType,
					signatureManifestDigest: sigInfo.GetSignatureManifestDigest(),
					layerDigest:             layerInfo.GetLayerDigest(),
					signatureKey:            layerInfo.GetSignatureKey(),
				}]
				if !ok {
					continue
				}

				layerInfo.Signer = result.signer

				if result.date != nil {
					layerInfo.Date = result.date
				}
			}
		}
	}
}

// StripSignatureLayerContent drops the signature layer content older zot versions stored in the repo record, so the
// record shrinks the next time it is written. Signature layers are loaded from storage when they are verified.
func StripSignatureLayerContent(repoMeta *proto_go.RepoMeta) {
	for _, manifestSignatures := range repoMeta.GetSignatures() {
		for _, sigs := range manifestSignatures.GetMap() {
			for _, sigInfo := range sigs.GetList() {
				for _, layerInfo := range sigInfo.GetLayersInfo() {
					layerInfo.LayerContent = nil
				}
			}
		}
	}
}
