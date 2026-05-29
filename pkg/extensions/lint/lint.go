//go:build lint

package lint

import (
	"encoding/json"
	"fmt"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type Linter struct {
	config            *config.LintConfig
	signatureVerifier mTypes.ImageTrustStore
	trustStoreReady   bool
	log               log.Logger
}

func NewLinter(config *config.LintConfig, log log.Logger) *Linter {
	return &Linter{
		config: config,
		log:    log,
	}
}

func (linter *Linter) SetSignatureVerifier(signatureVerifier mTypes.ImageTrustStore, trustStoreReady bool) {
	linter.signatureVerifier = signatureVerifier
	linter.trustStoreReady = trustStoreReady
}

func (linter *Linter) isEnabled() bool {
	return linter.config != nil && (linter.config.Enable == nil || *linter.config.Enable)
}

func (linter *Linter) CheckMandatoryAnnotations(repo string, manifestDigest godigest.Digest,
	imgStore storageTypes.ImageStore,
) (bool, error) {
	if linter.config == nil {
		return true, nil
	}

	if !linter.isEnabled() || len(linter.config.MandatoryAnnotations) == 0 {
		return true, nil
	}

	mandatoryAnnotationsList := linter.config.MandatoryAnnotations

	content, err := imgStore.GetBlobContent(repo, manifestDigest)
	if err != nil {
		linter.log.Error().Err(err).Str("component", "linter").Msg("failed to get image manifest")

		return false, err
	}

	var manifest ispec.Manifest

	if err := json.Unmarshal(content, &manifest); err != nil {
		linter.log.Error().Err(err).Str("component", "linter").Msg("failed to unmarshal manifest JSON")

		return false, err
	}

	mandatoryAnnotationsMap := make(map[string]bool)
	for _, annotation := range mandatoryAnnotationsList {
		mandatoryAnnotationsMap[annotation] = false
	}

	manifestAnnotations := manifest.Annotations
	for annotation := range manifestAnnotations {
		if _, ok := mandatoryAnnotationsMap[annotation]; ok {
			mandatoryAnnotationsMap[annotation] = true
		}
	}

	missingAnnotations := getMissingAnnotations(mandatoryAnnotationsMap)
	if len(missingAnnotations) == 0 {
		return true, nil
	}

	// if there are mandatory annotations missing in the manifest, get config and check these annotations too
	configDigest := manifest.Config.Digest

	content, err = imgStore.GetBlobContent(repo, configDigest)
	if err != nil {
		linter.log.Error().Err(err).Str("component", "linter").Msg("failed to get config JSON " +
			configDigest.String())

		return false, err
	}

	var imageConfig ispec.Image
	if err := json.Unmarshal(content, &imageConfig); err != nil {
		linter.log.Error().Err(err).Str("component", "linter").Msg("failed to unmarshal config JSON " + configDigest.String())

		return false, err
	}

	configAnnotations := imageConfig.Config.Labels

	for annotation := range configAnnotations {
		if _, ok := mandatoryAnnotationsMap[annotation]; ok {
			mandatoryAnnotationsMap[annotation] = true
		}
	}

	missingAnnotations = getMissingAnnotations(mandatoryAnnotationsMap)
	if len(missingAnnotations) > 0 {
		msg := fmt.Sprintf("\nlinter: manifest %s\nor config %s\nis missing the next annotations: %s",
			string(manifestDigest), string(configDigest), missingAnnotations)
		linter.log.Error().Msg(msg)

		return false, zerr.NewError(zerr.ErrImageLintAnnotations).AddDetail("missingAnnotations", msg)
	}

	return true, nil
}

func (linter *Linter) CheckMandatorySignatures(repo string, manifestDigest godigest.Digest,
	imgStore storageTypes.ImageStore,
) (bool, error) {
	if linter.config == nil || !linter.isEnabled() || len(linter.config.MandatorySignatures) == 0 {
		return true, nil
	}

	mandatory := false
	for _, mandatoryRepo := range linter.config.MandatorySignatures {
		if mandatoryRepo == "*" || mandatoryRepo == "**" || repo == mandatoryRepo {
			mandatory = true

			break
		}
	}

	if !mandatory {
		return true, nil
	}

	if linter.signatureVerifier == nil || !linter.trustStoreReady {
		msg := fmt.Sprintf("mandatory signatures lint for repository %q requires a configured trust store", repo)

		return false, zerr.NewError(zerr.ErrImageLintAnnotations).AddDetail("missingSignatures", msg)
	}

	isTrusted, err := linter.hasTrustedSignature(repo, manifestDigest, imgStore)
	if err != nil {
		return false, err
	}

	if !isTrusted {
		msg := fmt.Sprintf("manifest %s in repository %s does not have a trusted signature", manifestDigest, repo)

		return false, zerr.NewError(zerr.ErrImageLintAnnotations).AddDetail("missingSignatures", msg)
	}

	return true, nil
}

func (linter *Linter) hasTrustedSignature(repo string, manifestDigest godigest.Digest,
	imgStore storageTypes.ImageStore,
) (bool, error) {
	index, err := storageCommon.GetIndex(imgStore, repo, linter.log)
	if err != nil {
		return false, err
	}

	manifestBlob, err := imgStore.GetBlobContent(repo, manifestDigest)
	if err != nil {
		return false, err
	}

	imageMeta := mTypes.ImageMeta{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      int64(len(manifestBlob)),
	}

	for _, descriptor := range index.Manifests {
		if descriptor.Digest == manifestDigest {
			continue
		}

		signatureBlob, err := imgStore.GetBlobContent(repo, descriptor.Digest)
		if err != nil {
			continue
		}

		var signatureManifest ispec.Manifest
		if err := json.Unmarshal(signatureBlob, &signatureManifest); err != nil {
			continue
		}

		signatureType, isImageSignature := getSignatureType(descriptor, signatureManifest, manifestDigest)
		if !isImageSignature {
			continue
		}

		signatureLayers, err := meta.GetSignatureLayersInfo(repo,
			descriptor.Annotations[ispec.AnnotationRefName], descriptor.Digest.String(), signatureType,
			signatureBlob, imgStore, linter.log)
		if err != nil {
			continue
		}

		for _, signatureLayer := range signatureLayers {
			_, _, trusted, err := linter.signatureVerifier.VerifySignature(signatureType,
				signatureLayer.LayerContent, signatureLayer.SignatureKey, manifestDigest, imageMeta, repo)
			if err != nil {
				continue
			}

			if trusted {
				return true, nil
			}
		}
	}

	return false, nil
}

func getSignatureType(descriptor ispec.Descriptor, signatureManifest ispec.Manifest, manifestDigest godigest.Digest) (string, bool) {
	artifactType := zcommon.GetManifestArtifactType(signatureManifest)

	if signatureManifest.Subject != nil && signatureManifest.Subject.Digest == manifestDigest {
		switch {
		case zcommon.IsArtifactTypeCosign(artifactType):
			return zcommon.CosignSignature, true
		case artifactType == zcommon.ArtifactTypeNotation:
			return zcommon.NotationSignature, true
		}
	}

	tag := descriptor.Annotations[ispec.AnnotationRefName]
	if zcommon.IsCosignSignature(tag) {
		signedDigest, err := getDigestFromCosignTag(tag)
		if err == nil && signedDigest == manifestDigest {
			return zcommon.CosignSignature, true
		}
	}

	return "", false
}

func getDigestFromCosignTag(tag string) (godigest.Digest, error) {
	const (
		cosignPrefix = "sha256-"
		cosignSuffix = ".sig"
	)

	if !strings.HasPrefix(tag, cosignPrefix) || !strings.HasSuffix(tag, cosignSuffix) {
		return "", zerr.ErrBadManifest
	}

	encodedDigest := strings.TrimSuffix(strings.TrimPrefix(tag, cosignPrefix), cosignSuffix)

	return godigest.NewDigestFromEncoded(godigest.SHA256, encodedDigest), nil
}

func (linter *Linter) Lint(repo string, manifestDigest godigest.Digest,
	imageStore storageTypes.ImageStore,
) (bool, error) {
	pass, err := linter.CheckMandatoryAnnotations(repo, manifestDigest, imageStore)
	if err != nil || !pass {
		return pass, err
	}

	return linter.CheckMandatorySignatures(repo, manifestDigest, imageStore)
}

func getMissingAnnotations(mandatoryAnnotationsMap map[string]bool) []string {
	var missingAnnotations []string

	for annotation, flag := range mandatoryAnnotationsMap {
		if !flag {
			missingAnnotations = append(missingAnnotations, annotation)
		}
	}

	return missingAnnotations
}
