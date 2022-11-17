//go:build lint
// +build lint

package lint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	_ "image/gif"  // imported for the registration of it's decoder func
	_ "image/jpeg" // imported for the registration of it's decoder func
	_ "image/png"  // imported for the registration of it's decoder func

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
)

type Linter struct {
	config *config.LintConfig
	log    log.Logger
}

func NewLinter(config *config.LintConfig, log log.Logger) *Linter {
	return &Linter{
		config: config,
		log:    log,
	}
}

func (linter *Linter) CheckMandatoryConditions(repo string, manifestDescriptor ispec.Descriptor,
	imgStore storage.ImageStore,
) (bool, error) {
	passing := false

	passing, err := linter.CheckMandatoryAnnotations(repo, manifestDescriptor, imgStore)
	if err != nil || !passing {
		return passing, err
	}

	if manifestDescriptor.MediaType == ispec.MediaTypeArtifactManifest {
		return linter.CheckArtifactIfLogo(repo, manifestDescriptor.Digest, imgStore)
	}

	return passing, nil
}

func (linter *Linter) CheckArtifactIfLogo(repo string, manifestDigest godigest.Digest,
	imgStore storage.ImageStore,
) (bool, error) {
	artifactManifestBlob, err := imgStore.GetBlobContent(repo, manifestDigest)
	if err != nil {
		linter.log.Error().Err(err).Msg("linter: unable to get artifact manifest")

		return false, err
	}

	var artifact ispec.Artifact
	if err := json.Unmarshal(artifactManifestBlob, &artifact); err != nil {
		linter.log.Error().Err(err).Msg("unable to unmarshal JSON")

		return false, zerr.ErrBadManifest
	}

	if artifact.ArtifactType == storageConstants.LogoKey {
		artifactBlobDigest := artifact.Blobs[0].Digest

		artifactBlob, err := imgStore.GetBlobContent(repo, artifactBlobDigest)
		if err != nil {
			linter.log.Error().Err(err).Msg("linter: unable to get artifact blob")

			return false, zerr.ErrBadManifest
		}

		if !isLogoDataValid(string(artifactBlob), linter.log) {
			linter.log.Error().Err(err).Msg("invalid logo data")

			return false, zerr.ErrImageLintAnnotations
		}
	}

	return true, nil
}

func (linter *Linter) CheckMandatoryAnnotations(repo string, manifestDescriptor ispec.Descriptor,
	imgStore storage.ImageStore,
) (bool, error) {
	if linter.config == nil {
		return true, nil
	}

	if (linter.config != nil && !*linter.config.Enable) || len(linter.config.MandatoryAnnotations) == 0 {
		return true, nil
	}

	mandatoryAnnotationsList := linter.config.MandatoryAnnotations

	content, err := imgStore.GetBlobContent(repo, manifestDescriptor.Digest)
	if err != nil {
		linter.log.Error().Err(err).Msg("linter: unable to get image manifest")

		return false, err
	}

	mandatoryAnnotationsMap := make(map[string]bool)
	for _, annotation := range mandatoryAnnotationsList {
		mandatoryAnnotationsMap[annotation] = false
	}

	if manifestDescriptor.MediaType == ispec.MediaTypeImageManifest {
		var manifest ispec.Manifest

		if err := json.Unmarshal(content, &manifest); err != nil {
			linter.log.Error().Err(err).Msg("linter: couldn't unmarshal manifest JSON")

			return false, err
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
			linter.log.Error().Err(err).Msg("linter: couldn't get config JSON " + configDigest.String())

			return false, err
		}

		var imageConfig ispec.Image
		if err := json.Unmarshal(content, &imageConfig); err != nil {
			linter.log.Error().Err(err).Msg("linter: couldn't unmarshal config JSON " + configDigest.String())

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
			linter.log.Error().Msgf("linter: manifest %s / config %s are missing annotations: %s",
				string(manifestDescriptor.Digest), string(configDigest), missingAnnotations)

			return false, nil
		}
	}

	if manifestDescriptor.MediaType == ispec.MediaTypeArtifactManifest {
		var artifactManifest ispec.Artifact
		if err := json.Unmarshal(content, &artifactManifest); err != nil {
			linter.log.Error().Err(err).Msg("linter: couldn't unmarshal artifact manifest JSON")

			return false, err
		}

		artifactAnnotations := artifactManifest.Annotations
		for annotation := range artifactAnnotations {
			if _, ok := mandatoryAnnotationsMap[annotation]; ok {
				mandatoryAnnotationsMap[annotation] = true
			}
		}

		missingAnnotations := getMissingAnnotations(mandatoryAnnotationsMap)
		if len(missingAnnotations) == 0 {
			return true, nil
		}

		// if there are mandatory annotations missing in the artifact, get blobs and check these annotations too
		for _, blobDescriptor := range artifactManifest.Blobs {
			for annotation := range blobDescriptor.Annotations {
				if _, ok := mandatoryAnnotationsMap[annotation]; ok {
					mandatoryAnnotationsMap[annotation] = true
				}
			}
		}

		missingAnnotations = getMissingAnnotations(mandatoryAnnotationsMap)
		if len(missingAnnotations) > 0 {
			linter.log.Error().Msgf("linter: artifact manifest %s and its blobs  are missing annotations: %s",
				string(manifestDescriptor.Digest), missingAnnotations)

			return false, nil
		}
	}

	return true, nil
}

func (linter *Linter) Lint(repo string, manifestDescriptor ispec.Descriptor,
	imageStore storage.ImageStore,
) (bool, error) {
	return linter.CheckMandatoryConditions(repo, manifestDescriptor, imageStore)
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

func isLogoDataValid(logoVal string, log log.Logger) bool {
	decodedVal, err := base64.StdEncoding.DecodeString(logoVal)
	if err != nil {
		log.Error().Err(err).Msg("unable to decode value")

		return false
	}
	imageVal := bytes.NewBuffer(decodedVal)

	logoConf, format, err := image.DecodeConfig(imageVal)
	if err != nil {
		log.Error().Err(err).Msg("unable to decode image")

		return false
	}

	if format != "jpeg" && format != "gif" && format != "png" {
		log.Error().Msg("encoded logo is of incorrect format, allowed formats are jpeg/png/gif")

		return false
	}

	if logoConf.Height > 200 || logoConf.Width > 200 {
		log.Error().Msg("encoded logo is of incorrect size")

		return false
	}

	return true
}
