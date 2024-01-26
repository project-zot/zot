//go:build lint
// +build lint

package lint

import (
	"encoding/json"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/log"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
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

func (linter *Linter) CheckMandatoryAnnotations(repo string, manifestDigest godigest.Digest,
	imgStore storageTypes.ImageStore,
) (bool, error) {
	if linter.config == nil {
		return true, nil
	}

	if (linter.config != nil && !*linter.config.Enable) || len(linter.config.MandatoryAnnotations) == 0 {
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

func (linter *Linter) Lint(repo string, manifestDigest godigest.Digest,
	imageStore storageTypes.ImageStore,
) (bool, error) {
	return linter.CheckMandatoryAnnotations(repo, manifestDigest, imageStore)
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
