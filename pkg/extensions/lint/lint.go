//go:build lint
// +build lint

package lint

import (
	"encoding/json"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
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
	imgStore storage.ImageStore,
) (bool, error) {
	if linter.config == nil {
		return true, nil
	}

	if (linter.config != nil && !*linter.config.Enabled) || len(linter.config.MandatoryAnnotations) == 0 {
		return true, nil
	}

	mandatoryAnnotationsList := linter.config.MandatoryAnnotations

	content, err := imgStore.GetBlobContent(repo, string(manifestDigest))
	if err != nil {
		linter.log.Error().Err(err).Msg("linter: unable to get image manifest")

		return false, err
	}

	var manifest ispec.Manifest

	if err := json.Unmarshal(content, &manifest); err != nil {
		linter.log.Error().Err(err).Msg("linter: couldn't unmarshal manifest JSON")

		return false, err
	}

	annotations := manifest.Annotations

	for _, annot := range mandatoryAnnotationsList {
		_, found := annotations[annot]

		if !found {
			// if annotations are not found, return false but it's not an error
			linter.log.Error().Msgf("linter: missing %s annotations", annot)

			return false, nil
		}
	}

	return true, nil
}

func (linter *Linter) Lint(repo string, manifestDigest godigest.Digest,
	imageStore storage.ImageStore,
) (bool, error) {
	return linter.CheckMandatoryAnnotations(repo, manifestDigest, imageStore)
}
