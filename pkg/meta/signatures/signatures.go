package signatures

import (
	"context"
	"encoding/json"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
)

const (
	CosignSignature   = "cosign"
	NotationSignature = "notation"
	defaultDirPerms   = 0o700
	defaultFilePerms  = 0o644
)

func InitCosignAndNotationDirs(rootDir string) error {
	err := InitCosignDir(rootDir)
	if err != nil {
		return err
	}

	err = InitNotationDir(rootDir)

	return err
}

func VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, manifestContent []byte,
	repo string,
) (string, time.Time, bool, error) {
	var manifest ispec.Manifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return "", time.Time{}, false, err
	}

	desc := ispec.Descriptor{
		MediaType: manifest.MediaType,
		Digest:    manifestDigest,
		Size:      int64(len(manifestContent)),
	}

	if manifestDigest.String() == "" {
		return "", time.Time{}, false, zerr.ErrBadManifestDigest
	}

	switch signatureType {
	case CosignSignature:
		author, isValid, err := VerifyCosignSignature(repo, manifestDigest, sigKey, rawSignature)

		return author, time.Time{}, isValid, err
	case NotationSignature:
		return VerifyNotationSignature(desc, manifestDigest.String(), rawSignature, sigKey)
	default:
		return "", time.Time{}, false, zerr.ErrInvalidSignatureType
	}
}

func NewTaskGenerator(metaDB mTypes.MetaDB, log log.Logger) scheduler.TaskGenerator {
	return &sigValidityTaskGenerator{
		repos:     []mTypes.RepoMetadata{},
		metaDB:    metaDB,
		repoIndex: -1,
		log:       log,
	}
}

type sigValidityTaskGenerator struct {
	repos     []mTypes.RepoMetadata
	metaDB    mTypes.MetaDB
	repoIndex int
	done      bool
	log       log.Logger
}

func (gen *sigValidityTaskGenerator) Next() (scheduler.Task, error) {
	if len(gen.repos) == 0 {
		ctx := context.Background()

		repos, err := gen.metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMetadata) bool {
			return true
		})
		if err != nil {
			return nil, err
		}

		gen.repos = repos
	}

	gen.repoIndex++

	if gen.repoIndex >= len(gen.repos) {
		gen.done = true

		gen.log.Info().Msg("finished generating tasks for updating signatures validity")

		return nil, nil
	}

	return NewValidityTask(gen.metaDB, gen.repos[gen.repoIndex], gen.log), nil
}

func (gen *sigValidityTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *sigValidityTaskGenerator) IsReady() bool {
	return true
}

func (gen *sigValidityTaskGenerator) Reset() {
	gen.done = false
	gen.repoIndex = -1
	gen.repos = []mTypes.RepoMetadata{}

	gen.log.Info().Msg("finished resetting task generator for updating signatures validity")
}

type validityTask struct {
	metaDB mTypes.MetaDB
	repo   mTypes.RepoMetadata
	log    log.Logger
}

func NewValidityTask(metaDB mTypes.MetaDB, repo mTypes.RepoMetadata, log log.Logger) *validityTask {
	return &validityTask{metaDB, repo, log}
}

func (validityT *validityTask) DoWork() error {
	validityT.log.Info().Msg("updating signatures validity")

	for signedManifest, sigs := range validityT.repo.Signatures {
		if len(sigs[CosignSignature]) != 0 || len(sigs[NotationSignature]) != 0 {
			err := validityT.metaDB.UpdateSignaturesValidity(validityT.repo.Name, godigest.Digest(signedManifest))
			if err != nil {
				validityT.log.Info().Msg("error while verifying signatures")

				return err
			}
		}
	}

	validityT.log.Info().Msg("verifying signatures successfully completed")

	return nil
}
