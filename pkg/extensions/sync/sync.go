//go:build sync
// +build sync

package sync

import (
	"context"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/scheduler"
)

// below types are used by containers/image to copy images
// types.ImageReference - describes a registry/repo:tag
// types.SystemContext - describes a registry/oci layout config

// Sync general functionalities, one service per registry config.
type Service interface {
	// Get next repo from remote /v2/_catalog, will return empty string when there is no repo left.
	GetNextRepo(lastRepo string) (string, error) // used by task scheduler
	// Sync a repo with all of its tags and references (signatures, artifacts, sboms) into ImageStore.
	SyncRepo(repo string) error // used by periodically sync
	// Sync an image (repo:tag || repo:digest) into ImageStore.
	SyncImage(repo, reference string) error // used by sync on demand
	// Sync a single reference for an image.
	SyncReference(repo string, subjectDigestStr string, referenceType string) error // used by sync on demand
	// Remove all internal catalog entries.
	ResetCatalog() // used by scheduler to empty out the catalog after a sync periodically roundtrip finishes
	// Sync supports multiple urls per registry, before a sync repo/image/ref 'ping' each url.
	SetNextAvailableURL() error // used by all sync methods
	// Returns retry options from registry config.
	GetRetryOptions() *retry.Options // used by sync on demand to retry in background
}

// Local and remote registries must implement this interface.
type Registry interface {
	// Get temporary ImageReference, is used by functions in containers/image package
	GetImageReference(repo string, tag string) (types.ImageReference, error)
	// Get local oci layout context, is used by functions in containers/image package
	GetContext() *types.SystemContext
}

/*
Temporary oci layout, sync first pulls an image to this oci layout (using oci:// transport)
then moves them into ImageStore.
*/
type OciLayoutStorage interface {
	Registry
}

// Remote registry.
type Remote interface {
	Registry
	// Get a list of repos (catalog)
	GetRepositories(ctx context.Context) ([]string, error)
	// Get a list of tags given a repo
	GetRepoTags(repo string) ([]string, error)
	// Get manifest content, mediaType, digest given an ImageReference
	GetManifestContent(imageReference types.ImageReference) ([]byte, string, digest.Digest, error)
}

// Local registry.
type Local interface {
	Registry
	// Check if an image is already synced
	CanSkipImage(repo, tag string, imageDigest digest.Digest) (bool, error)
	// CommitImage moves a synced repo/ref from temporary oci layout to ImageStore
	CommitImage(imageReference types.ImageReference, repo, tag string) error
}

type TaskGenerator struct {
	Service  Service
	lastRepo string
	done     bool
	log      log.Logger
}

func NewTaskGenerator(service Service, log log.Logger) *TaskGenerator {
	return &TaskGenerator{
		Service:  service,
		done:     false,
		lastRepo: "",
		log:      log,
	}
}

func (gen *TaskGenerator) GenerateTask() (scheduler.Task, error) {
	if err := gen.Service.SetNextAvailableURL(); err != nil {
		return nil, err
	}

	repo, err := gen.Service.GetNextRepo(gen.lastRepo)
	if err != nil {
		return nil, err
	}

	if repo == "" {
		gen.log.Info().Msg("sync: finished syncing all repos")
		gen.done = true

		return nil, nil
	}

	gen.lastRepo = repo

	return newSyncRepoTask(gen.lastRepo, gen.Service), nil
}

func (gen *TaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *TaskGenerator) Reset() {
	gen.lastRepo = ""
	gen.Service.ResetCatalog()
	gen.done = false
}

type syncRepoTask struct {
	repo    string
	service Service
}

func newSyncRepoTask(repo string, service Service) *syncRepoTask {
	return &syncRepoTask{repo, service}
}

func (srt *syncRepoTask) DoWork() error {
	return srt.service.SyncRepo(srt.repo)
}
