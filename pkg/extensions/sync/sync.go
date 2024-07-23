//go:build sync
// +build sync

package sync

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/scheduler"
)

// below types are used by containers/image to copy images
// types.ImageReference - describes a registry/repo:tag
// types.SystemContext - describes a registry/oci layout config

// Sync general functionalities, one service per registry config.
type Service interface {
	// Get next repo from remote /v2/_catalog, will return empty string when there is no repo left.
	GetNextRepo(lastRepo string) (string, error) // used by task scheduler
	// Sync a repo with all of its tags and references (signatures, artifacts, sboms) into ImageStore.
	SyncRepo(ctx context.Context, repo string) error // used by periodically sync
	// Sync an image (repo:tag || repo:digest) into ImageStore.
	SyncImage(ctx context.Context, repo, reference string) error // used by sync on demand
	// Sync a single reference for an image.
	SyncReference(ctx context.Context, repo string, subjectDigestStr string,
		referenceType string) error // used by sync on demand
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
	// In the case of public dockerhub images 'library' namespace is added to the repo names of images
	// eg: alpine -> library/alpine
	GetDockerRemoteRepo(repo string) string
}

// Local registry.
type Destination interface {
	Registry
	// Check if an image is already synced
	CanSkipImage(repo, tag string, imageDigest digest.Digest) (bool, error)
	// CommitImage moves a synced repo/ref from temporary oci layout to ImageStore
	CommitImage(imageReference types.ImageReference, repo, tag string) error
	// Removes image reference, used when copy.Image() errors out
	CleanupImage(imageReference types.ImageReference, repo, reference string) error
}

type TaskGenerator struct {
	Service      Service
	lastRepo     string
	done         bool
	waitTime     time.Duration
	lastTaskTime time.Time
	maxWaitTime  time.Duration
	lock         *sync.Mutex
	log          log.Logger
}

func NewTaskGenerator(service Service, maxWaitTime time.Duration, log log.Logger) *TaskGenerator {
	return &TaskGenerator{
		Service:      service,
		done:         false,
		waitTime:     0,
		lastTaskTime: time.Now(),
		lock:         &sync.Mutex{},
		lastRepo:     "",
		maxWaitTime:  maxWaitTime,
		log:          log,
	}
}

func (gen *TaskGenerator) Name() string {
	return "SyncGenerator"
}

func (gen *TaskGenerator) Next() (scheduler.Task, error) {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	if time.Since(gen.lastTaskTime) <= gen.waitTime {
		return nil, nil
	}

	if err := gen.Service.SetNextAvailableURL(); err != nil {
		gen.increaseWaitTime()

		return nil, err
	}

	repo, err := gen.Service.GetNextRepo(gen.lastRepo)
	if err != nil {
		gen.increaseWaitTime()

		return nil, err
	}

	gen.resetWaitTime()

	if repo == "" {
		gen.log.Info().Str("component", "sync").Msg("finished syncing all repositories")
		gen.done = true

		return nil, nil
	}

	gen.lastRepo = repo

	return newSyncRepoTask(gen.lastRepo, gen.Service), nil
}

func (gen *TaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *TaskGenerator) IsReady() bool {
	return true
}

func (gen *TaskGenerator) Reset() {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	gen.lastRepo = ""
	gen.Service.ResetCatalog()
	gen.done = false
	gen.waitTime = 0
}

func (gen *TaskGenerator) increaseWaitTime() {
	if gen.waitTime == 0 {
		gen.waitTime = time.Second
	}

	gen.waitTime *= 2

	// max wait time should not exceed generator interval.
	if gen.waitTime > gen.maxWaitTime {
		gen.waitTime = gen.maxWaitTime
	}

	gen.lastTaskTime = time.Now()
}

// resets wait time.
func (gen *TaskGenerator) resetWaitTime() {
	gen.lastTaskTime = time.Now()
	gen.waitTime = 0
}

type syncRepoTask struct {
	repo    string
	service Service
}

func newSyncRepoTask(repo string, service Service) *syncRepoTask {
	return &syncRepoTask{repo, service}
}

func (srt *syncRepoTask) DoWork(ctx context.Context) error {
	return srt.service.SyncRepo(ctx, srt.repo)
}

func (srt *syncRepoTask) String() string {
	return fmt.Sprintf("{Name: \"%s\", repository: \"%s\"}",
		srt.Name(), srt.repo)
}

func (srt *syncRepoTask) Name() string {
	return "SyncTask"
}
