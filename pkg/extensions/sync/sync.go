//go:build sync

package sync

import (
	"context"
	"fmt"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/ref"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
)

// below types are used by regclient to copy images
// ref.Ref- describes a registry/repo:tag

// Service provides sync general functionalities, one service per registry config.
type Service interface {
	// Get next repo from remote /v2/_catalog, will return empty string when there is no repo left.
	GetNextRepo(lastRepo string) (string, error) // used by task scheduler
	// Sync a repo with all of its tags and references (signatures, artifacts, sboms) into ImageStore.
	SyncRepo(ctx context.Context, repo string) error // used by periodically sync
	// Sync an image (repo:tag || repo:digest) into ImageStore.
	SyncImage(ctx context.Context, repo, reference string) error // used by sync on demand
	// Sync referrers for an image (repo:subjectDigestStr) into ImageStore.
	SyncReferrers(ctx context.Context, repo string, subjectDigestStr string, referenceTypes []string) error
	// Sync a blob (repo@digest) into ImageStore with streaming support.
	SyncBlob(ctx context.Context, repo string, digest godigest.Digest) error // used by sync on demand for blobs
	// Remove all internal catalog entries.
	ResetCatalog() // used by scheduler to empty out the catalog after a sync periodically roundtrip finishes
	/* Returns if service has retry option set.
	Is used by ondemand to decide if it retries pulling an image in background or not. */
	CanRetryOnError() bool // used by sync on demand to retry in background
	// Get the sync timeout configured for this service
	GetSyncTimeout() time.Duration
}

// Registry interface must be implemented by local and remote registries.
type Registry interface {
	// Get temporary ImageReference, is used by functions in regclient package
	GetImageReference(repo string, tag string) (ref.Ref, error)
}

// The CredentialHelper interface should be implemented by registries that use temporary tokens.
// This interface defines methods to:
// - Check if the credentials for a registry are still valid.
// - Retrieve credentials for the specified registry URLs.
// - Refresh credentials for a given registry URL.
type CredentialHelper interface {
	// Validates whether the credentials for the specified registry URL have expired.
	AreCredentialsValid(url string) bool

	// Retrieves credentials for the provided list of registry URLs.
	GetCredentials(urls []string) (syncconf.CredentialsFile, error)

	// Refreshes credentials for the specified registry URL.
	RefreshCredentials(url string) (syncconf.Credentials, error)
}

/*
OciLayoutStorage is a temporary oci layout, sync first pulls an image to this oci layout (using oci:// transport)
then moves them into ImageStore.
*/
type OciLayoutStorage interface {
	Registry
}

// Remote registry.
type Remote interface {
	Registry
	// Get host name
	GetHostName() string
	// Get a list of repos (catalog)
	GetRepositories(ctx context.Context) ([]string, error)
	// Get a list of tags given a repo
	GetTags(ctx context.Context, repo string) ([]string, error)
	/* Get oci digest for repo:tag, if docker image, convert it before returning:
	oci digest,	original digest on the remote before converting, if it was converted and error	*/
	GetOCIDigest(ctx context.Context, repo, tag string) (godigest.Digest, godigest.Digest, bool, error)
	// Get remote digest for repo:tag
	GetDigest(ctx context.Context, repo, tag string) (godigest.Digest, error)
}

// Destination is a local registry.
type Destination interface {
	Registry
	// Check if descriptors are already synced
	CanSkipImage(repo string, tag string, digest godigest.Digest) (bool, error)
	// CommitAll moves a synced repo and all its manifests from temporary oci layout to ImageStore
	CommitAll(repo string, imageReference ref.Ref) error
	// Removes image reference, used when copy.Image() errors out
	CleanupImage(imageReference ref.Ref, repo string) error
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
		return nil, nil //nolint:nilnil
	}

	repo, err := gen.Service.GetNextRepo(gen.lastRepo)
	if err != nil {
		gen.increaseWaitTime()

		return nil, err
	}

	gen.resetWaitTime()

	if repo == "" {
		gen.log.Info().Str("component", "sync").Msg("finished generating tasks to sync repositories")
		gen.done = true

		return nil, nil //nolint:nilnil
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
