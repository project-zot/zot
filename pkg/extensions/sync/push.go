//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// PushService is the part of the sync service a push generator drives. The push loop reads
// the local store, so the only thing a generator needs from the service is "push this repo".
type PushService interface {
	PushRepo(ctx context.Context, repo string) error
}

// pushDestination is the outbound registry surface the push loop needs. It is an interface so
// the loop can be driven by a test double: the guarantee that a failed referrer fails the push
// is only worth anything if a test can make that failure happen.
type pushDestination interface {
	URL() string
	GetImageReference(repo, reference string) (ref.Ref, error)
	CanSkipImage(ctx context.Context, repo, reference string, digest godigest.Digest) (bool, error)
	CopyImage(ctx context.Context, sourceRef, targetRef ref.Ref) error
	Close(ctx context.Context, imageRef ref.Ref)
}

// PushDestination is one outbound registry. Every destination gets its own regclient because
// a client carries the host config (TLS, certs, credentials) of one host: sharing the pull
// client would mean pushing with the source's transport settings.
type PushDestination struct {
	rc   *regclient.RegClient
	url  string
	host string
	log  log.Logger
}

// NewPushDestination builds a client for one destination URL, reusing the pull-side client
// builder so TLS, certDir, retry and timeout settings behave identically on both directions.
func NewPushDestination(rawURL string, push *syncconf.PushConfig, parent syncconf.RegistryConfig,
	credentials syncconf.CredentialsFile, log log.Logger,
) (*PushDestination, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", zerr.ErrSyncInvalidURL, rawURL, err)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: %s", zerr.ErrSyncInvalidURL, rawURL)
	}

	opts := syncconf.RegistryConfig{
		URLs:          []string{rawURL},
		TLSVerify:     push.TLSVerify,
		CertDir:       push.CertDir,
		SyncTimeout:   parent.SyncTimeout,
		MaxRetries:    parent.MaxRetries,
		RetryDelay:    parent.RetryDelay,
		MaxRetryDelay: parent.MaxRetryDelay,
	}

	client, _, err := newClient(opts, credentials, log)
	if err != nil {
		return nil, err
	}

	return newPushDestinationFromClient(client, parsed, rawURL, log), nil
}

func newPushDestinationFromClient(client *regclient.RegClient, parsed *url.URL, rawURL string,
	log log.Logger,
) *PushDestination {
	return &PushDestination{rc: client, url: rawURL, host: parsed.Host, log: log}
}

// InitPushMode builds one client per destination. None of them shares the service's client:
// that one belongs to the pull source, and a combined entry can have both.
func (service *BaseService) InitPushMode() error {
	push := service.config.Push
	if !push.IsEnabled() {
		return nil
	}

	if len(push.URLs) == 0 {
		return zerr.ErrSyncNoURLsLeft
	}

	for _, rawURL := range push.URLs {
		destination, err := NewPushDestination(rawURL, push, service.config, service.credentials, service.log)
		if err != nil {
			return err
		}

		service.pushTargets = append(service.pushTargets, destination)
	}

	service.log.Info().Int("destinations", len(service.pushTargets)).
		Msg("sync push mode enabled, local content is mirrored to the configured destinations")

	return nil
}

// URL is the destination as configured, for logs and errors.
func (destination *PushDestination) URL() string {
	return destination.url
}

// GetImageReference builds the destination ref for repo and reference. The host comes from
// the configured URL, so a destination written with a scheme or a trailing slash still
// produces the "host/repo:tag" form regclient expects.
func (destination *PushDestination) GetImageReference(repo, reference string) (ref.Ref, error) {
	imageRef, err := ref.New(destination.host + "/" + strings.Trim(repo, "/"))
	if err != nil {
		return ref.Ref{}, err
	}

	if digest, ok := parseReference(reference); ok {
		return imageRef.SetDigest(digest.String()), nil
	}

	return imageRef.SetTag(reference), nil
}

// CanSkipImage reports whether the destination already holds digest under reference. The pull
// path asks the local store the same question through Destination.CanSkipImage; here the
// answer comes from the destination itself, one HEAD per tag.
func (destination *PushDestination) CanSkipImage(ctx context.Context, repo, reference string,
	digest godigest.Digest,
) (bool, error) {
	imageRef, err := destination.GetImageReference(repo, reference)
	if err != nil {
		return false, err
	}

	manifest, err := destination.rc.ManifestHead(ctx, imageRef)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			return false, nil
		}

		return false, err
	}

	defer destination.rc.Close(ctx, imageRef)

	return manifest.GetDescriptor().Digest == digest, nil
}

// CopyImage copies one manifest tree from the staging layout to this destination.
func (destination *PushDestination) CopyImage(ctx context.Context, sourceRef, targetRef ref.Ref) error {
	return destination.rc.ImageCopy(ctx, sourceRef, targetRef)
}

// Close releases the per-reference resources regclient keeps for a copy.
func (destination *PushDestination) Close(ctx context.Context, imageRef ref.Ref) {
	destination.rc.Close(ctx, imageRef)
}

// PushTaskGenerator walks the local stores and emits one task per repository. The pull
// generator asks the upstream catalog; a push has no upstream, so the catalog is
// ImageStore.GetNextRepository, the same walk scrub and GC use.
type PushTaskGenerator struct {
	service   PushService
	stores    []storageTypes.ImageStore
	storeIdx  int
	processed map[string]struct{}
	done      bool
	lock      *sync.Mutex
	log       log.Logger
}

func NewPushTaskGenerator(service PushService, stores []storageTypes.ImageStore, log log.Logger) *PushTaskGenerator {
	return &PushTaskGenerator{
		service:   service,
		stores:    stores,
		processed: make(map[string]struct{}),
		lock:      &sync.Mutex{},
		log:       log,
	}
}

func (gen *PushTaskGenerator) Name() string {
	return "PushGenerator"
}

func (gen *PushTaskGenerator) Next() (scheduler.Task, error) {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	for gen.storeIdx < len(gen.stores) {
		repo, err := gen.stores[gen.storeIdx].GetNextRepository(gen.processed)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}

		if repo == "" {
			gen.storeIdx++

			continue
		}

		gen.processed[repo] = struct{}{}

		return newPushRepoTask(repo, gen.service), nil
	}

	gen.log.Info().Str("component", "sync").Msg("finished generating push tasks for stored repositories")

	gen.done = true

	return nil, nil //nolint:nilnil
}

func (gen *PushTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *PushTaskGenerator) IsReady() bool {
	return true
}

func (gen *PushTaskGenerator) Reset() {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	gen.storeIdx = 0
	gen.processed = make(map[string]struct{})
	gen.done = false
}

type pushRepoTask struct {
	repo    string
	service PushService
}

func newPushRepoTask(repo string, service PushService) *pushRepoTask {
	return &pushRepoTask{repo: repo, service: service}
}

func (task *pushRepoTask) DoWork(ctx context.Context) error {
	return task.service.PushRepo(ctx, task.repo)
}

func (task *pushRepoTask) Name() string {
	return "PushTask"
}

func (task *pushRepoTask) String() string {
	return fmt.Sprintf("{Name: %q, repository: %q}", task.Name(), task.repo)
}

// PushRepo mirrors every selected tag of repo to every configured destination.
func (service *BaseService) PushRepo(ctx context.Context, repo string) error {
	matches := service.contentManager.LocalContentMatches(repo)
	if len(matches) == 0 {
		service.log.Debug().Str("repo", repo).Msg("repo is not selected by the sync content rules, not pushing it")

		return nil
	}

	if len(matches) > 1 {
		// Only the first entry governs tags, platforms and stripPrefix. Say so: the narrower
		// rule silently loses, which is not what a config author expects.
		service.log.Debug().Str("repo", repo).Int("matchedRules", len(matches)).
			Str("appliedPrefix", matches[0].Prefix).
			Msg("more than one content rule matches this repo, the first one applies")
	}

	imageStore := service.storeController.GetImageStore(repo)
	if imageStore == nil {
		return fmt.Errorf("%w: %q", zerr.ErrLocalImgStoreNotFound, repo)
	}

	tags, err := imageStore.GetImageTags(repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) {
			return nil
		}

		return err
	}

	tags, err = service.contentManager.FilterLocalTags(repo, tags)
	if err != nil {
		return err
	}

	for _, tag := range tags {
		if err := service.pushTag(ctx, imageStore, repo, tag); err != nil {
			return err
		}
	}

	return nil
}

// pushTag copies one tag and its referrers. A destination that already holds the tag digest
// still receives referrers it is missing: signatures and SBOMs usually arrive after the image
// they describe, and a delta check on the tag alone would strand them.
func (service *BaseService) pushTag(ctx context.Context, imageStore storageTypes.ImageStore, repo, tag string) error {
	_, digest, mediaType, err := imageStore.GetImageManifest(repo, tag)
	if err != nil {
		return err
	}

	if err := service.rejectUnsupportedRootMedia(repo, tag, mediaType); err != nil {
		return err
	}

	// Ask every destination before staging anything: a fully synced edge costs one HEAD per
	// tag and no local copy.
	targets := make([]pushDestination, 0, len(service.pushTargets))

	for _, destination := range service.pushTargets {
		skip, err := destination.CanSkipImage(ctx, repo, tag, digest)
		if err != nil {
			return fmt.Errorf("checking %s:%s on %s: %w", repo, tag, destination.URL(), err)
		}

		if skip {
			service.log.Debug().Str("repo", repo).Str("tag", tag).Str("destination", destination.URL()).
				Msg("destination already has this digest, skipping push")

			continue
		}

		targets = append(targets, destination)
	}

	referrers, err := service.localReferrers(imageStore, repo, digest)
	if err != nil {
		return err
	}

	if len(targets) == 0 && len(referrers.Manifests) == 0 {
		return nil
	}

	stagingRef, tempStore, err := service.newPushStaging(repo, tag)
	if err != nil {
		return err
	}

	defer service.destination.CleanupImage(stagingRef, repo) //nolint: errcheck

	platforms := service.contentManager.EffectiveLocalPlatforms(repo, service.pushPlatforms())

	if len(targets) > 0 {
		if err := service.materializeTree(ctx, imageStore, tempStore, repo, digest, mediaType, platforms); err != nil {
			return fmt.Errorf("staging %s:%s for push: %w", repo, tag, err)
		}
	}

	for _, destination := range targets {
		// The destination carries the tag, not just the digest: a mirror that only stores
		// untagged manifests is invisible to every consumer of the destination.
		targetRef, err := destination.GetImageReference(repo, tag)
		if err != nil {
			return err
		}

		sourceRef := stagingRef.SetDigest(digest.String())

		if err := destination.CopyImage(ctx, sourceRef, targetRef); err != nil {
			return fmt.Errorf("pushing %s:%s to %s: %w", repo, tag, destination.URL(), err)
		}

		destination.Close(ctx, targetRef)

		service.log.Info().Str("repo", repo).Str("tag", tag).Str("destination", destination.URL()).
			Msg("pushed image to destination")
	}

	// Every destination, not only the ones that just received the image: a referrer can be
	// new on one destination and old on another.
	for _, destination := range service.pushTargets {
		err := service.pushReferrers(ctx, imageStore, tempStore, stagingRef, repo, destination, digest, platforms)
		if err != nil {
			// A push without its signatures is worse than a failed push: the destination would
			// serve an image whose signature chain silently stops at the last successful run.
			return fmt.Errorf("pushing referrers of %s:%s to %s: %w", repo, tag, destination.URL(), err)
		}
	}

	return nil
}

// localReferrers returns the referrers of subject from the local store. A repository that was
// never signed has none, which is not an error.
func (service *BaseService) localReferrers(imageStore storageTypes.ImageStore, repo string,
	subject godigest.Digest,
) (ispec.Index, error) {
	referrers, err := imageStore.GetReferrers(repo, subject, nil)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestNotFound) || errors.Is(err, zerr.ErrRepoNotFound) {
			return ispec.Index{}, nil
		}

		return ispec.Index{}, err
	}

	return referrers, nil
}

// pushPlatforms is the registry-level platform allowlist for push. Content-level platforms are
// applied on top by EffectiveLocalPlatforms.
func (service *BaseService) pushPlatforms() []string {
	if service.config.Push == nil {
		return nil
	}

	return service.config.Push.Platforms
}
