package sync

import (
	"context"
	"io"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
)

// OnDemand pulls images and referrers from upstream registries on client request.
type OnDemand interface {
	// SyncImage syncs a single image (repo:tag or repo:digest) into local storage.
	// ns, when non-empty, restricts the sync to the upstream registry named by the
	// containerd ?ns= namespace/query parameter (e.g. "docker.io").
	SyncImage(ctx context.Context, repo, reference, ns string) error
	// SyncReferrers syncs referrers for the given subject digest into local storage.
	// ns, when non-empty, restricts the sync to the upstream registry named by the
	// containerd ?ns= namespace/query parameter.
	SyncReferrers(ctx context.Context, repo string, subjectDigestStr string, referenceTypes []string,
		ns string) error
	// ShouldCheckUpstreamManifest reports whether repo:reference still needs an upstream check.
	// ns, when non-empty, restricts the check to services whose upstream registry matches the
	// containerd ?ns= namespace/query parameter. A false result must only short-circuit an
	// unscoped request: the check tracker is keyed by repo:reference and cannot tell which
	// namespaced upstream last validated the local tag.
	ShouldCheckUpstreamManifest(repo, reference, ns string) bool
	// ShouldQueueOnDemandSync reports whether a missing local manifest for repo should
	// return immediately while a background sync copies the image into storage.
	// ns, when non-empty, restricts the check to services whose upstream registry matches the
	// containerd ?ns= namespace/query parameter.
	ShouldQueueOnDemandSync(repo, ns string) bool
	// IsTagFromNamespace reports whether repo:reference's local tag was last committed by a
	// sync scoped to ns (the containerd ?ns= namespace/query parameter). An empty ns always
	// reports true: unscoped requests serve the shared tag regardless of its origin. A tag
	// synced without a namespace is unrecorded and matches none, so a namespaced request
	// treats it as another registry's content.
	IsTagFromNamespace(repo, reference, ns string) bool
	// QueueImage schedules at most one background SyncImage for repo:reference from
	// onDemandInBackground registries that match the repo. The request context is detached.
	// ns, when non-empty, restricts the queued sync to services whose upstream registry matches
	// the containerd ?ns= namespace/query parameter.
	QueueImage(ctx context.Context, repo, reference, ns string)
	// FetchManifestForStream returns repo:reference's manifest straight from upstream and syncs
	// the image in the background. onSynced, if non-nil, runs once that sync commits (e.g. to
	// count a download). If the image is not streamed (e.g. an index, or the stream cap), it waits
	// for a plain sync and returns ErrSyncNotStreamed, wrapping that sync's error if it failed;
	// the caller then serves from storage.
	// ns, when non-empty, restricts the sync to the upstream registry named by the
	// containerd ?ns= namespace/query parameter.
	FetchManifestForStream(ctx context.Context, repo, reference string, ns string,
		onSynced func(manifest.Manifest)) (manifest.Manifest, error)
	// StreamManager returns the shared stream manager, or nil when no registry streams.
	StreamManager() StreamManager
	// IsStreamingEnabledForRepo reports whether any on-demand service streams blobs for repo.
	IsStreamingEnabledForRepo(repo string) bool
}

// StreamManager tracks manifests staged for streaming and their blobs' streams.
type StreamManager interface {
	// ConnectClient attaches a client to blobDigest's stream. The blob must belong to a manifest
	// staged under repo, so access stays scoped to repos the caller may read.
	ConnectClient(repo, blobDigest string, writer io.Writer) (BlobCopier, error)
	// DownloadStreamedBlobs downloads repo:reference's streamed blobs with fetch, for its
	// background sync, and returns each completed blob's temp file by digest, for the sync to link
	// into its layout. If priority is not nil, a blob a client is waiting on is also opened with it,
	// without waiting for fetch's throttle.
	DownloadStreamedBlobs(ctx context.Context, repo, reference string,
		fetch, priority BlobFetcher) map[godigest.Digest]string
	// StoreImageForStreaming stages a manifest and creates a stream per blob the repo lacks. If
	// repo:reference is already staged, that manifest is returned instead; use the returned one,
	// since only its blobs have streams. accept, if non-nil, must accept that existing manifest:
	// a rejected collision is not adopted and returns ErrSyncStagedNamespaceMismatch, leaving the
	// existing entry (and its callbacks) untouched.
	StoreImageForStreaming(repo, reference string, streamManifest *StreamableManifest,
		accept func(*StreamableManifest) bool) (*StreamableManifest, error)
	// StreamingImageManifest returns the manifest staged for repo:reference, if any.
	StreamingImageManifest(repo, reference string) (*StreamableManifest, bool)
	// JoinStreamingImage returns repo:reference's staged manifest if it exists and accept (when
	// non-nil) accepts it, and registers onSynced (if non-nil) to run once its sync commits. The
	// check and the registration are atomic: a rejected manifest gets no callback.
	JoinStreamingImage(repo, reference string, accept func(*StreamableManifest) bool,
		onSynced func(manifest.Manifest)) (*StreamableManifest, bool)
	// RemoveStreamingImage unstages repo:reference after its sync. If synced, its onSynced
	// callbacks run.
	RemoveStreamingImage(repo, reference string, synced bool)
	// HasStreamsForRepo reports whether any manifest staged under repo has blob streams.
	HasStreamsForRepo(repo string) bool
	// CachedBlobInfo returns a staged blob's size and media type before its download starts
	// (scoped to repo like ConnectClient).
	CachedBlobInfo(repo, blobDigest string) (size int64, mediaType string, err error)
}

// BlobFetcher opens a blob at the upstream a staged image was fetched from. The sync passes
// regclient's BlobGet, pinned to its remote repo, so auth, mirrors, throttling and resumed reads
// all stay regclient's.
type BlobFetcher func(ctx context.Context, desc descriptor.Descriptor) (*blob.BReader, error)

// priorityFetch is the out-of-band download of a staged image's blobs, set while its sync downloads
// them (see StreamManager.DownloadStreamedBlobs). ctx is derived from the sync's and cancelled when
// that download returns, so no priority download outlives it.
type priorityFetch struct { //nolint:unused // only used by sync-tagged files
	ctx   context.Context //nolint:containedctx,unused // only used by sync-tagged files
	fetch BlobFetcher     //nolint:unused // only used by sync-tagged files
}

// BlobCopier copies one streamed blob (or a range of it) to one client.
type BlobCopier interface {
	// Copy streams the whole blob, returning when done, when the download fails, or when ctx (the
	// client's request) ends.
	Copy(ctx context.Context) error
	// CopyRange streams bytes [start, end] (inclusive), returning as soon as end has arrived or ctx
	// ends. The caller validates the range first (e.g. via CachedBlobInfo).
	CopyRange(ctx context.Context, start, end int64) error
	// Descriptor waits (bounded) for the download to start, or errors if it never starts, failed,
	// or ctx (the request's) ends first. On error the caller must Close.
	Descriptor(ctx context.Context) (descriptor.Descriptor, error)
	// Close releases the subscription when Copy will never run. Harmless after Copy.
	Close()
}

// StreamableManifest is an image manifest staged for streaming. Indexes are never staged: their
// sync is sparse, so nothing would feed the streams.
type StreamableManifest struct {
	referenceManifest manifest.Manifest
	// source names the registry that supplied this manifest (BaseOnDemand.streamSource). Streams
	// are keyed by it, so clients never get another registry's unverified bytes.
	source string //nolint:unused // only read/written by sync-tagged files (stream_manager.go, on_demand.go)
	// registryHosts identifies the upstream registry that supplied this manifest: the authority
	// (host:port) of that service's configured URLs. It is captured at staging time so a join can
	// validate the manifest against the registry that produced it, even after a config reload has
	// replaced or reordered services.
	registryHosts []string //nolint:unused // only read/written by sync-tagged files
	// onSynced holds every served request's callback, run once the sync commits. Guarded by
	// streamLock.
	onSynced []func(manifest.Manifest) //nolint:unused // only used by sync-tagged files
	// streamKeys are the streams this manifest references: its blobs minus those already local.
	// Set at staging; guarded by streamLock.
	streamKeys map[string]struct{} //nolint:unused // only used by sync-tagged files
	// done is closed when RemoveStreamingImage unstages it, after its onSynced callbacks; synced
	// then reports whether its sync succeeded. Lets a flight that joined it wait for its sync.
	done   chan struct{} //nolint:unused // only used by sync-tagged files
	synced bool          //nolint:unused // only used by sync-tagged files
	// priority is set while this manifest's sync downloads its streams. Guarded by streamLock.
	priority *priorityFetch //nolint:unused // only used by sync-tagged files
}

// NewStreamableManifest wraps an image manifest for staging.
func NewStreamableManifest(mainManifest manifest.Manifest) *StreamableManifest {
	return &StreamableManifest{
		referenceManifest: mainManifest,
		done:              make(chan struct{}),
	}
}

// MatchesNamespace reports whether ns (the containerd ?ns= namespace/query parameter) names the
// upstream registry that supplied this manifest. An empty ns matches every manifest; a manifest
// staged without registry information matches no namespace, so a scoped request never joins it.
func (m *StreamableManifest) MatchesNamespace(nsParam string) bool {
	if nsParam == "" {
		return true
	}

	return registryMatches(m.registryHosts, nsParam)
}

// registryMatches reports whether ns names one of hosts. A host is a registry authority
// (host:port) as configured for an upstream service. Docker Hub aliases compare equal regardless
// of port; every other authority is compared case-insensitively and port-sensitively.
func registryMatches(hosts []string, nsParam string) bool {
	nsNormalized := normalizeRegistryName(nsParam)

	for _, host := range hosts {
		if isDockerHubHost(stripPort(nsParam)) || isDockerHubHost(stripPort(host)) {
			if normalizeRegistryName(host) == nsNormalized {
				return true
			}

			continue
		}

		if strings.EqualFold(host, nsParam) {
			return true
		}
	}

	return false
}

// stripPort returns host without its port, if any.
func stripPort(host string) string {
	host, _, _ = strings.CutLast(host, ":")

	return host
}

// isDockerHubHost reports whether host (port already stripped) is a Docker Hub alias.
func isDockerHubHost(host string) bool {
	switch strings.ToLower(host) {
	case "docker.io", "registry-1.docker.io", "index.docker.io":
		return true
	default:
		return false
	}
}

// normalizeRegistryName strips the port and normalizes Docker Hub aliases so that
// docker.io, registry-1.docker.io and index.docker.io all compare equal.
func normalizeRegistryName(host string) string {
	host = stripPort(host)

	if isDockerHubHost(host) {
		return "docker.io"
	}

	return strings.ToLower(host)
}
