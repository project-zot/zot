//go:build sync

package sync

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/scheme/reg"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"
	"golang.org/x/sync/singleflight"

	zerr "zotregistry.dev/zot/v2/errors"
	zconfig "zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cluster"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageCommon "zotregistry.dev/zot/v2/pkg/storage/common"
)

const (
	defaultExpireMinutes = 30 * time.Minute
)

// copyStrategy selects how a single ensure copies remote content into the temp layout.
type copyStrategy int

const (
	// copySparseIndex stores indexes/lists as the root manifest only (no child recursion).
	// Image manifests still copy config + layers via a full ImageCopy.
	copySparseIndex copyStrategy = iota
	// copyDigestComplete copies an image manifest with config + layers (full ImageCopy).
	copyDigestComplete
)

// syncImageOptions configures a leaf syncImage/ensureImage call.
type syncImageOptions struct {
	WithReferrers bool
	Strategy      copyStrategy
	// SkipOnlySigned skips the OnlySigned gate. Used for digest ensures of children
	// under an index whose tag was already verified (periodic), and for on-demand
	// digest pulls (content-addressed follow-ups; see onlySigned docs).
	SkipOnlySigned bool
	// TagContentDigest, when set, is the upstream content digest already resolved for a
	// mutable tag. syncImage uses it instead of re-resolving the tag so parent copy
	// and child expansion stay on the same index.
	TagContentDigest godigest.Digest
	// MediaType, when set with TagContentDigest, skips HeadManifest in syncImage.
	MediaType string
}

type BaseService struct {
	config           syncconf.RegistryConfig
	credentials      syncconf.CredentialsFile
	credentialHelper CredentialHelper
	remote           Remote
	destination      Destination
	clusterConfig    *zconfig.ClusterConfig
	contentManager   ContentManager
	storeController  storage.StoreController
	metaDB           mTypes.MetaDB
	repositories     []string
	rc               *regclient.RegClient
	hosts            []config.Host
	tagsCache        *tagsCache
	checkTracker     *manifestCheckTracker
	// imageFlight dedupes concurrent ensures of the same
	// localRepo+remoteRepo+reference+opts (shared by on-demand SyncImage and periodic
	// SyncRepo index/child ensures).
	imageFlight   singleflight.Group
	streamManager StreamManager

	clientLock sync.RWMutex
	log        log.Logger
}

func New(
	config syncconf.RegistryConfig,
	credentialsFilepath string,
	clusterConfig *zconfig.ClusterConfig,
	tmpDir string,
	storeController storage.StoreController,
	streamManager StreamManager,
	metadb mTypes.MetaDB,
	log log.Logger,
) (*BaseService, error) {
	service := &BaseService{}

	service.config = config
	service.log = log
	service.metaDB = metadb
	service.contentManager = NewContentManager(config.Content, log)
	service.storeController = storeController
	service.streamManager = streamManager
	service.tagsCache = newTagsCache(defaultExpireMinutes)

	if config.ManifestCheckInterval > 0 {
		service.checkTracker = newManifestCheckTracker(config.ManifestCheckInterval)
	}

	var err error

	var credentialsFile syncconf.CredentialsFile

	if service.config.CredentialHelper == "" && credentialsFilepath != "" {
		// Only load credentials from file if CredentialHelper is not set
		log.Info().Msgf("using file-based credentials because CredentialHelper is not set")

		credentialsFile, err = getFileCredentials(credentialsFilepath)
		if err != nil {
			log.Error().
				Str("errortype", common.TypeOf(err)).
				Str("path", credentialsFilepath).
				Err(err).
				Msg("couldn't get registry credentials from configured path")
		}
		service.credentialHelper = nil
		service.credentials = credentialsFile
	} else if service.config.CredentialHelper != "" {
		log.Info().Msgf("using credentials helper, because CredentialHelper is set to %s", service.config.CredentialHelper)

		switch service.config.CredentialHelper {
		case "ecr":
			// Logic to fetch credentials for ECR
			log.Info().Msg("fetch the credentials using AWS ECR Auth Token.")
			service.credentialHelper = NewECRCredentialHelper(log, GetECRCredentials)

			creds, err := service.credentialHelper.GetCredentials(service.config.URLs)
			if err != nil {
				log.Error().Err(err).Msg("failed to retrieve credentials using ECR credentials helper.")
			}
			service.credentials = creds
		case "gcp":
			// Logic to fetch an access token from the Google application default credentials.
			log.Info().Msg("fetch the credentials using Google application default credentials.")
			service.credentialHelper = NewGCPCredentialHelper(log, GetGCPTokenSource)

			creds, err := service.credentialHelper.GetCredentials(service.config.URLs)
			if err != nil {
				log.Error().Err(err).Msg("failed to retrieve credentials using GCP credentials helper.")
			}
			service.credentials = creds
		case "oauth2":
			// Logic to fetch credentials by exchanging a JWT assertion for an access token.
			log.Info().Msg("fetch the credentials using OAuth2 JWT assertion exchange.")

			oauth2Config, err := syncconf.OAuth2HelperConfigFromMap(service.config.Oauth2CredentialHelper)
			if err != nil {
				log.Error().Err(err).Msg("failed to parse the OAuth2 credentials helper config.")
				service.config.CredentialHelper = ""

				break
			}

			credentialHelper, err := NewOAuth2CredentialHelper(log, oauth2Config)
			if err != nil {
				log.Error().Err(err).Msg("failed to create OAuth2 credentials helper.")
				service.config.CredentialHelper = ""

				break
			}

			service.credentialHelper = credentialHelper

			creds, err := service.credentialHelper.GetCredentials(service.config.URLs)
			if err != nil {
				log.Error().Err(err).Msg("failed to retrieve credentials using OAuth2 credentials helper.")
			}
			service.credentials = creds
		default:
			log.Warn().Msgf("unsupported CredentialHelper: %s", service.config.CredentialHelper)
			service.config.CredentialHelper = ""
		}
	}

	// load the cluster config into the object
	// can be nil if the user did not configure cluster config
	service.clusterConfig = clusterConfig

	service.contentManager = NewContentManager(config.Content, log)

	if len(tmpDir) == 0 {
		// first it will sync in tmpDir then it will move everything into local ImageStore
		service.destination = NewDestinationRegistry(storeController, storeController, metadb, log)
	} else {
		// first it will sync under /rootDir/reponame/.sync/ then it will move everything into local ImageStore
		service.destination = NewDestinationRegistry(
			storeController,
			storage.StoreController{
				DefaultStore: getImageStore(tmpDir, log),
			},
			metadb,
			log,
		)
	}

	service.storeController = storeController

	err = service.init()
	if err != nil {
		log.Err(err).Msg("failed to initialize sync client")

		return nil, err
	}

	return service, nil
}

func (service *BaseService) init() error {
	service.clientLock.Lock()
	defer service.clientLock.Unlock()

	return service.initClient()
}

// initClient rebuilds the registry client from the current credentials.
// Caller must hold clientLock for writing.
func (service *BaseService) initClient() error {
	client, hosts, err := newClient(service.config, service.credentials, service.log)
	if err != nil {
		service.log.Err(err).Msg("failed to create registry client")

		return err
	}

	service.rc = client
	service.hosts = hosts

	service.remote = NewRemoteRegistry(
		service.rc,
		service.hosts,
		service.log,
	)

	return nil
}

// refreshRegistryTemporaryCredentials refreshes the temporary credentials for the registry if necessary.
// It checks whether a CredentialHelper is configured and if the current credentials have expired.
// If the credentials are expired, it attempts to refresh them and updates the service configuration.
func (service *BaseService) refreshRegistryTemporaryCredentials() error {
	// Exit early if no CredentialHelper is configured.
	if service.config.CredentialHelper == "" || service.credentialHelper == nil {
		return nil
	}

	// Fast path: skip the write lock and client reinit when nothing has expired.
	service.clientLock.RLock()
	needsRefresh := false

	for _, host := range service.hosts {
		if !service.credentialHelper.AreCredentialsValid(host.Hostname) {
			needsRefresh = true

			break
		}
	}

	service.clientLock.RUnlock()

	if !needsRefresh {
		return nil
	}

	service.clientLock.Lock()
	defer service.clientLock.Unlock()

	credentialsUpdated := false

	for _, host := range service.hosts {
		// Re-check under the write lock: another refresher may have won the race.
		if service.credentialHelper.AreCredentialsValid(host.Hostname) {
			continue
		}

		// Attempt to refresh the credentials using the CredentialHelper.
		credentials, err := service.credentialHelper.RefreshCredentials(host.Hostname)
		if err != nil {
			service.log.Error().
				Err(err).
				Str("url", host.Hostname).
				Msg("failed to refresh the credentials")

			continue
		}

		service.log.Info().
			Str("url", host.Hostname).
			Msg("refreshing the upstream remote registry credentials")

		// Update the service's credentials map with the new set of credentials.
		service.credentials[host.Hostname] = credentials
		credentialsUpdated = true
	}

	if !credentialsUpdated {
		return nil
	}

	// Reinitialize regclient with new credentials
	return service.initClient()
}

// remoteHostName returns the primary remote hostname under clientLock so callers do not
// race with credential refresh replacing service.remote in initClient.
func (service *BaseService) remoteHostName() string {
	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	return service.remote.GetHostName()
}

func (service *BaseService) CanRetryOnError() bool {
	if service.config.MaxRetries != nil && *service.config.MaxRetries > 0 {
		return true
	}

	return false
}

// IsStreamingForRepo reports whether streaming is enabled for the given local repo on this
// service. Streaming is enabled if the registry config has Stream set to true and the repo
// matches the content config (or no content filter is configured, in which case all repos match).
func (service *BaseService) IsStreamingForRepo(repo string) bool {
	if !service.config.IsStreamEnabled() {
		return false
	}

	if len(service.config.Content) == 0 {
		return true
	}

	return service.contentManager.GetContentByLocalRepo(repo) != nil
}

// ShouldCheckUpstream reports whether an upstream manifest check is due for repo:reference.
// It is always true when manifestCheckInterval is not configured, which keeps the default
// behaviour of validating every on-demand request against upstream.
func (service *BaseService) ShouldCheckUpstream(repo, reference string) bool {
	if service.checkTracker == nil {
		return true
	}

	return service.checkTracker.ShouldCheckUpstream(repo, reference)
}

// markUpstreamChecked records a successful upstream check, so that subsequent on-demand
// requests for the same reference can be served locally until the interval elapses.
func (service *BaseService) markUpstreamChecked(repo, reference string) {
	if service.checkTracker == nil {
		return
	}

	service.checkTracker.MarkChecked(repo, reference)
}

func (service *BaseService) GetSyncTimeout() time.Duration {
	if service.config.SyncTimeout == 0 {
		return syncConstants.DefaultSyncTimeout
	}

	return service.config.SyncTimeout
}

func (service *BaseService) getNextRepoFromCatalog(lastRepo string) string {
	var found bool

	var nextRepo string

	for _, repo := range service.repositories {
		if lastRepo == "" {
			nextRepo = repo

			break
		}

		if repo == lastRepo {
			found = true

			continue
		}

		if found {
			nextRepo = repo

			break
		}
	}

	return nextRepo
}

func (service *BaseService) GetNextRepo(lastRepo string) (string, error) {
	var err error

	/* Refresh before taking the read lock: a refresh reinitializes the client under the
	write lock, which a held read lock would deadlock against. */
	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	if len(service.repositories) == 0 {
		service.clientLock.RLock()
		service.repositories, err = service.remote.GetRepositories(context.Background())
		service.clientLock.RUnlock()

		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("remote registry", service.remoteHostName()).
				Err(err).Msg("error while getting repositories from remote registry")

			return "", err
		}
	}

	var matches bool

	for !matches {
		lastRepo = service.getNextRepoFromCatalog(lastRepo)
		if lastRepo == "" {
			break
		}

		if service.clusterConfig != nil {
			targetIdx, targetMember := cluster.ComputeTargetMember(
				service.clusterConfig.HashKey, service.clusterConfig.Members, lastRepo)

			// if the target index does not match with the local socket index,
			// then the local instance is not responsible for syncing the repo and should skip the sync
			if targetIdx != service.clusterConfig.Proxy.LocalMemberClusterSocketIndex {
				service.log.Debug().
					Str(constants.RepositoryLogKey, lastRepo).
					Str("targetMemberIndex", strconv.FormatUint(targetIdx, 10)).
					Str("targetMember", targetMember).
					Msg("skipping sync of repo not managed by local instance")

				continue
			}
		}

		matches = service.contentManager.MatchesContent(lastRepo)
	}

	return lastRepo, nil
}

// FetchManifest fetches repo:reference's manifest (and, for a multi-arch reference, each
// platform's child manifest) directly from upstream, without syncing anything into local
// storage. Used by on-demand streaming, where the manifest must reach the client immediately
// while the real sync into local storage happens separately, in the background.
//
// Applies the same content-filter and OnlySigned gates SyncImage applies, and in the same order
// relative to the fetch, so a manifest this rejects would also have been rejected by a plain
// on-demand sync - streaming must never hand a client something the non-streaming path would
// have refused to serve.
func (service *BaseService) FetchManifest(ctx context.Context, repo, reference string) (
	manifest.Manifest, []manifest.Manifest, error,
) {
	remoteRepo := repo

	remoteURL := service.remote.GetHostName()

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
				Msg("will not sync image, filtered out by content")

			return nil, nil, zerr.ErrSyncImageFilteredOut
		}
	}

	service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
		Msg("sync: fetching manifest for stream")

	/* Refresh before taking the read lock: a refresh reinitializes the client under the
	write lock, which a held read lock would deadlock against - same pattern as SyncReferrers. */
	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	remoteImageRef, err := service.remote.GetImageReference(remoteRepo, reference)
	if err != nil {
		return nil, nil, err
	}

	fetchedManifest, err := service.rc.ManifestGet(ctx, remoteImageRef)
	if err != nil {
		return nil, nil, err
	}

	if err := service.rejectUnsupportedRootMedia(remoteRepo, reference,
		fetchedManifest.GetDescriptor().MediaType); err != nil {
		return nil, nil, err
	}

	if err := service.enforceOnlySigned(ctx, remoteRepo, reference, remoteImageRef,
		fetchedManifest.GetDescriptor().Digest, nil, false); err != nil {
		return nil, nil, err
	}

	var childManifests []manifest.Manifest

	// A multi-arch reference (an index) has no config/layers of its own to stream - each
	// platform's own manifest underneath it does, so those need fetching (and later, staging for
	// streaming) individually.
	if fetchedManifest.IsList() {
		indexer, ok := fetchedManifest.(manifest.Indexer)
		if !ok {
			service.log.Error().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
				Msg("failed to cast manifest to index")

			return nil, nil, zerr.ErrBadManifest
		}

		childDescriptors, err := indexer.GetManifestList()
		if err != nil {
			service.log.Error().Err(err).Str("remote", remoteURL).Str("repo", repo).
				Str("reference", reference).Msg("failed to get manifest list")

			return nil, nil, zerr.ErrBadManifest
		}

		// Fetched sequentially, one upstream round trip per platform - on a many-platform index
		// this adds up before the manifest is returned to the streaming caller, working against
		// the "hand the client the manifest immediately" goal this function otherwise serves.
		for _, childDesc := range childDescriptors {
			childRef, err := service.remote.GetImageReference(remoteRepo, childDesc.Digest.String())
			if err != nil {
				return nil, nil, err
			}

			childManifest, err := service.rc.ManifestGet(ctx, childRef)
			if err != nil {
				service.log.Error().Err(err).Str("remote", remoteURL).Str("repo", repo).
					Str("reference", reference).Str("childDigest", childDesc.Digest.String()).
					Msg("failed to fetch child manifest")

				return nil, nil, err
			}

			childManifests = append(childManifests, childManifest)
		}
	}

	service.markUpstreamChecked(repo, reference)

	return fetchedManifest, childManifests, nil
}

// SyncImage on demand.
func (service *BaseService) SyncImage(ctx context.Context, repo, reference string) error {
	remoteRepo := repo

	// Content rules are local config — apply them before credential refresh or upstream I/O.
	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", service.remoteHostName()).Str("repo", repo).Str("reference", reference).
				Msg("will not sync image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	/* Refresh before taking the read lock: a refresh reinitializes the client under the
	write lock, which a held read lock would deadlock against. */
	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	service.log.Info().Str("remote", service.remoteHostName()).Str("repo", repo).Str("reference", reference).
		Msg("sync: syncing image")

	opts := syncImageOptions{
		WithReferrers: false,
		// Always sparse for on-demand (any tag/digest): indexes copy root only;
		// image manifests still get config+layers via full ImageCopy.
		Strategy: copySparseIndex,
	}

	// Multi-arch signatures cover the index, not each platform child. Digest pulls skip
	// OnlySigned so tag→digest client flows work; tags still enforce signatures.
	if _, parseErr := godigest.Parse(reference); parseErr == nil {
		opts.SkipOnlySigned = true
	}

	if err := service.ensureImage(ctx, repo, remoteRepo, reference, nil, opts); err != nil {
		return err
	}

	service.markUpstreamChecked(repo, reference)

	return nil
}

// SyncImageAtDigest is SyncImage, except the remote fetch is pinned to digest instead of being
// resolved fresh from tag - see PinnedSyncer's doc comment for why a caller would want that. The
// local commit is still keyed by tag, exactly as SyncImage does.
func (service *BaseService) SyncImageAtDigest(ctx context.Context, repo, tag string, digest godigest.Digest) error {
	remoteRepo := repo

	// Content rules are local config — apply them before credential refresh or upstream I/O.
	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", service.remoteHostName()).Str("repo", repo).Str("reference", tag).
				Msg("will not sync image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	/* Refresh before taking the read lock: a refresh reinitializes the client under the
	write lock, which a held read lock would deadlock against. */
	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	service.log.Info().Str("remote", service.remoteHostName()).Str("repo", repo).Str("reference", tag).
		Str("digest", digest.String()).Msg("sync: syncing image pinned to digest")

	opts := syncImageOptions{
		WithReferrers: false,
		// Always sparse for on-demand (any tag/digest): indexes copy root only;
		// image manifests still get config+layers via full ImageCopy.
		Strategy:         copySparseIndex,
		TagContentDigest: digest,
	}

	// Multi-arch signatures cover the index, not each platform child. Digest pulls skip
	// OnlySigned so tag→digest client flows work; tags still enforce signatures.
	if _, parseErr := godigest.Parse(tag); parseErr == nil {
		opts.SkipOnlySigned = true
	}

	if err := service.ensureImage(ctx, repo, remoteRepo, tag, nil, opts); err != nil {
		return err
	}

	service.markUpstreamChecked(repo, tag)

	return nil
}

func (service *BaseService) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	remoteRepo := repo

	// Content rules are local config — apply them before credential refresh or upstream I/O.
	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", service.remoteHostName()).Str("repository", repo).
				Str("subject", subjectDigestStr).Interface("reference types", referenceTypes).
				Msg("will not sync reference for image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	/* Refresh before taking the read lock: a refresh reinitializes the client under the
	write lock, which a held read lock would deadlock against. */
	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	service.log.Info().Str("remote", service.remoteHostName()).Str("repository", repo).Str("subject", subjectDigestStr).
		Interface("reference types", referenceTypes).Msg("syncing reference for image")

	var tags []string
	if service.config.ShouldSyncLegacyCosignTags() {
		var err error
		tags, err = service.getTags(ctx, remoteRepo, false)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
				Err(err).Msg("error while getting tags for repo")

			return err
		}
	}

	localImageRef, err := service.destination.GetImageReference(repo, subjectDigestStr)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", repo).Str("reference", subjectDigestStr).Msg("failed to get a local image reference")

		return err
	}

	err = func() error {
		service.clientLock.RLock()
		defer service.clientLock.RUnlock()

		remoteImageRef, err := service.remote.GetImageReference(remoteRepo, subjectDigestStr)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repository", remoteRepo).Str("reference", subjectDigestStr).Msg("couldn't get a remote image reference")

			return err
		}

		if err := service.syncReferrers(ctx, tags, repo, remoteRepo, localImageRef, remoteImageRef, false); err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repo", repo).Str("reference", subjectDigestStr).Msg("failed to sync referrers")

			return err
		}

		return nil
	}()
	if err != nil {
		return err
	}

	// Commit outside clientLock so credential refresh is not blocked on local I/O.
	err = service.destination.CommitAll(repo, localImageRef)
	if err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
			Err(err).Msg("failed to commit image")

		return err
	}

	return nil
}

// SyncRepo syncs repo periodically.
func (service *BaseService) SyncRepo(ctx context.Context, repo string) error {
	/* Refresh before taking the read lock: a refresh reinitializes the client under the
	write lock, which a held read lock would deadlock against. */
	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	service.log.Info().Str("repo", repo).Str("registry", service.remoteHostName()).
		Msg("sync: syncing repo")

	var err error

	var tags []string

	tags, err = service.getTags(ctx, repo, true)
	if err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
			Err(err).Msg("error while getting tags for repo")

		return err
	}

	// filter tags
	tags, err = service.contentManager.FilterTags(repo, tags)
	if err != nil {
		return err
	}

	service.log.Info().Str("repo", repo).Msgf("sync: syncing tags %v", tags)

	// apply content.destination rule
	localRepo := service.contentManager.GetRepoDestination(repo)

	for _, tag := range tags {
		if common.IsContextDone(ctx) {
			return ctx.Err()
		}

		// skip referrers tags and cosign tags here; they are synced via syncReferrers in syncImage.
		if common.IsCosignTag(tag) || common.IsReferrersTag(tag) {
			continue
		}

		// Resolve the mutable tag once so parent copy and child expansion use the same
		// index digest even if the upstream tag moves mid-sync. Pass media type through
		// so syncImage does not HeadManifest again.
		service.clientLock.RLock()
		tagContentDigest, mediaType, err := service.remote.HeadManifest(ctx, repo, tag)
		service.clientLock.RUnlock()

		if err != nil {
			service.log.Error().Err(err).Str("repository", repo).Str("reference", tag).
				Msg("failed to get upstream image manifest details")

			if isSkippableSyncImageErr(err) || isUnresolvedRemoteManifestErr(err) {
				continue
			}

			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
				Str("tag", tag).Err(err).Msg("error while resolving tag for periodic sync")

			return err
		}

		// Sparse index (or single image) first, then ensure allowlisted / all child digests.
		err = service.ensureImage(ctx, localRepo, repo, tag, tags, syncImageOptions{
			WithReferrers:    true,
			Strategy:         copySparseIndex,
			TagContentDigest: tagContentDigest,
			MediaType:        mediaType,
		})
		if err != nil {
			if isSkippableSyncImageErr(err) {
				continue
			}

			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
				Err(err).Msg("error while syncing tags for repo")

			return err
		}

		// Child expansion is only for indexes/lists. Single-arch manifests are already
		// fully copied above; skipping avoids a redundant GetManifestList ManifestGet.
		if !compat.IsImageIndexMediaType(mediaType) {
			service.markUpstreamChecked(localRepo, tag)

			continue
		}

		children, err := expandIndexChildren(tagContentDigest.String(), func(ref string) ([]childToSync, error) {
			return service.filterChildrenToSync(ctx, repo, ref)
		})
		if err != nil {
			if isSkippableSyncImageErr(err) {
				continue
			}

			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("tag", tag).
				Err(err).Msg("error while listing platform children for periodic sync")

			return err
		}

		for _, child := range children {
			if common.IsContextDone(ctx) {
				return ctx.Err()
			}

			// Parent tag ensure above already enforced OnlySigned on the index/image.
			// Pass digest + mediaType from the parent descriptor so syncImage skips
			// a redundant HeadManifestRef per selected child.
			err = service.ensureImage(ctx, localRepo, repo, child.digest, tags, child.ensureOpts())
			if err != nil {
				if isSkippableSyncImageErr(err) {
					continue
				}

				service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
					Str("tag", tag).Str("child", child.digest).
					Err(err).Msg("error while syncing platform child for repo")

				return err
			}
		}

		// periodic sync just validated this tag against upstream, so on-demand requests
		// arriving right after do not need to check it again.
		service.markUpstreamChecked(localRepo, tag)
	}

	service.log.Info().Str("repo", repo).Msg("sync: finished syncing repo")

	return nil
}

// isSkippableSyncImageErr reports whether err should not fail periodic SyncRepo
// (skip tag / continue) and should not spawn on-demand background retries
// (try the next configured registry instead).
func isSkippableSyncImageErr(err error) bool {
	return errors.Is(err, zerr.ErrSyncImageNotSigned) ||
		errors.Is(err, zerr.ErrSyncDockerCompatRequired) ||
		errors.Is(err, zerr.ErrUnauthorizedAccess) ||
		errors.Is(err, zerr.ErrMediaTypeNotSupported) ||
		errors.Is(err, zerr.ErrManifestNotFound) ||
		errors.Is(err, zerr.ErrRepoNotFound) ||
		errors.Is(err, zerr.ErrSyncImageFilteredOut)
}

type childToSync struct {
	digest    string
	mediaType string
	strategy  copyStrategy
}

// ensureOpts builds syncImageOptions for a periodic child ensure: digest and mediaType
// are already known from the parent descriptor, and OnlySigned was checked on the tag.
func (c childToSync) ensureOpts() syncImageOptions {
	return syncImageOptions{
		Strategy:         c.strategy,
		SkipOnlySigned:   true,
		TagContentDigest: godigest.Digest(c.digest),
		MediaType:        c.mediaType,
	}
}

// expandIndexChildren walks selected children breadth-first. getChildren lists one level
// (filterChildrenToSync in production). Nested index children are enqueued for further
// expansion; image manifests are leaves. Missing nested indexes are skipped so sibling
// children still sync; errors at the root reference still fail the walk.
func expandIndexChildren(root string, getChildren func(ref string) ([]childToSync, error),
) ([]childToSync, error) {
	seen := make(map[string]struct{})
	out := make([]childToSync, 0)
	queue := []string{root}

	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]

		children, err := getChildren(ref)
		if err != nil {
			if ref != root && isUnresolvedRemoteManifestErr(err) {
				continue
			}

			return nil, err
		}

		for _, child := range children {
			if _, ok := seen[child.digest]; ok {
				continue
			}

			seen[child.digest] = struct{}{}
			out = append(out, child)

			if child.strategy == copySparseIndex {
				queue = append(queue, child.digest)
			}
		}
	}

	return out, nil
}

// isUnresolvedRemoteManifestErr reports missing remote content after Remote helpers
// have mapped regclient errors to zot errors (see mapRegclientManifestErr).
func isUnresolvedRemoteManifestErr(err error) bool {
	return errors.Is(err, zerr.ErrManifestNotFound) ||
		errors.Is(err, zerr.ErrBlobNotFound) ||
		errors.Is(err, zerr.ErrRepoNotFound)
}

// filterChildrenToSync returns one level of index children to materialize for periodic sync.
// Effective allowlist is content[].platforms if set for remoteRepo, else config.Platforms;
// empty means all children. Non-list images yield no children (already fully copied by
// copySparseIndex). Nested indexes use copySparseIndex; image manifests use copyDigestComplete.
func (service *BaseService) filterChildrenToSync(ctx context.Context, remoteRepo, reference string,
) ([]childToSync, error) {
	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	descriptors, err := service.remote.GetManifestList(ctx, remoteRepo, reference)
	if err != nil {
		return nil, err
	}

	if len(descriptors) == 0 {
		return nil, nil
	}

	allowlist := service.contentManager.EffectivePlatforms(remoteRepo, service.config.Platforms)
	children := make([]childToSync, 0, len(descriptors))

	for _, desc := range descriptors {
		include, strategy, err := includeChildForPlatformFilter(desc, allowlist)
		if err != nil {
			return nil, err
		}

		if !include {
			service.log.Debug().Str("repo", remoteRepo).Str("reference", reference).
				Str("digest", desc.Digest.String()).Interface("platform", desc.Platform).
				Msg("periodic sync: skipping child platform not in allowlist")

			continue
		}

		children = append(children, childToSync{
			digest:    desc.Digest.String(),
			mediaType: desc.MediaType,
			strategy:  strategy,
		})
	}

	return children, nil
}

// includeChildForPlatformFilter decides whether a list child should be materialized /
// traversed under the periodic platforms allowlist. Platform-less nested indexes are
// always included so allowlisted leaves beneath them can be discovered.
func includeChildForPlatformFilter(desc descriptor.Descriptor, allowlist []string,
) (bool, copyStrategy, error) {
	strategy := copyStrategyForDescriptor(desc)
	isNestedList := strategy == copySparseIndex
	platformLess := desc.Platform == nil || desc.Platform.OS == ""

	if isNestedList && platformLess {
		return true, strategy, nil
	}

	match, err := descriptorMatchesPlatforms(desc.Platform, allowlist)
	if err != nil {
		return false, strategy, err
	}

	return match, strategy, nil
}

func copyStrategyForDescriptor(desc descriptor.Descriptor) copyStrategy {
	switch desc.MediaType {
	case mediatype.OCI1ManifestList, mediatype.Docker2ManifestList:
		return copySparseIndex
	default:
		return copyDigestComplete
	}
}

// descriptorMatchesPlatforms reports whether a descriptor's platform is included in allowlist.
// Empty allowlist means all platforms. Matches regclient ImageWithPlatforms empty-OS rules.
func descriptorMatchesPlatforms(target *platform.Platform, allowlist []string) (bool, error) {
	if len(allowlist) == 0 {
		return true, nil
	}

	if target == nil || target.OS == "" {
		return slices.Contains(allowlist, ""), nil
	}

	for _, entry := range allowlist {
		if entry == "" {
			continue
		}

		plat, err := platform.Parse(entry)
		if err != nil {
			return false, err
		}

		if platform.Match(*target, plat) {
			return true, nil
		}
	}

	return false, nil
}

func (service *BaseService) syncRef(ctx context.Context, localRepo string, remoteImageRef, localImageRef ref.Ref,
	remoteDigest godigest.Digest, blobDigests []godigest.Digest, mediaType string, strategy copyStrategy,
) error {
	var reference string

	var skipImage bool

	var err error

	// Prefer the local reference (tag) for CanSkip so digest-pinned remotes still
	// check the destination tag the caller is committing.
	switch {
	case localImageRef.Tag != "":
		reference = localImageRef.Tag
	case remoteImageRef.Tag != "":
		reference = remoteImageRef.Tag
	case localImageRef.Digest != "":
		reference = localImageRef.Digest
	default:
		reference = remoteImageRef.Digest
	}

	copyOpts := []regclient.ImageOpts{}

	if service.config.IsStreamEnabled() {
		if service.streamManager == nil {
			return zerr.ErrStreamManagerNotInitialized
		}

		// Only install the hook when THIS repo:reference was actually staged for streaming -
		// not merely because this registry has streaming enabled. Without this check, the
		// maxConcurrentStreams fallback path (StoreImageForStreaming rolls back, then calls the
		// ordinary SyncImage on the same stream-enabled registry) would still install the hook;
		// StreamingBlobReader would then find no activeStreams entry for any of this image's
		// blobs and return ErrBlobReaderMissing, failing the very sync that fallback exists to
		// let succeed.
		if _, staged := service.streamManager.StreamingImageManifest(localRepo, reference); staged {
			service.log.Debug().Str("repo", localRepo).Str("reference", reference).
				Msg("streaming is enabled. Enabling reader hook")
			copyOpts = append(copyOpts, regclient.ImageWithBlobReaderHook(service.streamManager.StreamingBlobReader))
		}
	}

	// check if image is already synced
	skipImage, err = service.destination.CanSkipImage(localRepo, reference, remoteDigest)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", localRepo).Str("reference", reference).
			Msg("couldn't check if the local image can be skipped")
	}

	if !skipImage {
		if seeded := service.preseedLocalBlobs(ctx, localRepo, localImageRef, blobDigests); seeded > 0 {
			service.log.Debug().Str("repo", localRepo).Str("reference", reference).
				Int("seededBlobs", seeded).Msg("reused blobs already present in local storage")
		}

		service.log.Info().Str("remote image", remoteImageRef.CommonName()).
			Str("local image", fmt.Sprintf("%s:%s", localRepo, reference)).Msg("syncing image")

		if strategy == copySparseIndex && compat.IsImageIndexMediaType(mediaType) {
			// Explicit index-only copy: never recurse into children
			err = service.copySparseIndexManifest(ctx, remoteImageRef, localImageRef)
		} else {
			// Image manifests (and copyDigestComplete): full config + layers.
			err = service.rc.ImageCopy(ctx, remoteImageRef, localImageRef, copyOpts...)
		}

		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("remote image", remoteImageRef.CommonName()).
				Str("local image", fmt.Sprintf("%s:%s", localRepo, reference)).Msg("failed to sync image")

			// Map so missing digests stay skippable when HeadManifest was skipped
			// (periodic children carry digest+mediaType from the parent descriptor).
			return mapRegclientManifestErr(err)
		}

		return nil
	}

	service.log.Info().Str("remote image", remoteImageRef.CommonName()).
		Str("local image", fmt.Sprintf("%s:%s", localRepo, reference)).
		Msg("skipping image because it's already synced")

	return nil
}

// copySparseIndexManifest writes only the remote index/list manifest into the local
// temp layout. Children are not fetched; later ensures materialize selected digests.
func (service *BaseService) copySparseIndexManifest(ctx context.Context, remoteImageRef, localImageRef ref.Ref,
) error {
	man, err := service.rc.ManifestGet(ctx, remoteImageRef)
	if err != nil {
		return err
	}

	return service.rc.ManifestPut(ctx, localImageRef, man)
}

// ensureImage runs syncImage once per localRepo+remoteRepo+reference+behavior-affecting
// opts (shared singleflight). remoteRepo is part of the key so destination/stripPrefix
// remaps of distinct upstreams to the same local name do not share a flight.
func (service *BaseService) ensureImage(ctx context.Context, localRepo, remoteRepo, reference string,
	repoTags []string, opts syncImageOptions,
) error {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%t\x00%t\x00%d\x00%s",
		localRepo, remoteRepo, reference, opts.WithReferrers, opts.SkipOnlySigned, opts.Strategy,
		opts.TagContentDigest.String())

	_, err, _ := service.imageFlight.Do(key, func() (any, error) {
		return nil, service.syncImage(ctx, localRepo, remoteRepo, reference, repoTags, opts)
	})

	return err
}

// rejectUnsupportedRootMedia rejects roots that sync cannot store: Docker types without
// docker2s2, and anything that is neither an image manifest nor an index/list.
func (service *BaseService) rejectUnsupportedRootMedia(repo, reference, mediaType string) error {
	isDocker := compat.IsCompatibleManifestMediaType(mediaType) ||
		compat.IsCompatibleManifestListMediaType(mediaType)
	if isDocker && !service.config.IsDockerCompatEnabled() {
		service.log.Info().Str("repo", repo).Str("reference", reference).Str("mediaType", mediaType).
			Msg("skipping docker media type because http.compat docker2s2 is not enabled")

		return fmt.Errorf("%w: mediaType %q", zerr.ErrSyncDockerCompatRequired, mediaType)
	}

	if compat.IsImageManifestMediaType(mediaType) || compat.IsImageIndexMediaType(mediaType) {
		return nil
	}

	service.log.Info().Str("repo", repo).Str("reference", reference).Str("mediaType", mediaType).
		Msg("skipping unsupported root media type")

	return fmt.Errorf("%w: mediaType %q", zerr.ErrMediaTypeNotSupported, mediaType)
}

// blobDigestsForReuse returns the config+layer digests referenced by remoteImageRef's manifest
// (skipping non-distributable layers), for preseedLocalBlobs to try reusing from local storage
// before ImageCopy fetches them from upstream - see blob_reuse.go and issue #4386. Returns nil
// (never an error: reuse is a best-effort optimization, never a correctness requirement) when
// reuse does not apply: a sparse index copy fetches no blobs of its own, and a streaming-enabled
// registry must never preseed, since the blob-reader hook that forwards bytes to a waiting client
// never runs for a blob ImageCopy skips because it was already found at the destination.
func (service *BaseService) blobDigestsForReuse(ctx context.Context, remoteImageRef ref.Ref,
	mediaType string, strategy copyStrategy,
) []godigest.Digest {
	if service.config.IsStreamEnabled() {
		return nil
	}

	if strategy == copySparseIndex && compat.IsImageIndexMediaType(mediaType) {
		return nil
	}

	man, err := service.rc.ManifestGet(ctx, remoteImageRef)
	if err != nil {
		service.log.Debug().Err(err).Str("image", remoteImageRef.CommonName()).
			Msg("failed to fetch manifest for blob reuse, continuing without preseeding local blobs")

		return nil
	}
	defer service.rc.Close(ctx, man.GetRef())

	imager, ok := man.(manifest.Imager)
	if !ok {
		return nil
	}

	configDesc, err := imager.GetConfig()
	if err != nil {
		return nil
	}

	layers, err := imager.GetLayers()
	if err != nil {
		return nil
	}

	blobDigests := make([]godigest.Digest, 0, len(layers)+1)
	blobDigests = append(blobDigests, configDesc.Digest)

	for _, layer := range layers {
		if storageCommon.IsNonDistributable(layer.MediaType) {
			continue
		}

		blobDigests = append(blobDigests, layer.Digest)
	}

	return blobDigests
}

// enforceOnlySigned rejects tag with zerr.ErrSyncImageNotSigned when the config requires signed
// images (OnlySigned) and tag has no signature referrer (or, when legacy cosign tags are synced,
// no matching cosign signature tag). It is a no-op otherwise, including for a signature/referrers
// tag itself (which can never be "signed" in this sense), and whenever skipOnlySigned is set - see
// syncImageOptions.SkipOnlySigned.
//
// Shared between syncImage (the plain periodic/on-demand path, where a rejection here simply
// means the tag was already excluded from the local store) and FetchManifest (the streaming
// path, where this check MUST run before the manifest is handed back to a client, not just
// before the eventual local commit - otherwise an unsigned image could be fully streamed to a
// client before the normal on-demand sync would have rejected it).
func (service *BaseService) enforceOnlySigned(ctx context.Context, remoteRepo, tag string,
	remoteImageRef ref.Ref, remoteDigest godigest.Digest, repoTags []string, skipOnlySigned bool,
) error {
	checkIsSigned := service.config.OnlySigned != nil && *service.config.OnlySigned &&
		!skipOnlySigned &&
		!common.IsCosignSignature(tag) && !common.IsReferrersTag(tag)

	if !checkIsSigned {
		return nil
	}

	referrers, err := service.rc.ReferrerList(ctx, remoteImageRef)
	if err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
			Err(err).Msg("failed to get referrers for repo")

		return err
	}

	isSigned := hasSignatureReferrers(referrers)
	if service.config.ShouldSyncLegacyCosignTags() {
		// legacy fallback: verify repo contains a cosign signature tag for this manifest
		if len(repoTags) == 0 {
			repoTags, err = service.getTagsUnlocked(ctx, remoteRepo, false)
			if err != nil {
				service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
					Err(err).Msg("error while getting tags for repo")

				return err
			}
		}

		hasCosignSignature := slices.Contains(repoTags, fmt.Sprintf("%s-%s.sig", remoteDigest.Algorithm(),
			remoteDigest.Encoded()))

		isSigned = isSigned || hasCosignSignature
	}

	if !isSigned {
		// skip unsigned images
		service.log.Info().Str("image", remoteImageRef.CommonName()).
			Msg("skipping image without mandatory signature")

		return zerr.ErrSyncImageNotSigned
	}

	return nil
}

// syncImage syncs localRepo:tag from remoteRepo:tag, unless pinnedDigest is set, in which case
// the remote fetch targets that exact digest instead of re-resolving tag - see PinnedSyncer's doc
// comment for why a caller would want that. Either way the local commit is keyed by tag.
func (service *BaseService) syncImage(ctx context.Context, localRepo, remoteRepo, tag string,
	repoTags []string, opts syncImageOptions,
) error {
	var remoteDigest godigest.Digest

	var mediaType string

	lookupRef := tag
	if opts.TagContentDigest != "" {
		remoteDigest = opts.TagContentDigest
		lookupRef = remoteDigest.String()
	}

	localImageRef, err := service.destination.GetImageReference(localRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", localRepo).Str("reference", tag).Msg("failed to get a local image reference")

		return err
	}

	// Clean up temp layout on all exit paths after we have a local ref.
	defer service.destination.CleanupImage(localImageRef, localRepo) //nolint: errcheck

	// Deliberately no stream-cache cleanup here: this syncImage is shared by SyncRepo's periodic
	// sync and plain on-demand SyncImage, either of which can run for localRepo:tag concurrently
	// with an unrelated streaming background sync of the very same reference. Purging the stream
	// cache from here would race that background sync's own copy, potentially removing the active
	// readers/blob-reader hook it's still using and truncating attached clients. Only the
	// FetchManifestForStream background goroutine that actually staged the entry owns removing it
	// - see its defer in on_demand.go.

	err = func() error {
		service.clientLock.RLock()
		defer service.clientLock.RUnlock()

		// Close under the lock (rc can be replaced on credential refresh). CommitAll only
		// needs the destination temp path on localImageRef, not an open regclient handle.
		defer service.rc.Close(ctx, localImageRef)

		// One GetImageReference for the pin; HeadManifestRef reuses that ref (no second parse).
		remoteImageRef, err := service.remote.GetImageReference(remoteRepo, lookupRef)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repository", remoteRepo).Str("reference", lookupRef).Msg("couldn't get a remote image reference")

			return err
		}

		if opts.TagContentDigest != "" && opts.MediaType != "" {
			mediaType = opts.MediaType
		} else {
			var headDigest godigest.Digest

			headDigest, mediaType, err = service.remote.HeadManifestRef(ctx, remoteImageRef)
			if err != nil {
				service.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", lookupRef).
					Msg("failed to get upstream image manifest details")

				return err
			}

			if opts.TagContentDigest == "" {
				remoteDigest = headDigest
			}
		}

		if err := service.rejectUnsupportedRootMedia(remoteRepo, tag, mediaType); err != nil {
			return err
		}

		// Pin remote content by digest so ImageCopy / referrers cannot follow a moved tag.
		remoteImageRef = remoteImageRef.SetDigest(remoteDigest.String())

		defer service.rc.Close(ctx, remoteImageRef)

		if err := service.enforceOnlySigned(ctx, remoteRepo, tag, remoteImageRef, remoteDigest,
			repoTags, opts.SkipOnlySigned); err != nil {
			return err
		}

		blobDigests := service.blobDigestsForReuse(ctx, remoteImageRef, mediaType, opts.Strategy)

		// first sync image (CanSkip uses upstream digest; no Docker→OCI conversion).
		err = service.syncRef(ctx, localRepo, remoteImageRef, localImageRef, remoteDigest,
			blobDigests, mediaType, opts.Strategy)
		if err != nil {
			return err
		}

		if opts.WithReferrers {
			_ = service.syncReferrers(ctx, repoTags, localRepo, remoteRepo, localImageRef, remoteImageRef, true)
		}

		return nil
	}()
	if err != nil {
		return err
	}

	// Commit outside clientLock so credential refresh is not blocked on local I/O.
	err = service.destination.CommitAll(localRepo, localImageRef)
	if err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", localRepo).
			Err(err).Msg("failed to commit image")

		return err
	}

	service.log.Info().Str("repo", localRepo).Str("reference", tag).Msg("successfully synced image")

	return nil
}

func (service *BaseService) getTags(ctx context.Context, repo string, noCache bool) ([]string, error) {
	if !noCache {
		if isValid, tags := service.tagsCache.Get(repo); isValid {
			return tags, nil
		}
	}

	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	return service.getTagsUnlocked(ctx, repo, noCache)
}

// getTagsUnlocked lists tags without taking clientLock. Caller must hold clientLock for
// reading when contacting the remote (cache hits do not touch remote/rc).
func (service *BaseService) getTagsUnlocked(ctx context.Context, repo string, noCache bool) ([]string, error) {
	var isValid bool

	var tags []string

	var err error

	if !noCache {
		isValid, tags = service.tagsCache.Get(repo)
	}

	if !isValid || noCache {
		tags, err = service.remote.GetTags(ctx, repo)
		if err != nil {
			return nil, err
		}

		service.tagsCache.Set(repo, tags)
	}

	return tags, nil
}

// syncs referrers of the given subject, when recursive is true also syncs referrers of those referrers.
// Caller must hold clientLock for reading (uses remote and rc).
func (service *BaseService) syncReferrers(ctx context.Context, tags []string, localRepo, remoteRepo string,
	localImageRef ref.Ref, remoteImageRef ref.Ref, recursive bool,
) error {
	seen := []string{}

	var err error

	if service.config.ShouldSyncLegacyCosignTags() && len(tags) == 0 {
		tags, err = service.getTagsUnlocked(ctx, remoteRepo, false)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
				Err(err).Msg("error while getting tags for repo")

			return err
		}
	}

	var inner func(ctx context.Context, tags []string, localRepo, remoteRepo string,
		localImageRef ref.Ref, remoteImageRef ref.Ref, seen []string, recursive bool,
	) error

	inner = func(ctx context.Context, tags []string, localRepo, remoteRepo string,
		localImageRef ref.Ref, remoteImageRef ref.Ref, seen []string, recursive bool,
	) error {
		var err error

		remoteDigest := godigest.Digest(remoteImageRef.Digest)

		if remoteImageRef.Tag != "" {
			remoteDigest, _, err = service.remote.HeadManifest(ctx, remoteRepo, remoteImageRef.Tag)
			if err != nil {
				service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
					Str("repo", remoteRepo).Str("remote reference", remoteImageRef.Tag).Msg("failed to get manifest")

				return err
			}
		}

		// is seen
		if slices.Contains(seen, remoteDigest.String()) {
			return nil
		}

		seen = append(seen, remoteDigest.String())

		referrers, err := service.rc.ReferrerList(ctx, remoteImageRef)
		if err != nil {
			return err
		}

		for _, desc := range referrers.Descriptors {
			remoteImageRef = remoteImageRef.SetDigest(desc.Digest.String())

			localImageRef = localImageRef.SetDigest(desc.Digest.String())

			err = service.syncRef(ctx, localRepo, remoteImageRef, localImageRef, desc.Digest,
				nil, desc.MediaType, copyDigestComplete)
			if err != nil {
				service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
					Str("repo", localRepo).Str("local reference", localImageRef.Tag).
					Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
			}

			if recursive {
				_ = inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen, recursive)
			}
		}

		if service.config.ShouldSyncLegacyCosignTags() {
			// try legacy cosign-style tags (sha256-<subjectDigest>.<suffix>)
			prefix := fmt.Sprintf("%s-%s.", remoteDigest.Algorithm(), remoteDigest.Encoded())
			for _, tag := range tags {
				if strings.Contains(tag, prefix) {
					remoteImageRef = remoteImageRef.SetTag(tag)

					localImageRef = localImageRef.SetTag(tag)

					err = service.syncRef(ctx, localRepo, remoteImageRef, localImageRef, remoteDigest,
						nil, "", copyDigestComplete)
					if err != nil {
						service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
							Str("repo", localRepo).Str("local reference", localImageRef.Tag).
							Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
					}

					if recursive {
						_ = inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen, recursive)
					}
				}
			}
		}

		return err
	}

	return inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen, recursive)
}

func (service *BaseService) ResetCatalog() {
	service.log.Info().Msg("resetting catalog")

	service.repositories = []string{}
}

func getTLSConfigOption(url *url.URL, tlsVerify *bool) config.TLSConf {
	// by default enabled
	tls := config.TLSEnabled

	// tlsVerify is to false
	if tlsVerify != nil {
		if !*tlsVerify {
			tls = config.TLSInsecure
		}
	}

	// conn is http => disabled
	if url.Scheme == "http" {
		tls = config.TLSDisabled
	}

	return tls
}

// httpRetryDelayBounds returns regclient WithDelay arguments for HTTP retry backoff.
// When maxRetryDelay is unset, delayMax defaults to delayInit so existing configs keep a fixed retry interval.
// Set maxRetryDelay greater than retryDelay to enable exponential backoff up to that cap.
func httpRetryDelayBounds(opts syncconf.RegistryConfig) (time.Duration, time.Duration, bool) {
	if opts.RetryDelay == nil {
		return 0, 0, false
	}

	delayInit := *opts.RetryDelay
	delayMax := delayInit

	if opts.MaxRetryDelay != nil {
		delayMax = *opts.MaxRetryDelay
	}

	return delayInit, delayMax, true
}

// effectiveMaxIdleConnsPerHost returns the transport's MaxIdleConnsPerHost setting: the
// configured override when set, or — when DisableHTTP2 is enabled — reqConcurrent, so the idle
// pool is sized to match how many HTTP/1.1 connections can actually be in flight (otherwise it
// stays at Go's default of 2, and connections beyond that get closed instead of pooled, undoing
// most of DisableHTTP2's benefit under concurrency). Otherwise 0, meaning "leave it at the Go
// default" (the same value the cloned http.DefaultTransport already carries).
func effectiveMaxIdleConnsPerHost(opts syncconf.RegistryConfig, reqConcurrent int64) int {
	if opts.MaxIdleConnsPerHost != nil {
		return *opts.MaxIdleConnsPerHost
	}

	if opts.DisableHTTP2 != nil && *opts.DisableHTTP2 {
		return int(reqConcurrent)
	}

	return 0
}

// pinHTTP1ALPN returns tlsConfig with NextProtos pinned to exclude HTTP/2, so ALPN negotiation
// itself excludes "h2" even if the upstream would otherwise select it (clearing Transport.TLSNextProto
// alone isn't enough for that). tlsConfig may be nil: http.Transport.Clone() lazily runs Go's own
// HTTP/2 auto-configuration on its source transport first, which in virtually every real build sets a
// non-nil TLSClientConfig before Clone() copies it — but that's an internal net/http implementation
// detail, not a guarantee, so this stays nil-safe rather than assuming it.
func pinHTTP1ALPN(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil {
		// No fields set here diverge from http.DefaultTransport's TLS behavior (e.g. MinVersion
		// stays at Go's secure default); this only exists as a place to pin NextProtos below.
		tlsConfig = &tls.Config{} //nolint:gosec
	}

	tlsConfig.NextProtos = []string{"http/1.1"}

	return tlsConfig
}

// applySyncTransportOptions applies DisableHTTP2 and MaxIdleConnsPerHost to transport in place.
// Extracted out of newClient so a unit test can inspect the resulting *http.Transport directly:
// newClient only returns a *regclient.RegClient, which wraps the transport and doesn't expose it.
func applySyncTransportOptions(transport *http.Transport, opts syncconf.RegistryConfig, reqConcurrent int64) {
	// DisableHTTP2: net/http multiplexes every request to a host onto a single HTTP/2 connection,
	// so all of it shares one TCP congestion window regardless of client-side concurrency. Forcing
	// HTTP/1.1 makes each concurrent request open its own TCP connection instead.
	if opts.DisableHTTP2 != nil && *opts.DisableHTTP2 {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		transport.TLSClientConfig = pinHTTP1ALPN(transport.TLSClientConfig)
	}

	transport.MaxIdleConnsPerHost = effectiveMaxIdleConnsPerHost(opts, reqConcurrent)
}

func newClient(opts syncconf.RegistryConfig, credentials syncconf.CredentialsFile, logger log.Logger,
) (*regclient.RegClient, []config.Host, error) {
	urls, err := parseRegistryURLs(opts.URLs)
	if err != nil {
		return nil, nil, err
	}

	mirrorsHosts := make([]string, 0)
	for _, url := range urls[1:] {
		mirrorsHosts = append(mirrorsHosts, url.Host)
	}

	mainHost := urls[0].Host

	hostConfig := config.Host{}

	host := config.HostNew()
	if host != nil {
		hostConfig = *host
	}

	hostConfig.Name = mainHost
	hostConfig.Hostname = mainHost
	hostConfig.Mirrors = mirrorsHosts
	hostConfig.RepoAuth = true

	// Override regclient's per-host concurrency/rate limits when configured. regclient applies these
	// limits independently per host: the value set here on the upstream host is also copied onto each
	// mirror, so the effective cap is per host, not a shared total across the upstream and its mirrors.
	// When unset, regclient's defaults are kept (ReqConcurrent=3, ReqPerSec=0 i.e. unlimited).
	if opts.ReqConcurrent != nil {
		hostConfig.ReqConcurrent = int64(*opts.ReqConcurrent)
	}

	if opts.ReqPerSec != nil {
		hostConfig.ReqPerSec = *opts.ReqPerSec
	}

	// set TLS configuration
	tlsConf := getTLSConfigOption(urls[0], opts.TLSVerify)
	hostConfig.TLS = tlsConf

	if opts.CertDir != "" {
		clientCert, clientKey, regCert, err := getCertificates(opts.CertDir)
		if err != nil {
			return nil, nil, err
		}

		hostConfig.ClientCert = clientCert
		hostConfig.ClientKey = clientKey
		hostConfig.RegCert = regCert
	}

	if mainHost == regclient.DockerRegistryAuth ||
		mainHost == regclient.DockerRegistryDNS ||
		mainHost == regclient.DockerRegistry ||
		mainHost == "index.docker.io" {
		hostConfig.Name = regclient.DockerRegistry
		hostConfig.Hostname = regclient.DockerRegistryDNS
		hostConfig.CredHost = regclient.DockerRegistryAuth
	}

	creds, ok := credentials[mainHost]
	if ok {
		hostConfig.User = creds.Username
		hostConfig.Pass = creds.Password
	}

	hostConfigOpts := []config.Host{}
	hostConfigOpts = append(hostConfigOpts, hostConfig)

	for _, mirror := range mirrorsHosts {
		mirrorHostConfig := hostConfig
		mirrorHostConfig.Name = mirror
		mirrorHostConfig.Hostname = mirror

		creds, ok := credentials[mirror]
		if ok {
			mirrorHostConfig.User = creds.Username
			mirrorHostConfig.Pass = creds.Password
		}

		hostConfigOpts = append(hostConfigOpts, mirrorHostConfig)
	}

	regOpts := []reg.Opts{}

	if opts.CertDir != "" {
		regOpts = append(regOpts, reg.WithCertDirs([]string{opts.CertDir}))
	}

	if opts.MaxRetries != nil {
		regOpts = append(regOpts, reg.WithRetryLimit(*opts.MaxRetries))
	}

	if delayInit, delayMax, ok := httpRetryDelayBounds(opts); ok {
		regOpts = append(regOpts, reg.WithDelay(delayInit, delayMax))
	}

	// Configure transport with timeouts to prevent indefinite hangs.
	// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	// Clone DefaultTransport to preserve proxy/TLS settings and existing timeouts
	// (DialContext: 30s, TLSHandshakeTimeout: 10s).
	// regclient uses DefaultTransport internally if no custom transport is provided, so this ensures compatibility.
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert

	// ResponseHeaderTimeout: prevents hanging when server connects but doesn't send headers.
	// Set programmatically in root.go. This timeout applies only to waiting for response headers
	// after the request is sent. It does NOT include DialContext (30s) or TLSHandshakeTimeout (10s),
	// which are separate component timeouts. Doesn't cover body transfer time, which is expected
	// to be slow for large images.
	transport.ResponseHeaderTimeout = opts.ResponseHeaderTimeout

	// hostConfig.ReqConcurrent already holds the effective per-host concurrency cap at this point
	// (regclient's default of 3, from HostNew() above, or opts.ReqConcurrent if it was set).
	applySyncTransportOptions(transport, opts, hostConfig.ReqConcurrent)

	// Use SyncTimeout for overall HTTP client timeout. This is the maximum time for the entire
	// HTTP request, covering all stages: DialContext (connection establishment), TLSHandshakeTimeout
	// (TLS handshake), ResponseHeaderTimeout (waiting for headers), and body transfer time.
	// Critical for periodic sync operations (catalog listing, SyncRepo, getTags) which don't use
	// on-demand timeout contexts and could otherwise hang indefinitely if upstream doesn't respond.
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   opts.SyncTimeout,
	}
	regOpts = append(regOpts, reg.WithHTTPClient(httpClient))

	client := regclient.New(
		regclient.WithDockerCerts(),
		regclient.WithDockerCreds(),
		regclient.WithRegOpts(regOpts...),
		regclient.WithConfigHost(hostConfigOpts...),
		regclient.WithSlog(logger.Logger),
	)

	return client, hostConfigOpts, nil
}
