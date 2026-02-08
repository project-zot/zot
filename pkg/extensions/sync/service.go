//go:build sync

package sync

import (
	"context"
	"encoding/json"
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
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/mod"
	"github.com/regclient/regclient/scheme/reg"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
	zconfig "zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cluster"
	"zotregistry.dev/zot/v2/pkg/common"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
)

const defaultExpireMinutes = 30 * time.Minute

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
	streamManager    StreamManager

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
	service.tagsCache = newTagsCache(defaultExpireMinutes)
	service.streamManager = streamManager

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
		default:
			log.Warn().Msgf("unsupported CredentialHelper: %s", service.config.CredentialHelper)
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
	if service.config.CredentialHelper == "" {
		return nil
	}

	for _, host := range service.hosts {
		// Exit early if the credentials are valid.
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
	}

	// Reinitialize regclient with new credentials
	return service.init()
}

func (service *BaseService) CanRetryOnError() bool {
	if service.config.MaxRetries != nil && *service.config.MaxRetries > 0 {
		return true
	}

	return false
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

	if len(service.repositories) == 0 {
		service.clientLock.RLock()
		service.repositories, err = service.remote.GetRepositories(context.Background())
		service.clientLock.RUnlock()

		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("remote registry", service.remote.GetHostName()).
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

// FetchManifest on demand.
func (service *BaseService) FetchManifest(ctx context.Context, repo, reference string) (manifest.Manifest, error) {
	remoteRepo := repo

	remoteURL := service.remote.GetHostName()

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
				Msg("will not sync image, filtered out by content")

			return nil, zerr.ErrSyncImageFilteredOut
		}
	}

	service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
		Msg("sync: fetching manifest")

	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	artifactRef, err := service.remote.GetImageReference(remoteRepo, reference)
	if err != nil {
		return nil, err
	}

	m, err := service.rc.ManifestGet(ctx, artifactRef)
	if err != nil {
		return nil, err
	}

	// if this is being executed, it is for sure part of streaming.
	// install chunked blob readers for each blob into the stream manager's cache
	if m != nil {
		// first for the manifest blob
		err := service.streamManager.PrepareActiveStreamForBlob(m.GetDescriptor().Digest)
		if err != nil {
			return nil, err
		}

		var contents ispec.Manifest
		contentBytes, err := m.RawBody()
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(contentBytes, &contents)
		if err != nil {
			return nil, err
		}

		// imager, ok := orig.(manifest.Imager)
		// if !ok {
		// 	return nil, errors.New("failed to convert to imager")
		// }

		// next, for config
		// cfg, err := imager.GetConfig()
		// if err != nil {
		// 	return nil, err
		// }

		err = service.streamManager.PrepareActiveStreamForBlob(contents.Config.Digest)
		if err != nil {
			return nil, err
		}

		// finally, for all layers
		// layers, err := imager.GetLayers()
		// if err != nil {
		// 	return nil, err
		// }

		layers := contents.Layers
		for _, layer := range layers {
			err = service.streamManager.PrepareActiveStreamForBlob(layer.Digest)
			if err != nil {
				return nil, err
			}
		}
	}

	return m, nil
}

// SyncImage on demand.
func (service *BaseService) SyncImage(ctx context.Context, repo, reference string) error {
	remoteRepo := repo

	remoteURL := service.remote.GetHostName()

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
				Msg("will not sync image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
		Msg("sync: syncing image")

	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	return service.syncImage(ctx, repo, remoteRepo, reference, nil, false)
}

func (service *BaseService) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	remoteRepo := repo

	remoteURL := service.remote.GetHostName()

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repository", repo).Str("subject", subjectDigestStr).
				Interface("reference types", referenceTypes).Msg("will not sync reference for image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	service.log.Info().Str("remote", remoteURL).Str("repository", repo).Str("subject", subjectDigestStr).
		Interface("reference types", referenceTypes).Msg("syncing reference for image")

	tags, err := service.getTags(ctx, remoteRepo, false)
	if err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
			Err(err).Msg("error while getting tags for repo")

		return err
	}

	remoteImageRef, err := service.remote.GetImageReference(remoteRepo, subjectDigestStr)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repository", remoteRepo).Str("reference", subjectDigestStr).Msg("couldn't get a remote image reference")

		return err
	}

	localImageRef, err := service.destination.GetImageReference(repo, subjectDigestStr)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", repo).Str("reference", subjectDigestStr).Msg("failed to get a local image reference")

		return err
	}

	if err := service.syncReferrers(ctx, tags, repo, remoteRepo, localImageRef, remoteImageRef); err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", repo).Str("reference", subjectDigestStr).Msg("failed to sync referrers")

		return err
	}

	// convert image to oci if needed
	if !service.config.PreserveDigest {
		localImageRef, _ = mod.Apply(ctx, service.rc, localImageRef,
			// mod.WithRefTgt(localImageRef),
			mod.WithManifestToOCI(),
			mod.WithManifestToOCIReferrers(),
		)

		defer service.rc.Close(ctx, localImageRef)
	}

	// commit to storage
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
	service.log.Info().Str("repo", repo).Str("registry", service.remote.GetHostName()).
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

		// skip referrers, they are synced in syncTagAndReferrers.
		if common.IsCosignTag(tag) || common.IsReferrersTag(tag) {
			continue
		}

		err = service.syncImage(ctx, localRepo, repo, tag, tags, true)
		if err != nil {
			if errors.Is(err, zerr.ErrSyncImageNotSigned) ||
				errors.Is(err, zerr.ErrUnauthorizedAccess) ||
				errors.Is(err, zerr.ErrMediaTypeNotSupported) ||
				errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrRepoNotFound) {
				// skip unsigned images, unsupported image mediatype, or temp sync dir issues
				// ErrRepoNotFound from temp sync dir is skippable since each tag uses a different temp directory
				continue
			}

			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
				Err(err).Msg("error while syncing tags for repo")

			return err
		}
	}

	service.log.Info().Str("repo", repo).Msg("sync: finished syncing repo")

	return nil
}

func (service *BaseService) syncRef(ctx context.Context, localRepo string, remoteImageRef, localImageRef ref.Ref,
	remoteDigest godigest.Digest, recursive bool,
) error {
	var reference string

	var skipImage bool

	var err error

	if remoteImageRef.Tag != "" {
		reference = remoteImageRef.Tag
	} else {
		reference = remoteImageRef.Digest
	}

	copyOpts := []regclient.ImageOpts{}
	if recursive {
		copyOpts = append(copyOpts, regclient.ImageWithReferrers())
	}

	if service.streamManager != nil {
		service.log.Info().Str("repo", localRepo).Str("reference", remoteImageRef.Tag).Msg("streaming is enabled. Enabling reader hook")
		copyOpts = append(copyOpts, regclient.ImageWithBlobReaderHook(service.streamManager.StreamingBlobReader))
	}

	// check if image is already synced
	skipImage, err = service.destination.CanSkipImage(localRepo, reference, remoteDigest)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", localRepo).Str("reference", remoteImageRef.Tag).
			Msg("couldn't check if the local image can be skipped")
	}

	if !skipImage {
		service.log.Info().Str("remote image", remoteImageRef.CommonName()).
			Str("local image", fmt.Sprintf("%s:%s", localRepo, remoteImageRef.Tag)).Msg("syncing image")

		err = service.rc.ImageCopy(ctx, remoteImageRef, localImageRef, copyOpts...)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("remote image", remoteImageRef.CommonName()).
				Str("local image", fmt.Sprintf("%s:%s", localRepo, remoteImageRef.Tag)).Msg("failed to sync image")
		}

		return err
	}

	service.log.Info().Str("image", remoteImageRef.CommonName()).
		Msg("skipping image because it's already synced")

	return nil
}

// get "would be" digest of image after synced.
func (service *BaseService) computeLocalStoredImageDigest(ctx context.Context, repo, tag string,
) (godigest.Digest, godigest.Digest, bool, error) {
	var err error

	var localDigest, remoteDigest godigest.Digest

	var isConverted bool

	if !service.config.PreserveDigest {
		localDigest, remoteDigest, isConverted, err = service.remote.GetOCIDigest(ctx, repo, tag)
		if err != nil {
			service.log.Error().Err(err).Str("repository", repo).Str("reference", tag).
				Msg("failed to get upstream image manifest details")

			return "", "", false, err
		}
	} else {
		remoteDigest, err = service.remote.GetDigest(ctx, repo, tag)
		if err != nil {
			service.log.Error().Err(err).Str("repository", repo).Str("reference", tag).
				Msg("failed to get upstream image manifest details")

			return "", "", false, err
		}

		// preserve digest is true, so the local digest is same as remote
		localDigest = remoteDigest
	}

	return localDigest, remoteDigest, isConverted, nil
}

func (service *BaseService) syncImage(ctx context.Context, localRepo, remoteRepo, tag string,
	repoTags []string, withReferrers bool,
) error {
	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	var isConverted bool

	var remoteDigest, localDigest godigest.Digest

	remoteImageRef, err := service.remote.GetImageReference(remoteRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repository", remoteRepo).Str("reference", tag).Msg("couldn't get a remote image reference")

		return err
	}

	localDigest, remoteDigest, isConverted, err = service.computeLocalStoredImageDigest(ctx, remoteRepo, tag)
	if err != nil {
		return err
	}

	defer service.rc.Close(ctx, remoteImageRef)

	checkIsSigned := service.config.OnlySigned != nil && *service.config.OnlySigned &&
		!common.IsCosignSignature(tag) && !common.IsReferrersTag(tag)

	// if onlySigned flag true in config and the image is not itself a signature
	if checkIsSigned {
		// if need tags for checking signature (onlySigned option true) or needs for referrers
		if len(repoTags) == 0 {
			repoTags, err = service.getTags(ctx, remoteRepo, false)
			if err != nil {
				service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
					Err(err).Msg("error while getting tags for repo")

				return err
			}
		}

		referrers, err := service.rc.ReferrerList(ctx, remoteImageRef)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
				Err(err).Msg("failed to get referrers for repo")

			return err
		}

		// verify repo contains a cosign signature for this manifest
		hasCosignSignature := slices.Contains(repoTags, fmt.Sprintf("%s-%s.sig", remoteDigest.Algorithm(),
			remoteDigest.Encoded()))

		isSigned := hasSignatureReferrers(referrers) || hasCosignSignature
		if !isSigned {
			// skip unsigned images
			service.log.Info().Str("image", remoteImageRef.CommonName()).
				Msg("skipping image without mandatory signature")

			return zerr.ErrSyncImageNotSigned
		}
	}

	localImageRef, err := service.destination.GetImageReference(localRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", localRepo).Str("reference", localImageRef.Tag).Msg("failed to get a local image reference")

		return err
	}

	defer service.rc.Close(ctx, localImageRef)

	// just in case there is an error before commit() which cleans up.
	defer service.destination.CleanupImage(localImageRef, localRepo) //nolint: errcheck

	// first sync image
	err = service.syncRef(ctx, localRepo, remoteImageRef, localImageRef, localDigest, false)
	if err != nil {
		return err
	}

	if withReferrers {
		_ = service.syncReferrers(ctx, repoTags, localRepo, remoteRepo, localImageRef, remoteImageRef)
	}

	// convert image to oci if needed
	if isConverted && !service.config.PreserveDigest {
		localImageRef, err = mod.Apply(ctx, service.rc, localImageRef,
			mod.WithRefTgt(localImageRef),
			mod.WithManifestToOCI(),
			mod.WithManifestToOCIReferrers(),
		)

		defer service.rc.Close(ctx, localImageRef)

		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", localRepo).
				Err(err).Msg("failed to convert docker image to oci")

			return err
		}
	}

	// commit to storage
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

// syncs all referrers recursively.
func (service *BaseService) syncReferrers(ctx context.Context, tags []string, localRepo, remoteRepo string,
	localImageRef ref.Ref, remoteImageRef ref.Ref,
) error {
	seen := []string{}

	var err error

	if len(tags) == 0 {
		tags, err = service.getTags(ctx, remoteRepo, false)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
				Err(err).Msg("error while getting tags for repo")

			return err
		}
	}

	var inner func(ctx context.Context, tags []string, localRepo, remoteRepo string,
		localImageRef ref.Ref, remoteImageRef ref.Ref, seen []string,
	) error

	inner = func(ctx context.Context, tags []string, localRepo, remoteRepo string,
		localImageRef ref.Ref, remoteImageRef ref.Ref, seen []string,
	) error {
		var err error

		remoteDigest := godigest.Digest(remoteImageRef.Digest)

		if remoteImageRef.Tag != "" {
			remoteDigest, err = service.remote.GetDigest(ctx, remoteRepo, remoteImageRef.Tag)
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

			err := service.syncRef(ctx, localRepo, remoteImageRef, localImageRef, desc.Digest, false)
			if err != nil {
				service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
					Str("repo", localRepo).Str("local reference", localImageRef.Tag).
					Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
			}

			_ = inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen)
		}

		// try cosign
		prefix := fmt.Sprintf("%s-%s.", remoteDigest.Algorithm(), remoteDigest.Encoded())
		for _, tag := range tags {
			if strings.Contains(tag, prefix) {
				remoteImageRef = remoteImageRef.SetTag(tag)

				localImageRef = localImageRef.SetTag(tag)

				err := service.syncRef(ctx, localRepo, remoteImageRef, localImageRef, remoteDigest, true)
				if err != nil {
					service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
						Str("repo", localRepo).Str("local reference", localImageRef.Tag).
						Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
				}

				_ = inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen)
			}
		}

		return err
	}

	return inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen)
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

	// set TLS configuration
	tls := getTLSConfigOption(urls[0], opts.TLSVerify)
	hostConfig.TLS = tls

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

	if opts.RetryDelay != nil {
		regOpts = append(regOpts, reg.WithDelay(*opts.RetryDelay, *opts.RetryDelay))
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
