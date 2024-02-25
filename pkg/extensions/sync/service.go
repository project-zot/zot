//go:build sync
// +build sync

package sync

import (
	"context"
	"errors"
	"fmt"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	client "zotregistry.dev/zot/pkg/extensions/sync/httpclient"
	"zotregistry.dev/zot/pkg/extensions/sync/references"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

type BaseService struct {
	config          syncconf.RegistryConfig
	credentials     syncconf.CredentialsFile
	remote          Remote
	destination     Destination
	retryOptions    *retry.RetryOptions
	contentManager  ContentManager
	storeController storage.StoreController
	metaDB          mTypes.MetaDB
	repositories    []string
	references      references.References
	client          *client.Client
	log             log.Logger
}

func New(
	opts syncconf.RegistryConfig,
	credentialsFilepath string,
	tmpDir string,
	storeController storage.StoreController,
	metadb mTypes.MetaDB,
	log log.Logger,
) (*BaseService, error) {
	service := &BaseService{}

	service.config = opts
	service.log = log
	service.metaDB = metadb

	var err error

	var credentialsFile syncconf.CredentialsFile
	if credentialsFilepath != "" {
		credentialsFile, err = getFileCredentials(credentialsFilepath)
		if err != nil {
			log.Error().Str("errortype", common.TypeOf(err)).Str("path", credentialsFilepath).
				Err(err).Msg("couldn't get registry credentials from configured path")
		}
	}

	service.credentials = credentialsFile

	service.contentManager = NewContentManager(opts.Content, log)

	if len(tmpDir) == 0 {
		// first it will sync in tmpDir then it will move everything into local ImageStore
		service.destination = NewDestinationRegistry(storeController, storeController, metadb, log)
	} else {
		// first it will sync under /rootDir/reponame/.sync/ then it will move everything into local ImageStore
		service.destination = NewDestinationRegistry(
			storeController,
			storage.StoreController{
				DefaultStore: getImageStore(tmpDir),
			},
			metadb,
			log,
		)
	}

	retryOptions := &retry.RetryOptions{}

	if opts.MaxRetries != nil {
		retryOptions.MaxRetry = *opts.MaxRetries
		if opts.RetryDelay != nil {
			retryOptions.Delay = *opts.RetryDelay
		}
	}

	service.retryOptions = retryOptions
	service.storeController = storeController

	// try to set next client.
	if err := service.SetNextAvailableClient(); err != nil {
		// if it's a ping issue, it will be retried
		if !errors.Is(err, zerr.ErrSyncPingRegistry) {
			return service, err
		}
	}

	service.references = references.NewReferences(
		service.client,
		service.storeController,
		service.metaDB,
		service.log,
	)

	service.remote = NewRemoteRegistry(
		service.client,
		service.log,
	)

	return service, nil
}

func (service *BaseService) SetNextAvailableClient() error {
	if service.client != nil && service.client.Ping() {
		return nil
	}

	found := false

	for _, url := range service.config.URLs {
		// skip current client
		if service.client != nil && service.client.GetBaseURL() == url {
			continue
		}

		remoteAddress := StripRegistryTransport(url)
		credentials := service.credentials[remoteAddress]

		tlsVerify := true
		if service.config.TLSVerify != nil {
			tlsVerify = *service.config.TLSVerify
		}

		options := client.Config{
			URL:       url,
			Username:  credentials.Username,
			Password:  credentials.Password,
			TLSVerify: tlsVerify,
			CertDir:   service.config.CertDir,
		}

		var err error

		if service.client != nil {
			err = service.client.SetConfig(options)
		} else {
			service.client, err = client.New(options, service.log)
		}

		if err != nil {
			service.log.Error().Err(err).Str("url", url).Msg("failed to initialize http client")

			return err
		}

		if service.client.Ping() {
			found = true

			break
		}
	}

	if service.client == nil || !found {
		return zerr.ErrSyncPingRegistry
	}

	return nil
}

func (service *BaseService) GetRetryOptions() *retry.Options {
	return service.retryOptions
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
		if err = retry.RetryIfNecessary(context.Background(), func() error {
			service.repositories, err = service.remote.GetRepositories(context.Background())

			return err
		}, service.retryOptions); err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("remote registry", service.client.GetConfig().URL).
				Err(err).Msg("failed to get repository list from remote registry")

			return "", err
		}
	}

	var matches bool

	for !matches {
		lastRepo = service.getNextRepoFromCatalog(lastRepo)
		if lastRepo == "" {
			break
		}

		matches = service.contentManager.MatchesContent(lastRepo)
	}

	return lastRepo, nil
}

// SyncReference on demand.
func (service *BaseService) SyncReference(ctx context.Context, repo string,
	subjectDigestStr string, referenceType string,
) error {
	remoteRepo := repo

	remoteURL := service.client.GetConfig().URL

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repository", repo).Str("subject", subjectDigestStr).
				Str("reference type", referenceType).Msg("will not sync reference for image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	remoteRepo = service.remote.GetDockerRemoteRepo(remoteRepo)

	service.log.Info().Str("remote", remoteURL).Str("repository", repo).Str("subject", subjectDigestStr).
		Str("reference type", referenceType).Msg("syncing reference for image")

	return service.references.SyncReference(ctx, repo, remoteRepo, subjectDigestStr, referenceType)
}

// SyncImage on demand.
func (service *BaseService) SyncImage(ctx context.Context, repo, reference string) error {
	remoteRepo := repo

	remoteURL := service.client.GetConfig().URL

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repository", repo).Str("reference", reference).
				Msg("will not sync image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	remoteRepo = service.remote.GetDockerRemoteRepo(remoteRepo)

	service.log.Info().Str("remote", remoteURL).Str("repository", repo).Str("reference", reference).
		Msg("syncing image")

	manifestDigest, err := service.syncTag(ctx, repo, remoteRepo, reference)
	if err != nil {
		return err
	}

	err = service.references.SyncAll(ctx, repo, remoteRepo, manifestDigest.String())
	if err != nil && !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
		return err
	}

	return nil
}

// sync repo periodically.
func (service *BaseService) SyncRepo(ctx context.Context, repo string) error {
	service.log.Info().Str("repository", repo).Str("registry", service.client.GetConfig().URL).
		Msg("syncing repo")

	var err error

	var tags []string

	if err = retry.RetryIfNecessary(ctx, func() error {
		tags, err = service.remote.GetRepoTags(repo)

		return err
	}, service.retryOptions); err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repository", repo).
			Err(err).Msg("failed to get tags for repository")

		return err
	}

	// filter tags
	tags, err = service.contentManager.FilterTags(repo, tags)
	if err != nil {
		return err
	}

	service.log.Info().Str("repository", repo).Msgf("syncing tags %v", tags)

	// apply content.destination rule
	destinationRepo := service.contentManager.GetRepoDestination(repo)

	for _, tag := range tags {
		if common.IsContextDone(ctx) {
			return ctx.Err()
		}

		if references.IsCosignTag(tag) || common.IsReferrersTag(tag) {
			continue
		}

		var manifestDigest digest.Digest

		if err = retry.RetryIfNecessary(ctx, func() error {
			manifestDigest, err = service.syncTag(ctx, destinationRepo, repo, tag)

			return err
		}, service.retryOptions); err != nil {
			if errors.Is(err, zerr.ErrSyncImageNotSigned) || errors.Is(err, zerr.ErrMediaTypeNotSupported) {
				// skip unsigned images or unsupported image mediatype
				continue
			}

			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repository", repo).
				Err(err).Msg("failed to sync tags for repository")

			return err
		}

		if manifestDigest != "" {
			if err = retry.RetryIfNecessary(ctx, func() error {
				err = service.references.SyncAll(ctx, destinationRepo, repo, manifestDigest.String())
				if errors.Is(err, zerr.ErrSyncReferrerNotFound) {
					return nil
				}

				return err
			}, service.retryOptions); err != nil {
				service.log.Error().Str("errorType", common.TypeOf(err)).Str("repository", repo).
					Err(err).Msg("failed to sync tags for repository")
			}
		}
	}

	service.log.Info().Str("component", "sync").Str("repository", repo).Msg("finished syncing repository")

	return nil
}

func (service *BaseService) syncTag(ctx context.Context, destinationRepo, remoteRepo, tag string,
) (digest.Digest, error) {
	copyOptions := getCopyOptions(service.remote.GetContext(), service.destination.GetContext())

	policyContext, err := getPolicyContext(service.log)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = policyContext.Destroy()
	}()

	remoteImageRef, err := service.remote.GetImageReference(remoteRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repository", remoteRepo).Str("reference", tag).Msg("couldn't get a remote image reference")

		return "", err
	}

	_, mediaType, manifestDigest, err := service.remote.GetManifestContent(remoteImageRef)
	if err != nil {
		service.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", tag).
			Msg("couldn't get upstream image manifest details")

		return "", err
	}

	if !isSupportedMediaType(mediaType) {
		return "", zerr.ErrMediaTypeNotSupported
	}

	if service.config.OnlySigned != nil && *service.config.OnlySigned &&
		!references.IsCosignTag(tag) && !common.IsReferrersTag(tag) {
		signed := service.references.IsSigned(ctx, remoteRepo, manifestDigest.String())
		if !signed {
			// skip unsigned images
			service.log.Info().Str("image", remoteImageRef.DockerReference().String()).
				Msg("skipping image without mandatory signature")

			return "", zerr.ErrSyncImageNotSigned
		}
	}

	skipImage, err := service.destination.CanSkipImage(destinationRepo, tag, manifestDigest)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repository", destinationRepo).Str("reference", tag).
			Msg("couldn't check if the local image can be skipped")
	}

	if !skipImage {
		localImageRef, err := service.destination.GetImageReference(destinationRepo, tag)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repository", destinationRepo).Str("reference", tag).Msg("couldn't get a local image reference")

			return "", err
		}

		service.log.Info().Str("remote image", remoteImageRef.DockerReference().String()).
			Str("local image", fmt.Sprintf("%s:%s", destinationRepo, tag)).Msg("syncing image")

		_, err = copy.Image(ctx, policyContext, localImageRef, remoteImageRef, &copyOptions)
		if err != nil {
			// cleanup in cases of copy.Image errors while copying.
			if cErr := service.destination.CleanupImage(localImageRef, destinationRepo, tag); cErr != nil {
				service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
					Str("local image", fmt.Sprintf("%s:%s", destinationRepo, tag)).
					Msg("couldn't cleanup temp local image")
			}

			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("remote image", remoteImageRef.DockerReference().String()).
				Str("local image", fmt.Sprintf("%s:%s", destinationRepo, tag)).Msg("coulnd't sync image")

			return "", err
		}

		err = service.destination.CommitImage(localImageRef, destinationRepo, tag)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repository", destinationRepo).Str("reference", tag).Msg("couldn't commit image to local image store")

			return "", err
		}
	} else {
		service.log.Info().Str("image", remoteImageRef.DockerReference().String()).
			Msg("skipping image because it's already synced")
	}

	service.log.Info().Str("component", "sync").
		Str("image", remoteImageRef.DockerReference().String()).Msg("finished syncing image")

	return manifestDigest, nil
}

func (service *BaseService) ResetCatalog() {
	service.log.Info().Msg("resetting catalog")

	service.repositories = []string{}
}

func (service *BaseService) SetNextAvailableURL() error {
	service.log.Info().Msg("getting available client")

	return service.SetNextAvailableClient()
}
