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

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	syncconf "zotregistry.io/zot/pkg/extensions/config/sync"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/extensions/sync/references"
	"zotregistry.io/zot/pkg/log"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

type BaseService struct {
	config          syncconf.RegistryConfig
	credentials     syncconf.CredentialsFile
	remote          Remote
	local           Local
	retryOptions    *retry.RetryOptions
	contentManager  ContentManager
	storeController storage.StoreController
	metaDB          metaTypes.MetaDB
	repositories    []string
	references      references.References
	client          *client.Client
	log             log.Logger
}

func New(opts syncconf.RegistryConfig, credentialsFilepath string,
	storeController storage.StoreController, metaDB metaTypes.MetaDB, log log.Logger,
) (Service, error) {
	service := &BaseService{}

	service.config = opts
	service.log = log
	service.metaDB = metaDB

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
	service.local = NewLocalRegistry(storeController, metaDB, log)

	retryOptions := &retry.RetryOptions{}

	if opts.MaxRetries != nil {
		retryOptions.MaxRetry = *opts.MaxRetries
		if opts.RetryDelay != nil {
			retryOptions.Delay = *opts.RetryDelay
		}
	}

	service.retryOptions = retryOptions
	service.storeController = storeController

	err = service.SetNextAvailableClient()
	if err != nil {
		return nil, err
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
	if service.client != nil && service.client.IsAvailable() {
		return nil
	}

	for _, url := range service.config.URLs {
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
			return err
		}

		if !service.client.IsAvailable() {
			continue
		}
	}

	if service.client == nil {
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

		matches = service.contentManager.MatchesContent(lastRepo)
	}

	return lastRepo, nil
}

// SyncReference on demand.
func (service *BaseService) SyncReference(repo string, subjectDigestStr string, referenceType string) error {
	remoteRepo := repo

	remoteURL := service.client.GetConfig().URL

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("subject", subjectDigestStr).
				Str("reference type", referenceType).Msg("will not sync reference for image, filtered out by content")

			return zerr.ErrSyncImageFilteredOut
		}
	}

	service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("subject", subjectDigestStr).
		Str("reference type", referenceType).Msg("sync: syncing reference for image")

	return service.references.SyncReference(repo, remoteRepo, subjectDigestStr, referenceType)
}

// SyncImage on demand.
func (service *BaseService) SyncImage(repo, reference string) error {
	remoteRepo := repo

	remoteURL := service.client.GetConfig().URL

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

	manifestDigest, err := service.syncTag(repo, remoteRepo, reference)
	if err != nil {
		return err
	}

	err = service.references.SyncAll(repo, remoteRepo, manifestDigest.String())
	if err != nil && !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
		service.log.Error().Err(err).Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
			Msg("error while syncing references for image")

		return err
	}

	return nil
}

// sync repo periodically.
func (service *BaseService) SyncRepo(repo string) error {
	service.log.Info().Str("repo", repo).Str("registry", service.client.GetConfig().URL).
		Msg("sync: syncing repo")

	var err error

	var tags []string

	if err = retry.RetryIfNecessary(context.Background(), func() error {
		tags, err = service.remote.GetRepoTags(repo)

		return err
	}, service.retryOptions); err != nil {
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
		if references.IsCosignTag(tag) {
			continue
		}

		var manifestDigest digest.Digest

		if err = retry.RetryIfNecessary(context.Background(), func() error {
			manifestDigest, err = service.syncTag(localRepo, repo, tag)

			return err
		}, service.retryOptions); err != nil {
			if errors.Is(err, zerr.ErrSyncImageNotSigned) || errors.Is(err, zerr.ErrMediaTypeNotSupported) {
				// skip unsigned images or unsupported image mediatype
				continue
			}

			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
				Err(err).Msg("error while syncing tags for repo")

			return err
		}

		if manifestDigest != "" {
			if err = retry.RetryIfNecessary(context.Background(), func() error {
				err = service.references.SyncAll(localRepo, repo, manifestDigest.String())
				if errors.Is(err, zerr.ErrSyncReferrerNotFound) {
					return nil
				}

				return err
			}, service.retryOptions); err != nil {
				service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
					Err(err).Msg("error while syncing tags for repo")

				return err
			}
		}
	}

	service.log.Info().Str("repo", repo).Msg("sync: finished syncing repo")

	return nil
}

func (service *BaseService) syncTag(localRepo, remoteRepo, tag string) (digest.Digest, error) {
	copyOptions := getCopyOptions(service.remote.GetContext(), service.local.GetContext())

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
			Str("repo", remoteRepo).Str("reference", tag).Msg("couldn't get a remote image reference")

		return "", err
	}

	_, mediaType, manifestDigest, err := service.remote.GetManifestContent(remoteImageRef)
	if err != nil {
		service.log.Error().Err(err).Str("repo", remoteRepo).Str("reference", tag).
			Msg("couldn't get upstream image manifest details")

		return "", err
	}

	if !isSupportedMediaType(mediaType) {
		return "", zerr.ErrMediaTypeNotSupported
	}

	if service.config.OnlySigned != nil && *service.config.OnlySigned {
		signed := service.references.IsSigned(remoteRepo, manifestDigest.String())
		if !signed {
			// skip unsigned images
			service.log.Info().Str("image", remoteImageRef.DockerReference().String()).
				Msg("skipping image without mandatory signature")

			return "", zerr.ErrSyncImageNotSigned
		}
	}

	skipImage, err := service.local.CanSkipImage(localRepo, tag, manifestDigest)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repo", localRepo).Str("reference", tag).
			Msg("couldn't check if the local image can be skipped")
	}

	if !skipImage {
		localImageRef, err := service.local.GetImageReference(localRepo, tag)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repo", localRepo).Str("reference", tag).Msg("couldn't get a local image reference")

			return "", err
		}

		service.log.Info().Str("remote image", remoteImageRef.DockerReference().String()).
			Str("local image", fmt.Sprintf("%s:%s", localRepo, tag)).Msg("syncing image")

		_, err = copy.Image(context.Background(), policyContext, localImageRef, remoteImageRef, &copyOptions)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("remote image", remoteImageRef.DockerReference().String()).
				Str("local image", fmt.Sprintf("%s:%s", localRepo, tag)).Msg("coulnd't sync image")

			return "", err
		}

		err = service.local.CommitImage(localImageRef, localRepo, tag)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repo", localRepo).Str("reference", tag).Msg("couldn't commit image to local image store")

			return "", err
		}
	} else {
		service.log.Info().Str("image", remoteImageRef.DockerReference().String()).
			Msg("skipping image because it's already synced")
	}

	service.log.Info().Str("image", remoteImageRef.DockerReference().String()).Msg("sync: finished syncing image")

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
