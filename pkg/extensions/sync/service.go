//go:build sync
// +build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/mod"
	"github.com/regclient/regclient/scheme/reg"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/errors"
	zconfig "zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/cluster"
	"zotregistry.dev/zot/pkg/common"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

type BaseService struct {
	config           syncconf.RegistryConfig
	credentials      syncconf.CredentialsFile
	credentialHelper CredentialHelper
	remote           Remote
	destination      Destination
	clusterConfig    *zconfig.ClusterConfig
	copyOptions      []regclient.ImageOpts
	contentManager   ContentManager
	storeController  storage.StoreController
	metaDB           mTypes.MetaDB
	repositories     []string
	rc               *regclient.RegClient
	hosts            []config.Host
	clientLock       sync.RWMutex
	log              log.Logger
}

func New(
	config syncconf.RegistryConfig,
	credentialsFilepath string,
	clusterConfig *zconfig.ClusterConfig,
	tmpDir string,
	storeController storage.StoreController,
	metadb mTypes.MetaDB,
	log log.Logger,
) (*BaseService, error) {
	service := &BaseService{}

	service.config = config
	service.log = log
	service.metaDB = metadb
	service.contentManager = NewContentManager(config.Content, log)
	service.storeController = storeController

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

	client, hosts, err := newClient(service.config, service.credentials)
	if err != nil {
		service.log.Err(err).Msg("failed to parse sync config urls")

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
		defer service.clientLock.RUnlock()

		service.repositories, err = service.remote.GetRepositories(context.Background())
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

	return service.syncTagAndReferrers(ctx, repo, remoteRepo, reference)
}

// sync repo periodically.
func (service *BaseService) SyncRepo(ctx context.Context, repo string) error {
	service.log.Info().Str("repo", repo).Str("registry", service.remote.GetHostName()).
		Msg("sync: syncing repo")

	var err error

	var tags []string

	tags, err = service.remote.GetTags(ctx, repo)
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

		err = service.syncTagAndReferrers(ctx, localRepo, repo, tag)
		if err != nil {
			if errors.Is(err, zerr.ErrSyncImageNotSigned) ||
				errors.Is(err, zerr.ErrUnauthorizedAccess) ||
				errors.Is(err, zerr.ErrMediaTypeNotSupported) ||
				errors.Is(err, zerr.ErrManifestNotFound) {
				// skip unsigned images or unsupported image mediatype
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

func (service *BaseService) syncReference(ctx context.Context, localRepo string, remoteImageRef, localImageRef ref.Ref,
	remoteManifestDigest godigest.Digest, recursive bool,
) (bool, error) {
	var reference string

	if remoteImageRef.Tag != "" {
		reference = remoteImageRef.Tag
	} else {
		reference = remoteImageRef.Digest
	}

	copyOpts := []regclient.ImageOpts{}
	if recursive {
		copyOpts = append(copyOpts, service.copyOptions...)
	}

	// check if image digest + its referrers digests are already synced, otherwise sync everything again
	skipImage, err := service.destination.CanSkipImage(localRepo, reference, remoteManifestDigest)
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

			return false, err
		}
	} else {
		service.log.Info().Str("image", remoteImageRef.CommonName()).
			Msg("skipping image because it's already synced")

		return true, nil
	}

	return false, nil
}

func (service *BaseService) syncTagAndReferrers(ctx context.Context, localRepo, remoteRepo, tag string) error {
	service.clientLock.RLock()
	defer service.clientLock.RUnlock()

	var tags []string

	remoteImageRef, err := service.remote.GetImageReference(remoteRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repository", remoteRepo).Str("reference", tag).Msg("couldn't get a remote image reference")

		return err
	}

	defer service.rc.Close(ctx, remoteImageRef)

	_, remoteManifestDesc, isConverted, err := service.remote.GetOCIManifest(ctx, remoteRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", tag).
			Msg("failed to get upstream image manifest details")

		return err
	}

	// if onlySigned flag true in config and the image is not itself a signature
	if service.config.OnlySigned != nil && *service.config.OnlySigned &&
		!common.IsCosignSignature(tag) && !common.IsReferrersTag(tag) {
		tags, err := service.remote.GetTags(ctx, remoteRepo)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
				Err(err).Msg("failed to get tags for repo")

			return err
		}

		referrers, err := service.rc.ReferrerList(ctx, remoteImageRef)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
				Err(err).Msg("failed to get referrers for repo")

			return err
		}

		// verify repo contains a cosign signature for this manifest
		hasCosignSignature := common.Contains(tags, fmt.Sprintf("%s-%s.sig", remoteManifestDesc.Digest.Algorithm(),
			remoteManifestDesc.Digest.Encoded()))

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
	_, err = service.syncReference(ctx, localRepo, remoteImageRef, localImageRef, remoteManifestDesc.Digest, false)
	if err != nil {
		return err
	}

	_ = service.syncAllReferrers(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef)

	// convert image to oci if needed
	if isConverted {
		localImageRef, err = mod.Apply(ctx, service.rc, localImageRef,
			mod.WithRefTgt(localImageRef),
			mod.WithManifestToOCI(),
			mod.WithManifestToOCIReferrers(),
		)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", localRepo).
				Err(err).Msg("failed to convert docker image to oci")

			return err
		}

		defer service.rc.Close(ctx, localImageRef)
	}

	// commit to storage
	err = service.destination.CommitAll(localRepo, localImageRef)
	if err != nil {
		service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", localRepo).
			Err(err).Msg("failed to commit image")
	}

	service.log.Info().Str("repo", localRepo).Str("reference", tag).Msg("successfully synced image")

	return nil
}

// syncs all referrers recursively.
func (service *BaseService) syncAllReferrers(ctx context.Context, tags []string, localRepo, remoteRepo string,
	localImageRef ref.Ref, remoteImageRef ref.Ref,
) error {
	var err error

	seen := []string{}

	if len(tags) == 0 {
		tags, err = service.remote.GetTags(ctx, remoteRepo)
		if err != nil {
			service.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", remoteRepo).
				Err(err).Msg("failed to get tags for repo")

			return err
		}
	}

	var inner func(ctx context.Context, tags []string, localRepo, remoteRepo string,
		localImageRef ref.Ref, remoteImageRef ref.Ref, seen []string,
	) error

	inner = func(ctx context.Context, tags []string, localRepo, remoteRepo string,
		localImageRef ref.Ref, remoteImageRef ref.Ref, seen []string,
	) error {
		// is seen
		if common.Contains(seen, remoteImageRef.Digest) {
			return nil
		}

		remoteDigest := godigest.Digest(remoteImageRef.Digest)

		if remoteImageRef.Tag != "" {
			manifest, err := service.rc.ManifestHead(ctx, remoteImageRef, regclient.WithManifestRequireDigest())
			if err != nil {
				service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
					Str("repo", remoteRepo).Str("remote reference", remoteImageRef.Tag).Msg("failed to get manifest")

				return err
			}

			remoteDigest = manifest.GetDescriptor().Digest
		}

		seen = append(seen, remoteDigest.String())

		referrers, err := service.rc.ReferrerList(ctx, remoteImageRef)
		if err != nil {
			return err
		}

		for _, desc := range referrers.Descriptors {
			remoteImageRef = remoteImageRef.SetDigest(desc.Digest.String())

			localImageRef = localImageRef.SetDigest(desc.Digest.String())

			skipped, err := service.syncReference(ctx, localRepo, remoteImageRef, localImageRef, desc.Digest, false)
			if err != nil {
				service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
					Str("repo", localRepo).Str("local reference", localImageRef.Tag).
					Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
			}

			if skipped {
				service.log.Info().Str("repo", localRepo).Str("local reference", localImageRef.Tag).
					Str("remote reference", remoteImageRef.Tag).Msg("skipping syncing referrer because it's already synced")
			}

			_ = inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen)
		}

		if remoteDigest != "" {
			// try cosign
			prefix := fmt.Sprintf("%s-%s.", remoteDigest.Algorithm(), remoteDigest.Encoded())
			for _, tag := range tags {
				if strings.Contains(tag, prefix) {
					remoteImageRef = remoteImageRef.SetTag(tag)

					localImageRef = localImageRef.SetTag(tag)

					skipped, err := service.syncReference(ctx, localRepo, remoteImageRef, localImageRef, remoteDigest, true)
					if err != nil {
						service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
							Str("repo", localRepo).Str("local reference", localImageRef.Tag).
							Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
					}

					if skipped {
						service.log.Info().Str("repo", localRepo).Str("local reference", localImageRef.Tag).
							Str("remote reference", remoteImageRef.Tag).Msg("skipping syncing referrer because it's already synced")
					}

					_ = inner(ctx, tags, localRepo, remoteRepo, localImageRef, remoteImageRef, seen)
				}
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

func newClient(opts syncconf.RegistryConfig, credentials syncconf.CredentialsFile,
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
		mirroHostConfig := hostConfig
		mirroHostConfig.Name = mirror
		mirroHostConfig.Hostname = mirror

		creds, ok := credentials[mirror]
		if ok {
			mirroHostConfig.User = creds.Username
			mirroHostConfig.Pass = creds.Password
		}

		hostConfigOpts = append(hostConfigOpts, mirroHostConfig)
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

	client := regclient.New(
		regclient.WithDockerCerts(),
		regclient.WithDockerCreds(),
		regclient.WithRegOpts(regOpts...),
		regclient.WithConfigHost(hostConfigOpts...),
	)

	return client, hostConfigOpts, nil
}
