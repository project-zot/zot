//go:build sync
// +build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

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
	config          syncconf.RegistryConfig
	credentials     syncconf.CredentialsFile
	remote          Remote
	destination     Destination
	clusterConfig   *zconfig.ClusterConfig
	copyOptions     []regclient.ImageOpts
	contentManager  ContentManager
	storeController storage.StoreController
	metaDB          mTypes.MetaDB
	repositories    []string
	regclient       *regclient.RegClient
	log             log.Logger
}

func New(
	opts syncconf.RegistryConfig,
	credentialsFilepath string,
	clusterConfig *zconfig.ClusterConfig,
	tmpDir string,
	storeController storage.StoreController,
	metadb mTypes.MetaDB,
	log log.Logger,
) (*BaseService, error) {
	service := &BaseService{}

	service.config = opts
	service.log = log
	service.metaDB = metadb
	service.contentManager = NewContentManager(opts.Content, log)
	service.storeController = storeController

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

	// load the cluster config into the object
	// can be nil if the user did not configure cluster config
	service.clusterConfig = clusterConfig

	service.contentManager = NewContentManager(opts.Content, log)

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

	var maxRetries int

	var retryDelay time.Duration

	if opts.MaxRetries != nil {
		maxRetries = *opts.MaxRetries

		if opts.RetryDelay != nil {
			retryDelay = *opts.RetryDelay
		}
	}

	service.storeController = storeController

	urls, err := parseRegistryURLs(opts.URLs)
	if err != nil {
		return nil, err
	}

	tls := config.TLSEnabled // default

	mainHost := urls[0].Host

	if urls[0].Scheme == "http" {
		tls = config.TLSDisabled
	}

	mirrorsHosts := make([]string, 0)
	for _, url := range urls[1:] {
		mirrorsHosts = append(mirrorsHosts, url.Host)
	}

	hostConfig := config.Host{}
	hostConfig.Name = mainHost
	hostConfig.Mirrors = mirrorsHosts
	hostConfig.TLS = tls

	if opts.CertDir != "" {
		clientCert, clientKey, regCert, err := getCertificates(opts.CertDir)
		if err != nil {
			return nil, err
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

	credentials, ok := credentialsFile[mainHost]
	if ok {
		hostConfig.User = credentials.Username
		hostConfig.Pass = credentials.Password
	}

	hostConfigOpts := []config.Host{}
	hostConfigOpts = append(hostConfigOpts, hostConfig)

	for _, mirror := range mirrorsHosts {
		mirroHostConfig := hostConfig
		mirroHostConfig.Name = mirror
		hostConfigOpts = append(hostConfigOpts, mirroHostConfig)
	}

	service.regclient = regclient.New(
		regclient.WithDockerCerts(),
		regclient.WithDockerCreds(),
		regclient.WithRegOpts(
			reg.WithCertDirs([]string{opts.CertDir}),
			reg.WithRetryLimit(maxRetries),
			reg.WithDelay(1*time.Second, retryDelay),
		),
		regclient.WithConfigHost(hostConfigOpts...),
	)

	hosts := []string{}
	hosts = append(hosts, mainHost)
	hosts = append(hosts, mirrorsHosts...)

	service.remote = NewRemoteRegistry(
		service.regclient,
		hosts,
		service.log,
	)

	// we want referrers using sha-<digest>.*" tags
	// service.copyOptions = append(service.copyOptions, regclient.ImageWithDigestTags())
	// we want oci referrers
	service.copyOptions = append(service.copyOptions, regclient.ImageWithReferrers())

	return service, nil
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

		if isCosignTag(tag) || common.IsReferrersTag(tag) {
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
	remoteManifestDigest godigest.Digest,
) (bool, error) {
	var reference string

	if remoteImageRef.Tag != "" {
		reference = remoteImageRef.Tag
	} else {
		reference = remoteImageRef.Digest
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

		err = service.regclient.ImageCopy(ctx, remoteImageRef, localImageRef)
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
	var shouldCommit bool

	remoteImageRef, err := service.remote.GetImageReference(remoteRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
			Str("repository", remoteRepo).Str("reference", tag).Msg("couldn't get a remote image reference")

		return err
	}

	defer service.regclient.Close(ctx, remoteImageRef)

	_, remoteManifestDesc, isConverted, err := service.remote.GetOCIManifest(ctx, remoteRepo, tag)
	if err != nil {
		service.log.Error().Err(err).Str("repository", remoteRepo).Str("reference", tag).
			Msg("failed to get upstream image manifest details")

		return err
	}

	referrers, err := service.regclient.ReferrerList(ctx, remoteImageRef)
	if err != nil {
		return err
	}

	if service.config.OnlySigned != nil && *service.config.OnlySigned &&
		!isCosignTag(tag) && !common.IsReferrersTag(tag) {
		signed := hasSignatureReferrers(referrers)
		if !signed {
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

	defer service.regclient.Close(ctx, localImageRef)

	// first sync image
	skipped, err := service.syncReference(ctx, localRepo, remoteImageRef, localImageRef, remoteManifestDesc.Digest)
	if err != nil {
		return err
	}

	shouldCommit = !skipped

	// if image was skipped, then copy it's referrers if needed (they may have changed in the meantime)
	for _, desc := range referrers.Descriptors {
		remoteImageRef = remoteImageRef.SetDigest(desc.Digest.String())

		localImageRef = localImageRef.SetDigest(desc.Digest.String())

		skipped, err := service.syncReference(ctx, localRepo, remoteImageRef, localImageRef, desc.Digest)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repo", localRepo).Str("local reference", localImageRef.Tag).
				Str("remote reference", remoteImageRef.Tag).Msg("failed to sync referrer")
		}

		if skipped {
			service.log.Info().Str("repo", localRepo).Str("local reference", localImageRef.Tag).
				Str("remote reference", remoteImageRef.Tag).Msg("skipping syncing referrer because it's already synced")
		} else {
			shouldCommit = true
		}
	}

	// convert image to oci if needed
	if isConverted {
		localImageRef, err = mod.Apply(ctx, service.regclient, localImageRef,
			mod.WithRefTgt(localImageRef),
			mod.WithManifestToOCI(),
			mod.WithManifestToOCIReferrers(),
		)
		if err != nil {
			return err
		}

		defer service.regclient.Close(ctx, localImageRef)
	}

	if shouldCommit {
		err = service.destination.CommitAll(localRepo, localImageRef)
		if err != nil {
			service.log.Error().Err(err).Str("errortype", common.TypeOf(err)).
				Str("repo", localRepo).Str("reference", tag).Msg("failed to commit image to local image store")

			return err
		}
	}

	service.log.Info().Str("repo", localRepo).Str("reference", tag).Msg("successfully synced image")

	return nil
}

func (service *BaseService) ResetCatalog() {
	service.log.Info().Msg("resetting catalog")

	service.repositories = []string{}
}
