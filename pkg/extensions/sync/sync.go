package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	goSync "sync"
	"time"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	SyncBlobUploadDir     = ".sync"
	httpMaxRedirectsCount = 15
)

// /v2/_catalog struct.
type catalog struct {
	Repositories []string `json:"repositories"`
}

// // key is registry address.
// type CredentialsFile map[string]Credentials

// type Credentials struct {
// 	Username string
// 	Password string
// }

// type Config struct {
// 	Enable          *bool
// 	CredentialsFile string
// 	Registries      []extconf.RegistryConfig
// }

// type RegistryConfig struct {
// 	URLs         []string
// 	PollInterval time.Duration
// 	Content      []Content
// 	TLSVerify    *bool
// 	OnDemand     bool
// 	CertDir      string
// 	MaxRetries   *int
// 	RetryDelay   *time.Duration
// 	OnlySigned   *bool
// }

// type Content struct {
// 	Prefix      string
// 	Tags        *Tags
// 	Destination string `mapstructure:",omitempty"`
// 	StripPrefix bool
// }

// type Tags struct {
// 	Regex  *string
// 	Semver *bool
// }

type RepoReferences struct {
	contentID       int                    // matched registry config content
	name            string                 // repo name
	imageReferences []types.ImageReference // contained images(tags)
}

// getUpstreamCatalog gets all repos from a registry.
func GetUpstreamCatalog(client *http.Client, upstreamURL, username, password string, log log.Logger) (catalog, error) { //nolint
	var catalog catalog

	registryCatalogURL := fmt.Sprintf("%s%s%s", upstreamURL, constants.RoutePrefix, constants.ExtCatalogPrefix)

	body, statusCode, err := common.MakeHTTPGetRequest(client, username,
		password, &catalog,
		registryCatalogURL, "application/json", log)
	if err != nil {
		log.Error().Msgf("couldn't query %s, status code: %d, body: %s", registryCatalogURL,
			statusCode, body)

		return catalog, err
	}

	return catalog, nil
}

// imagesToCopyFromRepos lists all images given a registry name and its repos.
func imagesToCopyFromUpstream(ctx context.Context, registryName string, repoName string,
	upstreamCtx *types.SystemContext, content extconf.Content, log log.Logger,
) ([]types.ImageReference, error) {
	imageRefs := []types.ImageReference{}

	repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, repoName))
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't parse repository reference: %s", repoRef)

		return imageRefs, err
	}

	tags, err := getImageTags(ctx, upstreamCtx, repoRef)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't fetch tags for %s", repoRef)

		return imageRefs, err
	}

	// filter based on tags rules
	if content.Tags != nil {
		if content.Tags.Regex != nil {
			tags, err = filterTagsByRegex(tags, *content.Tags.Regex, log)
			if err != nil {
				return imageRefs, err
			}
		}

		if content.Tags.Semver != nil && *content.Tags.Semver {
			tags = filterTagsBySemver(tags, log)
		}
	}

	log.Debug().Msgf("repo: %s - upstream tags to be copied: %v", repoName, tags)

	for _, tag := range tags {
		// don't copy cosign signature, containers/image doesn't support it
		// we will copy it manually later
		if isCosignTag(tag) {
			continue
		}

		taggedRef, err := reference.WithTag(repoRef, tag)
		if err != nil {
			log.Err(err).Msgf("error creating a reference for repository %s and tag %q", repoRef.Name(), tag)

			return imageRefs, err
		}

		ref, err := docker.NewReference(taggedRef)
		if err != nil {
			log.Err(err).Msgf("cannot obtain a valid image reference for transport %q and reference %s",
				docker.Transport.Name(), taggedRef.String())

			return imageRefs, err
		}

		imageRefs = append(imageRefs, ref)
	}

	return imageRefs, nil
}

func getCopyOptions(upstreamCtx, localCtx *types.SystemContext) copy.Options {
	options := copy.Options{
		DestinationCtx:        localCtx,
		SourceCtx:             upstreamCtx,
		ReportWriter:          io.Discard,
		ForceManifestMIMEType: ispec.MediaTypeImageManifest, // force only oci manifest MIME type
		ImageListSelection:    copy.CopyAllImages,
	}

	return options
}

func getUpstreamContext(regCfg *extconf.RegistryConfig, credentials extconf.Credentials) *types.SystemContext {
	upstreamCtx := &types.SystemContext{}
	upstreamCtx.DockerCertPath = regCfg.CertDir
	upstreamCtx.DockerDaemonCertPath = regCfg.CertDir

	if regCfg.TLSVerify != nil && *regCfg.TLSVerify {
		upstreamCtx.DockerDaemonInsecureSkipTLSVerify = false
		upstreamCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(false)
	} else {
		upstreamCtx.DockerDaemonInsecureSkipTLSVerify = true
		upstreamCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
	}

	if credentials != (extconf.Credentials{}) {
		upstreamCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: credentials.Username,
			Password: credentials.Password,
		}
	}

	return upstreamCtx
}

//nolint:gocyclo  // offloading some of the functionalities from here would make the code harder to follow
func syncRegistry(ctx context.Context, regCfg extconf.RegistryConfig,
	upstreamURL string,
	storeController storage.StoreController, localCtx *types.SystemContext,
	policyCtx *signature.PolicyContext, credentials extconf.Credentials,
	retryOptions *retry.RetryOptions, log log.Logger,
) error {
	log.Info().Msgf("syncing registry: %s", upstreamURL)

	var err error

	log.Debug().Msg("getting upstream context")

	upstreamCtx := getUpstreamContext(&regCfg, credentials)
	options := getCopyOptions(upstreamCtx, localCtx)

	if !common.Contains(regCfg.URLs, upstreamURL) {
		return zerr.ErrSyncInvalidUpstreamURL
	}

	registryURL, err := url.Parse(upstreamURL)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("url", upstreamURL).Msg("couldn't parse url")

		return err
	}

	httpClient, err := common.CreateHTTPClient(*regCfg.TLSVerify, registryURL.Host, regCfg.CertDir)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("error while creating http client")

		return err
	}

	var catalog catalog

	if err = retry.RetryIfNecessary(ctx, func() error {
		catalog, err = GetUpstreamCatalog(httpClient, upstreamURL, credentials.Username, credentials.Password, log)

		return err
	}, retryOptions); err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("error while getting upstream catalog, retrying...")

		return err
	}

	log.Info().Msgf("filtering %d repos based on sync prefixes", len(catalog.Repositories))

	repos := filterRepos(catalog.Repositories, regCfg.Content, log)

	log.Info().Msgf("got repos: %v", repos)

	upstreamAddr := StripRegistryTransport(upstreamURL)

	reposReferences := []RepoReferences{}

	for contentID, repos := range repos {
		for _, repoName := range repos {
			var imageReferences []types.ImageReference

			if err = retry.RetryIfNecessary(ctx, func() error {
				imageReferences, err = imagesToCopyFromUpstream(ctx, upstreamAddr,
					repoName, upstreamCtx, regCfg.Content[contentID], log)

				return err
			}, retryOptions); err != nil {
				log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("error while getting images references from upstream, retrying...")

				return err
			}

			reposReferences = append(reposReferences, RepoReferences{
				contentID:       contentID,
				name:            repoName,
				imageReferences: imageReferences,
			})
		}
	}

	sig := newSignaturesCopier(httpClient, credentials, *registryURL, storeController, log)

	for _, repoReference := range reposReferences {
		upstreamRepo := repoReference.name
		content := regCfg.Content[repoReference.contentID]

		localRepo := getRepoDestination(upstreamRepo, content)

		imageStore := storeController.GetImageStore(localRepo)

		localCachePath, err := getLocalCachePath(imageStore, localRepo)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get localCachePath for %s", localRepo)

			return err
		}

		defer os.RemoveAll(localCachePath)

		for _, upstreamImageRef := range repoReference.imageReferences {
			manifestBuf, mediaType, err := getImageRefManifest(ctx, upstreamCtx, upstreamImageRef, log)
			if err != nil {
				return err
			}

			upstreamImageDigest := digest.FromBytes(manifestBuf)

			tag := getTagFromRef(upstreamImageRef, log).Tag()

			if !isSupportedMediaType(mediaType) {
				if mediaType == ispec.MediaTypeArtifactManifest {
					err = sig.syncOCIArtifact(localRepo, upstreamRepo, tag, manifestBuf) //nolint
					if err != nil {
						return err
					}
				}

				continue
			}

			// get upstream signatures
			cosignManifest, err := sig.getCosignManifest(upstreamRepo, upstreamImageDigest.String())
			if err != nil && !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
				log.Error().Err(err).Msgf("couldn't get upstream image %s cosign manifest", upstreamImageRef.DockerReference())

				return err
			}

			refs, err := sig.getNotaryRefs(upstreamRepo, upstreamImageDigest.String())
			if err != nil && !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
				log.Error().Err(err).Msgf("couldn't get upstream image %s notary references", upstreamImageRef.DockerReference())

				return err
			}

			// check if upstream image is signed
			if cosignManifest == nil && len(refs.References) == 0 {
				// upstream image not signed
				if regCfg.OnlySigned != nil && *regCfg.OnlySigned {
					// skip unsigned images
					log.Info().Msgf("skipping image without signature %s", upstreamImageRef.DockerReference())

					continue
				}
			}

			skipImage, err := canSkipImage(localRepo, tag, upstreamImageDigest, imageStore, log)
			if err != nil {
				log.Error().Err(err).Msgf("couldn't check if the upstream image %s can be skipped",
					upstreamImageRef.DockerReference())

				return err
			}

			if !skipImage {
				// sync image
				localImageRef, err := getLocalImageRef(localCachePath, localRepo, tag)
				if err != nil {
					log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
						localCachePath, localRepo, tag)

					return err
				}

				log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

				if err = retry.RetryIfNecessary(ctx, func() error {
					_, err = copy.Image(ctx, policyCtx, localImageRef, upstreamImageRef, &options)

					return err
				}, retryOptions); err != nil {
					log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msgf("error while copying image %s to %s",
						upstreamImageRef.DockerReference(), localCachePath)

					return err
				}
				// push from cache to repo
				err = pushSyncedLocalImage(localRepo, tag, localCachePath, imageStore, log)
				if err != nil {
					log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msgf("error while pushing synced cached image %s",
						fmt.Sprintf("%s/%s:%s", localCachePath, localRepo, tag))

					return err
				}
			} else {
				log.Info().Msgf("already synced image %s, checking its signatures", upstreamImageRef.DockerReference())
			}

			// sync signatures
			if err = retry.RetryIfNecessary(ctx, func() error {
				index, err := sig.getOCIRefs(upstreamRepo, upstreamImageDigest.String())
				if err != nil && !errors.Is(err, zerr.ErrSyncReferrerNotFound) {
					return err
				}

				err = sig.syncOCIRefs(localRepo, upstreamRepo, upstreamImageDigest.String(), index)
				if err != nil {
					return err
				}

				err = sig.syncNotaryRefs(localRepo, upstreamRepo, upstreamImageDigest.String(), refs)
				if err != nil {
					return err
				}

				err = sig.syncCosignSignature(localRepo, upstreamRepo, upstreamImageDigest.String(), cosignManifest)
				if err != nil {
					return err
				}

				return nil
			}, retryOptions); err != nil {
				log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msgf("couldn't copy referrer for %s", upstreamImageRef.DockerReference())
			}
		}
	}

	log.Info().Msgf("finished syncing %s", upstreamAddr)

	return nil
}

func getLocalContexts(log log.Logger) (*types.SystemContext, *signature.PolicyContext, error) {
	log.Debug().Msg("getting local context")

	var policy *signature.Policy

	var err error

	localCtx := &types.SystemContext{}
	// preserve compression
	localCtx.OCIAcceptUncompressedLayers = true

	// accept any image with or without signature
	policy = &signature.Policy{Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()}}

	policyContext, err := signature.NewPolicyContext(policy)
	if err := test.Error(err); err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't create policy context")

		return &types.SystemContext{}, &signature.PolicyContext{}, err
	}

	return localCtx, policyContext, nil
}

func Run(ctx context.Context, cfg extconf.SyncConfig,
	storeController storage.StoreController,
	wtgrp *goSync.WaitGroup, logger log.Logger,
) error {
	var credentialsFile extconf.CredentialsFile

	var err error

	if cfg.CredentialsFile != "" {
		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			logger.Error().Str("errortype", common.TypeOf(err)).
				Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)

			return err
		}
	}

	localCtx, policyCtx, err := getLocalContexts(logger)
	if err != nil {
		return err
	}

	// for each upstream registry, start a go routine.
	for _, regCfg := range cfg.Registries {
		// if content not provided, don't run periodically sync
		if len(regCfg.Content) == 0 {
			logger.Info().Msgf("sync config content not configured for %v, will not run periodically sync", regCfg.URLs)

			continue
		}

		// if pollInterval is not provided, don't run periodically sync
		if regCfg.PollInterval == 0 {
			logger.Warn().Msgf("sync config PollInterval not configured for %v, will not run periodically sync", regCfg.URLs)

			continue
		}

		ticker := time.NewTicker(regCfg.PollInterval)

		retryOptions := &retry.RetryOptions{}

		if regCfg.MaxRetries != nil {
			retryOptions.MaxRetry = *regCfg.MaxRetries
			if regCfg.RetryDelay != nil {
				retryOptions.Delay = *regCfg.RetryDelay
			}
		}

		// schedule each registry sync
		go func(ctx context.Context, regCfg extconf.RegistryConfig, logger log.Logger) {
			for {
				// increment reference since will be busy, so shutdown has to wait
				wtgrp.Add(1)

				for _, upstreamURL := range regCfg.URLs {
					upstreamAddr := StripRegistryTransport(upstreamURL)
					// first try syncing main registry
					if err := syncRegistry(ctx, regCfg, upstreamURL, storeController, localCtx, policyCtx,
						credentialsFile[upstreamAddr], retryOptions, logger); err != nil {
						logger.Error().Str("errortype", common.TypeOf(err)).
							Err(err).Str("registry", upstreamURL).
							Msg("sync exited with error, falling back to auxiliary registries if any")
					} else {
						// if success fall back to main registry
						break
					}
				}
				// mark as done after a single sync run
				wtgrp.Done()

				select {
				case <-ctx.Done():
					ticker.Stop()

					return
				case <-ticker.C:
					// run on intervals
					continue
				}
			}
		}(ctx, regCfg, logger)
	}

	logger.Info().Msg("finished setting up sync")

	return nil
}
