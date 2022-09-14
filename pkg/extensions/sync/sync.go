package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	goSync "sync"
	"time"

	"github.com/Masterminds/semver"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
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

// getUpstreamCatalog gets all repos from a registry.
func getUpstreamCatalog(client *resty.Client, upstreamURL string, log log.Logger) (catalog, error) {
	var catalog catalog

	registryCatalogURL := fmt.Sprintf("%s%s%s", upstreamURL, constants.RoutePrefix, constants.ExtCatalogPrefix)

	resp, err := client.R().SetHeader("Content-Type", "application/json").Get(registryCatalogURL)
	if err != nil {
		log.Err(err).Msgf("couldn't query %s", registryCatalogURL)

		return catalog, err
	}

	if resp.IsError() {
		log.Error().Msgf("couldn't query %s, status code: %d, body: %s", registryCatalogURL,
			resp.StatusCode(), resp.Body())

		return catalog, zerr.ErrSyncMissingCatalog
	}

	err = json.Unmarshal(resp.Body(), &catalog)
	if err != nil {
		log.Err(err).Str("body", string(resp.Body())).Msg("couldn't unmarshal registry's catalog")

		return catalog, err
	}

	return catalog, nil
}

// getImageTags lists all tags in a repository.
// It returns a string slice of tags and any error encountered.
func getImageTags(ctx context.Context, sysCtx *types.SystemContext, repoRef reference.Named) ([]string, error) {
	dockerRef, err := docker.NewReference(reference.TagNameOnly(repoRef))
	// hard to reach test case, injected error, see pkg/test/dev.go
	if err = test.Error(err); err != nil {
		return nil, err // Should never happen for a reference with tag and no digest
	}

	tags, err := docker.GetRepositoryTags(ctx, sysCtx, dockerRef)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// filterImagesByTagRegex filters images by tag regex given in the config.
func filterImagesByTagRegex(upstreamReferences *[]types.ImageReference, content extconf.Content, log log.Logger) error {
	refs := *upstreamReferences

	if content.Tags == nil {
		// no need to filter anything
		return nil
	}

	if content.Tags.Regex != nil {
		log.Info().Msgf("start filtering using the regular expression: %s", *content.Tags.Regex)

		tagReg, err := regexp.Compile(*content.Tags.Regex)
		if err != nil {
			return err
		}

		numTags := 0

		for _, ref := range refs {
			tagged := getTagFromRef(ref, log)
			if tagged != nil {
				if tagReg.MatchString(tagged.Tag()) {
					refs[numTags] = ref
					numTags++
				}
			}
		}

		refs = refs[:numTags]
	}

	*upstreamReferences = refs

	return nil
}

// filterImagesBySemver filters images by checking if their tags are semver compliant.
func filterImagesBySemver(upstreamReferences *[]types.ImageReference, content extconf.Content, log log.Logger) {
	refs := *upstreamReferences

	if content.Tags == nil {
		return
	}

	if content.Tags.Semver != nil && *content.Tags.Semver {
		log.Info().Msg("start filtering using semver compliant rule")

		numTags := 0

		for _, ref := range refs {
			tagged := getTagFromRef(ref, log)
			if tagged != nil {
				_, ok := semver.NewVersion(tagged.Tag())
				if ok == nil {
					refs[numTags] = ref
					numTags++
				}
			}
		}

		refs = refs[:numTags]
	}

	*upstreamReferences = refs
}

// imagesToCopyFromRepos lists all images given a registry name and its repos.
func imagesToCopyFromUpstream(ctx context.Context, registryName string, repos []string,
	upstreamCtx *types.SystemContext, content extconf.Content, log log.Logger,
) (map[string][]types.ImageReference, error) {
	upstreamReferences := make(map[string][]types.ImageReference)

	for _, repoName := range repos {
		repoUpstreamReferences := make([]types.ImageReference, 0)

		repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, repoName))
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't parse repository reference: %s", repoRef)

			return nil, err
		}

		tags, err := getImageTags(ctx, upstreamCtx, repoRef)
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't fetch tags for %s", repoRef)

			return nil, err
		}

		for _, tag := range tags {
			// don't copy cosign signature, containers/image doesn't support it
			// we will copy it manually later
			if isCosignTag(tag) {
				continue
			}

			taggedRef, err := reference.WithTag(repoRef, tag)
			if err != nil {
				log.Err(err).Msgf("error creating a reference for repository %s and tag %q", repoRef.Name(), tag)

				return nil, err
			}

			ref, err := docker.NewReference(taggedRef)
			if err != nil {
				log.Err(err).Msgf("cannot obtain a valid image reference for transport %q and reference %s",
					docker.Transport.Name(), taggedRef.String())

				return nil, err
			}

			repoUpstreamReferences = append(repoUpstreamReferences, ref)
		}

		upstreamReferences[repoName] = repoUpstreamReferences

		log.Debug().Msgf("repo: %s - upstream refs to be copied: %v", repoName, upstreamReferences)

		err = filterImagesByTagRegex(&repoUpstreamReferences, content, log)
		if err != nil {
			return map[string][]types.ImageReference{}, err
		}

		log.Debug().Msgf("repo: %s - remaining upstream refs to be copied: %v", repoName, repoUpstreamReferences)

		filterImagesBySemver(&repoUpstreamReferences, content, log)

		log.Debug().Msgf("repo: %s - remaining upstream refs to be copied: %v", repoName, repoUpstreamReferences)

		upstreamReferences[repoName] = repoUpstreamReferences
	}

	return upstreamReferences, nil
}

func getCopyOptions(upstreamCtx, localCtx *types.SystemContext) copy.Options {
	options := copy.Options{
		DestinationCtx:        localCtx,
		SourceCtx:             upstreamCtx,
		ReportWriter:          io.Discard,
		ForceManifestMIMEType: ispec.MediaTypeImageManifest, // force only oci manifest MIME type
		PreserveDigests:       true,
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

// nolint:gocyclo  // offloading some of the functionalities from here would make the code harder to follow
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

	httpClient, registryURL, err := getHTTPClient(&regCfg, upstreamURL, credentials, log)
	if err != nil {
		return err
	}

	var catalog catalog

	if err = retry.RetryIfNecessary(ctx, func() error {
		catalog, err = getUpstreamCatalog(httpClient, upstreamURL, log)

		return err
	}, retryOptions); err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msg("error while getting upstream catalog, retrying...")

		return err
	}

	log.Info().Msgf("filtering %d repos based on sync prefixes", len(catalog.Repositories))

	repos := filterRepos(catalog.Repositories, regCfg.Content, log)

	log.Info().Msgf("got repos: %v", repos)

	upstreamAddr := StripRegistryTransport(upstreamURL)

	reposWithContentID := make(map[string][]struct {
		ref     types.ImageReference
		content extconf.Content
	})

	for contentID, repos := range repos {
		r := repos
		contentID := contentID

		if err = retry.RetryIfNecessary(ctx, func() error {
			for _, repo := range r {
				refs, err := imagesToCopyFromUpstream(ctx, upstreamAddr, r, upstreamCtx, regCfg.Content[contentID], log)
				if err != nil {
					return err
				}

				for _, ref := range refs[repo] {
					reposWithContentID[repo] = append(reposWithContentID[repo], struct {
						ref     types.ImageReference
						content extconf.Content
					}{
						ref:     ref,
						content: regCfg.Content[contentID],
					})
				}
			}

			return nil
		}, retryOptions); err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msg("error while getting images references from upstream, retrying...")

			return err
		}
	}

	for remoteRepo, imageList := range reposWithContentID {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			break
		}

		remoteRepoCopy := remoteRepo
		imageStore := storeController.GetImageStore(remoteRepoCopy)

		localCachePath, err := getLocalCachePath(imageStore, remoteRepoCopy)
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get localCachePath for %s", remoteRepoCopy)

			return err
		}

		if localCachePath != "" {
			defer os.RemoveAll(localCachePath)
		}

		for _, image := range imageList {
			localRepo := remoteRepoCopy
			upstreamImageRef := image.ref

			upstreamImageDigest, err := docker.GetDigest(ctx, upstreamCtx, upstreamImageRef)
			if err != nil {
				log.Error().Err(err).Msgf("couldn't get upstream image %s manifest", upstreamImageRef.DockerReference())

				return err
			}

			tag := getTagFromRef(upstreamImageRef, log).Tag()
			// get upstream signatures
			cosignManifest, err := getCosignManifest(httpClient, *registryURL, remoteRepoCopy,
				upstreamImageDigest.String(), log)
			if err != nil && !errors.Is(err, zerr.ErrSyncSignatureNotFound) {
				log.Error().Err(err).Msgf("couldn't get upstream image %s cosign manifest", upstreamImageRef.DockerReference())

				return err
			}

			refs, err := getNotaryRefs(httpClient, *registryURL, remoteRepoCopy, upstreamImageDigest.String(), log)
			if err != nil && !errors.Is(err, zerr.ErrSyncSignatureNotFound) {
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

			skipImage, err := canSkipImage(localRepo, tag, upstreamImageDigest.String(), imageStore, log)
			if err != nil {
				log.Error().Err(err).Msgf("couldn't check if the upstream image %s can be skipped",
					upstreamImageRef.DockerReference())

				return err
			}

			// sync only differences
			if skipImage {
				log.Info().Msgf("already synced image %s, checking its signatures", upstreamImageRef.DockerReference())

				skipNotarySig, err := canSkipNotarySignature(localRepo, tag, upstreamImageDigest.String(),
					refs, imageStore, log)
				if err != nil {
					log.Error().Err(err).Msgf("couldn't check if the upstream image %s notary signature can be skipped",
						upstreamImageRef.DockerReference())
				}

				if !skipNotarySig {
					if err = retry.RetryIfNecessary(ctx, func() error {
						err = syncNotarySignature(httpClient, imageStore, *registryURL, localRepo, remoteRepoCopy,
							upstreamImageDigest.String(), refs, log)

						return err
					}, retryOptions); err != nil {
						log.Error().Err(err).Msgf("couldn't copy notary signature for %s", upstreamImageRef.DockerReference())
					}
				}

				skipCosignSig, err := canSkipCosignSignature(localRepo, tag, upstreamImageDigest.String(),
					cosignManifest, imageStore, log)
				if err != nil {
					log.Error().Err(err).Msgf("couldn't check if the upstream image %s cosign signature can be skipped",
						upstreamImageRef.DockerReference())
				}

				if !skipCosignSig {
					if err = retry.RetryIfNecessary(ctx, func() error {
						err = syncCosignSignature(httpClient, imageStore, *registryURL, localRepo, remoteRepoCopy,
							upstreamImageDigest.String(), cosignManifest, log)

						return err
					}, retryOptions); err != nil {
						log.Error().Err(err).Msgf("couldn't copy cosign signature for %s", upstreamImageRef.DockerReference())
					}
				}

				continue
			}

			localImageRef, err := getLocalImageRef(localCachePath, localRepo, tag)
			if err != nil {
				log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
					localCachePath, localRepo, tag)

				return err
			}

			log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

			if err = retry.RetryIfNecessary(ctx, func() error {
				_, err = copy.Image(ctx, policyCtx, localImageRef, upstreamImageRef, &options)

				return err
			}, retryOptions); err != nil {
				log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("error while copying image %s to %s",
					upstreamImageRef.DockerReference(), localCachePath)

				return err
			}
			// push from cache to repo
			err = pushSyncedLocalImage(localRepo, tag, localCachePath, imageStore, log)
			if err != nil {
				log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("error while pushing synced cached image %s",
					fmt.Sprintf("%s/%s:%s", localCachePath, localRepo, tag))

				return err
			}

			refs, err = getNotaryRefs(httpClient, *registryURL, remoteRepoCopy, upstreamImageDigest.String(), log)
			if err = retry.RetryIfNecessary(ctx, func() error {
				err = syncNotarySignature(httpClient, imageStore, *registryURL, localRepo,
					remoteRepoCopy, upstreamImageDigest.String(), refs, log)

				return err
			}, retryOptions); err != nil {
				log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("couldn't copy notary signature for %s", upstreamImageRef.DockerReference())
			}

			cosignManifest, err = getCosignManifest(httpClient, *registryURL, remoteRepoCopy,
				upstreamImageDigest.String(), log)
			if err = retry.RetryIfNecessary(ctx, func() error {
				err = syncCosignSignature(httpClient, imageStore, *registryURL, localRepo,
					remoteRepoCopy, upstreamImageDigest.String(), cosignManifest, log)

				return err
			}, retryOptions); err != nil {
				log.Error().Str("errorType", TypeOf(err)).
					Err(err).Msgf("couldn't copy cosign signature for %s", upstreamImageRef.DockerReference())
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
		log.Error().Str("errorType", TypeOf(err)).
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
			logger.Error().Str("errortype", TypeOf(err)).
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
						logger.Error().Str("errortype", TypeOf(err)).
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
