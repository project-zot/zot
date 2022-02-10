package sync

import (
	"context"
	"encoding/json"
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
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	SyncBlobUploadDir = ".sync"
)

// /v2/_catalog struct.
type catalog struct {
	Repositories []string `json:"repositories"`
}

// key is registry address.
type CredentialsFile map[string]Credentials

type Credentials struct {
	Username string
	Password string
}

type Config struct {
	Enable          *bool
	CredentialsFile string
	Registries      []RegistryConfig
}

type RegistryConfig struct {
	URLs         []string
	PollInterval time.Duration
	Content      []Content
	TLSVerify    *bool
	OnDemand     bool
	CertDir      string
	MaxRetries   *int
	RetryDelay   *time.Duration
}

type Content struct {
	Prefix string
	Tags   *Tags
}

type Tags struct {
	Regex  *string
	Semver *bool
}

// getUpstreamCatalog gets all repos from a registry.
func getUpstreamCatalog(client *resty.Client, upstreamURL string, log log.Logger) (catalog, error) {
	var c catalog

	registryCatalogURL := fmt.Sprintf("%s%s", upstreamURL, "/v2/_catalog")

	resp, err := client.R().SetHeader("Content-Type", "application/json").Get(registryCatalogURL)
	if err != nil {
		log.Err(err).Msgf("couldn't query %s", registryCatalogURL)

		return c, err
	}

	if resp.IsError() {
		log.Error().Msgf("couldn't query %s, status code: %d, body: %s", registryCatalogURL,
			resp.StatusCode(), resp.Body())

		return c, errors.ErrSyncMissingCatalog
	}

	err = json.Unmarshal(resp.Body(), &c)
	if err != nil {
		log.Err(err).Str("body", string(resp.Body())).Msg("couldn't unmarshal registry's catalog")

		return c, err
	}

	return c, nil
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
func filterImagesByTagRegex(upstreamReferences *[]types.ImageReference, content Content, log log.Logger) error {
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
func filterImagesBySemver(upstreamReferences *[]types.ImageReference, content Content, log log.Logger) {
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
	upstreamCtx *types.SystemContext, content Content, log log.Logger) ([]types.ImageReference, error) {
	var upstreamReferences []types.ImageReference

	for _, repoName := range repos {
		repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, repoName))
		if err != nil {
			log.Error().Err(err).Msgf("couldn't parse repository reference: %s", repoRef)

			return nil, err
		}

		tags, err := getImageTags(ctx, upstreamCtx, repoRef)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't fetch tags for %s", repoRef)

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

			upstreamReferences = append(upstreamReferences, ref)
		}
	}

	log.Debug().Msgf("upstream refs to be copied: %v", upstreamReferences)

	err := filterImagesByTagRegex(&upstreamReferences, content, log)
	if err != nil {
		return []types.ImageReference{}, err
	}

	log.Debug().Msgf("remaining upstream refs to be copied: %v", upstreamReferences)

	filterImagesBySemver(&upstreamReferences, content, log)

	log.Debug().Msgf("remaining upstream refs to be copied: %v", upstreamReferences)

	return upstreamReferences, nil
}

func getCopyOptions(upstreamCtx, localCtx *types.SystemContext) copy.Options {
	options := copy.Options{
		DestinationCtx:        localCtx,
		SourceCtx:             upstreamCtx,
		ReportWriter:          io.Discard,
		ForceManifestMIMEType: ispec.MediaTypeImageManifest, // force only oci manifest MIME type
	}

	return options
}

func getUpstreamContext(regCfg *RegistryConfig, credentials Credentials) *types.SystemContext {
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

	if credentials != (Credentials{}) {
		upstreamCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: credentials.Username,
			Password: credentials.Password,
		}
	}

	return upstreamCtx
}

func syncRegistry(ctx context.Context, regCfg RegistryConfig, upstreamURL string,
	storeController storage.StoreController, localCtx *types.SystemContext,
	policyCtx *signature.PolicyContext, credentials Credentials, log log.Logger) error {
	log.Info().Msgf("syncing registry: %s", upstreamURL)

	var err error

	log.Debug().Msg("getting upstream context")

	upstreamCtx := getUpstreamContext(&regCfg, credentials)
	options := getCopyOptions(upstreamCtx, localCtx)

	retryOptions := &retry.RetryOptions{}

	if regCfg.MaxRetries != nil {
		retryOptions.MaxRetry = *regCfg.MaxRetries
		if regCfg.RetryDelay != nil {
			retryOptions.Delay = *regCfg.RetryDelay
		}
	}

	var catalog catalog

	httpClient, err := getHTTPClient(&regCfg, upstreamURL, credentials, log)
	if err != nil {
		return err
	}

	if err = retry.RetryIfNecessary(ctx, func() error {
		catalog, err = getUpstreamCatalog(httpClient, upstreamURL, log)

		return err
	}, retryOptions); err != nil {
		log.Error().Err(err).Msg("error while getting upstream catalog, retrying...")

		return err
	}

	log.Info().Msgf("filtering %d repos based on sync prefixes", len(catalog.Repositories))

	repos := filterRepos(catalog.Repositories, regCfg.Content, log)

	log.Info().Msgf("got repos: %v", repos)

	var images []types.ImageReference

	upstreamAddr := StripRegistryTransport(upstreamURL)

	for contentID, repos := range repos {
		r := repos
		id := contentID

		if err = retry.RetryIfNecessary(ctx, func() error {
			refs, err := imagesToCopyFromUpstream(ctx, upstreamAddr, r, upstreamCtx, regCfg.Content[id], log)
			images = append(images, refs...)

			return err
		}, retryOptions); err != nil {
			log.Error().Err(err).Msg("error while getting images references from upstream, retrying...")

			return err
		}
	}

	if len(images) == 0 {
		log.Info().Msg("no images to copy, no need to sync")

		return nil
	}

	for _, ref := range images {
		upstreamImageRef := ref

		repo := getRepoFromRef(upstreamImageRef, upstreamAddr)
		tag := getTagFromRef(upstreamImageRef, log).Tag()

		imageStore := storeController.GetImageStore(repo)

		canBeSkipped, err := canSkipImage(ctx, repo, tag, upstreamImageRef, imageStore, upstreamCtx, log)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't check if the upstream image %s can be skipped",
				upstreamImageRef.DockerReference())
		}

		if canBeSkipped {
			continue
		}

		localImageRef, localCachePath, err := getLocalImageRef(imageStore, repo, tag)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
				localCachePath, repo, tag)

			return err
		}

		defer os.RemoveAll(localCachePath)

		log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

		if err = retry.RetryIfNecessary(ctx, func() error {
			_, err = copy.Image(ctx, policyCtx, localImageRef, upstreamImageRef, &options)

			return err
		}, retryOptions); err != nil {
			log.Error().Err(err).Msgf("error while copying image %s to %s",
				upstreamImageRef.DockerReference(), localCachePath)

			return err
		}

		err = pushSyncedLocalImage(repo, tag, localCachePath, storeController, log)
		if err != nil {
			log.Error().Err(err).Msgf("error while pushing synced cached image %s",
				fmt.Sprintf("%s/%s:%s", localCachePath, repo, tag))

			return err
		}

		if err = retry.RetryIfNecessary(ctx, func() error {
			err = syncSignatures(httpClient, storeController, upstreamURL, repo, tag, log)

			return err
		}, retryOptions); err != nil {
			log.Error().Err(err).Msgf("couldn't copy image signature %s", upstreamImageRef.DockerReference())
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
		log.Error().Err(err).Msg("couldn't create policy context")

		return &types.SystemContext{}, &signature.PolicyContext{}, err
	}

	return localCtx, policyContext, nil
}

func Run(ctx context.Context, cfg Config, storeController storage.StoreController,
	wtgrp *goSync.WaitGroup, logger log.Logger) error {
	var credentialsFile CredentialsFile

	var err error

	if cfg.CredentialsFile != "" {
		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			logger.Error().Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)

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

		// fork a new zerolog child to avoid data race
		tlogger := log.Logger{Logger: logger.With().Caller().Timestamp().Logger()}

		// schedule each registry sync
		go func(ctx context.Context, regCfg RegistryConfig, logger log.Logger) {
			for {
				// increment reference since will be busy, so shutdown has to wait
				wtgrp.Add(1)

				for _, upstreamURL := range regCfg.URLs {
					upstreamAddr := StripRegistryTransport(upstreamURL)
					// first try syncing main registry
					if err := syncRegistry(ctx, regCfg, upstreamURL, storeController, localCtx, policyCtx,
						credentialsFile[upstreamAddr], logger); err != nil {
						logger.Error().Err(err).Str("registry", upstreamURL).
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
		}(ctx, regCfg, tlogger)
	}

	logger.Info().Msg("finished setting up sync")

	return nil
}
