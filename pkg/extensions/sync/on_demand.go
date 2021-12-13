package sync

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/oci/layout"
	guuid "github.com/gofrs/uuid"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func OneImage(cfg Config, storeController storage.StoreController,
	repo, tag string, log log.Logger) error {
	var credentialsFile CredentialsFile

	if cfg.CredentialsFile != "" {
		var err error

		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)

			return err
		}
	}

	localCtx, policyCtx, err := getLocalContexts(log)
	if err != nil {
		return err
	}

	imageStore := storeController.GetImageStore(repo)

	var copyErr error

	uuid, err := guuid.NewV4()
	if err != nil {
		return err
	}

	for _, regCfg := range cfg.Registries {
		if !regCfg.OnDemand {
			log.Info().Msgf("skipping syncing on demand from %s, onDemand flag is false", regCfg.URL)

			continue
		}

		// if content config is not specified, then don't filter, just sync demanded image
		if len(regCfg.Content) != 0 {
			repos := filterRepos([]string{repo}, regCfg.Content, log)
			if len(repos) == 0 {
				log.Info().Msgf("skipping syncing on demand %s from %s registry because it's filtered out by content config",
					repo, regCfg.URL)

				continue
			}
		}

		registryConfig := regCfg
		log.Info().Msgf("syncing on demand with %s", registryConfig.URL)

		upstreamRegistryName := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

		upstreamCtx := getUpstreamContext(&registryConfig, credentialsFile[upstreamRegistryName])

		upstreamRepoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", upstreamRegistryName, repo))
		if err != nil {
			log.Error().Err(err).Msgf("error parsing repository reference %s/%s", upstreamRegistryName, repo)

			return err
		}

		upstreamTaggedRef, err := reference.WithTag(upstreamRepoRef, tag)
		if err != nil {
			log.Error().Err(err).Msgf("error creating a reference for repository %s and tag %q",
				upstreamRepoRef.Name(), tag)

			return err
		}

		upstreamRef, err := docker.NewReference(upstreamTaggedRef)
		if err != nil {
			log.Error().Err(err).Msgf("error creating docker reference for repository %s and tag %q",
				upstreamRepoRef.Name(), tag)

			return err
		}

		imageName := strings.Replace(upstreamTaggedRef.Name(), upstreamRegistryName, "", 1)

		localRepo := path.Join(imageStore.RootDir(), imageName, SyncBlobUploadDir, uuid.String(), imageName)

		if err = os.MkdirAll(localRepo, storage.DefaultDirPerms); err != nil {
			log.Error().Err(err).Str("dir", localRepo).Msg("couldn't create temporary dir")

			return err
		}

		defer os.RemoveAll(path.Join(imageStore.RootDir(), imageName, SyncBlobUploadDir, uuid.String()))

		localTaggedRepo := fmt.Sprintf("%s:%s", localRepo, tag)

		localRef, err := layout.ParseReference(localTaggedRepo)
		if err != nil {
			log.Error().Err(err).Msgf("cannot obtain a valid image reference for reference %q", localRepo)

			return err
		}

		log.Info().Msgf("copying image %s:%s to %s", upstreamTaggedRef.Name(),
			upstreamTaggedRef.Tag(), localRepo)

		options := getCopyOptions(upstreamCtx, localCtx)

		retryOptions := &retry.RetryOptions{
			MaxRetry: maxRetries,
		}

		if err = retry.RetryIfNecessary(context.Background(), func() error {
			_, copyErr = copy.Image(context.Background(), policyCtx, localRef, upstreamRef, &options)

			return err
		}, retryOptions); copyErr != nil {
			log.Error().Err(copyErr).Msgf("error while copying image %s to %s",
				upstreamRef.DockerReference().Name(), localTaggedRepo)
		} else {
			log.Info().Msgf("successfully synced %s", upstreamRef.DockerReference().Name())

			err := pushSyncedLocalImage(repo, tag, uuid.String(), storeController, log)
			if err != nil {
				log.Error().Err(err).Msgf("error while pushing synced cached image %s",
					localTaggedRepo)

				return err
			}

			return nil
		}
	}

	return copyErr
}
