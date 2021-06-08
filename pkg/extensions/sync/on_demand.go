package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/anuvu/zot/pkg/log"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
)

func OneImage(cfg Config, log log.Logger,
	address, port, serverCert, serverKey, caCert, repoName, tag string) (bool, error) {
	localCtx, policyCtx, err := getLocalContexts(serverCert, serverKey, caCert, log)
	if err != nil {
		return false, err
	}

	localRegistryName := strings.Replace(fmt.Sprintf("%s:%s", address, port), "0.0.0.0", "127.0.0.1", 1)

	var credentialsFile CredentialsFile

	if cfg.CredentialsFile != "" {
		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)
			return false, err
		}
	}

	var synced bool

	for _, regCfg := range cfg.Registries {
		if !regCfg.OnDemand {
			log.Info().Msgf("skipping syncing on demand from %s, onDemand flag is false", regCfg.URL)
			continue
		}

		registryConfig := regCfg
		log.Info().Msgf("syncing on demand with %s", registryConfig.URL)

		upstreamRegistryName := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

		upstreamCtx := getUpstreamContext(&registryConfig, credentialsFile[upstreamRegistryName])

		upstreamRepoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", upstreamRegistryName, repoName))

		upstreamTaggedRef, err := reference.WithTag(upstreamRepoRef, tag)
		if err != nil {
			log.Err(err).Msgf("error creating a reference for repository %s and tag %q", upstreamRepoRef.Name(), tag)
			return synced, err
		}

		upstreamRef, err := docker.NewReference(upstreamTaggedRef)
		ref := strings.Replace(upstreamRef.DockerReference().String(), upstreamRegistryName, "", 1)

		localRef, err := docker.Transport.ParseReference(
			fmt.Sprintf("//%s%s", localRegistryName, ref),
		)
		if err != nil {
			return synced, err
		}

		log.Info().Msgf("copying image %s to %s", upstreamRef.DockerReference().Name(), localRef.DockerReference().Name())

		options := getCopyOptions(upstreamCtx, localCtx)

		retryOptions := &retry.RetryOptions{
			MaxRetry: maxRetries,
		}

		if err = retry.RetryIfNecessary(context.Background(), func() error {
			_, err = copy.Image(context.Background(), policyCtx, localRef, upstreamRef, &options)
			return err
		}, retryOptions); err != nil {
			log.Error().Err(err).Msgf("error while copying image %s to %s",
				upstreamRef.DockerReference().Name(), localRef.DockerReference().Name())
		} else {
			log.Info().Msgf("successfully synced %s", upstreamRef.DockerReference().Name())
			synced = true

			return synced, nil
		}
	}

	return synced, nil
}
