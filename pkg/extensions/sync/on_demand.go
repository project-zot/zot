package sync

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// nolint: gochecknoglobals
var demandedImgs demandedImages

type demandedImages struct {
	syncedMap sync.Map
}

func (di *demandedImages) loadOrStoreChan(key string, value chan error) (chan error, bool) {
	val, found := di.syncedMap.LoadOrStore(key, value)
	errChannel, _ := val.(chan error)

	return errChannel, found
}

func (di *demandedImages) loadOrStoreStr(key string, value string) (string, bool) {
	val, found := di.syncedMap.LoadOrStore(key, value)
	str, _ := val.(string)

	return str, found
}

func (di *demandedImages) delete(key string) {
	di.syncedMap.Delete(key)
}

func OneImage(cfg Config, storeController storage.StoreController,
	repo, tag string, isArtifact bool, log log.Logger) error {
	// guard against multiple parallel requests
	demandedImage := fmt.Sprintf("%s:%s", repo, tag)
	// loadOrStore image-based channel
	imageChannel, found := demandedImgs.loadOrStoreChan(demandedImage, make(chan error))
	// if value found wait on channel receive or close
	if found {
		log.Info().Msgf("image %s already demanded by another client, waiting on imageChannel", demandedImage)

		err, ok := <-imageChannel
		// if channel closed exit
		if !ok {
			return nil
		}

		return err
	}

	defer demandedImgs.delete(demandedImage)
	defer close(imageChannel)

	go syncOneImage(imageChannel, cfg, storeController, repo, tag, isArtifact, log)

	err, ok := <-imageChannel
	if !ok {
		return nil
	}

	return err
}

func syncOneImage(imageChannel chan error, cfg Config, storeController storage.StoreController,
	localRepo, tag string, isArtifact bool, log log.Logger) {
	var credentialsFile CredentialsFile

	if cfg.CredentialsFile != "" {
		var err error

		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			log.Error().Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)

			imageChannel <- err

			return
		}
	}

	var copyErr error

	localCtx, policyCtx, err := getLocalContexts(log)
	if err != nil {
		imageChannel <- err

		return
	}

	imageStore := storeController.GetImageStore(localRepo)

	for _, registryCfg := range cfg.Registries {
		regCfg := registryCfg
		if !regCfg.OnDemand {
			log.Info().Msgf("skipping syncing on demand from %v, onDemand flag is false", regCfg.URLs)

			continue
		}

		remoteRepo := localRepo

		// if content config is not specified, then don't filter, just sync demanded image
		if len(regCfg.Content) != 0 {
			contentID, err := findRepoMatchingContentID(localRepo, regCfg.Content)
			if err != nil {
				log.Info().Msgf("skipping syncing on demand %s from %v registry because it's filtered out by content config",
					localRepo, regCfg.URLs)

				continue
			}

			remoteRepo = getRepoSource(localRepo, regCfg.Content[contentID])
		}

		retryOptions := &retry.RetryOptions{}

		if regCfg.MaxRetries != nil {
			retryOptions.MaxRetry = *regCfg.MaxRetries
			if regCfg.RetryDelay != nil {
				retryOptions.Delay = *regCfg.RetryDelay
			}
		}

		log.Info().Msgf("syncing on demand with %v", regCfg.URLs)

		for _, regCfgURL := range regCfg.URLs {
			upstreamURL := regCfgURL

			upstreamAddr := StripRegistryTransport(upstreamURL)

			httpClient, err := getHTTPClient(&regCfg, upstreamURL, credentialsFile[upstreamAddr], log)
			if err != nil {
				imageChannel <- err

				return
			}

			// demanded 'image' is a signature
			if isCosignTag(tag) || isArtifact {
				// at tis point we should already have images synced, but not their signatures.
				regURL, err := url.Parse(upstreamURL)
				if err != nil {
					log.Error().Err(err).Msgf("couldn't parse registry URL: %s", upstreamURL)

					imageChannel <- err

					return
				}

				// is notary signature
				if isArtifact {
					err = syncNotarySignature(httpClient, storeController, *regURL, remoteRepo, localRepo, tag, log)
					if err != nil {
						log.Error().Err(err).Msgf("couldn't copy image signature %s/%s:%s", upstreamURL, localRepo, tag)

						continue
					}

					imageChannel <- nil

					return
				}
				// is cosign signature
				err = syncCosignSignature(httpClient, storeController, *regURL, remoteRepo, localRepo, tag, log)
				if err != nil {
					log.Error().Err(err).Msgf("couldn't copy image signature %s/%s:%s", upstreamURL, localRepo, tag)

					continue
				}

				imageChannel <- nil

				return
			}

			// it's an image
			upstreamCtx := getUpstreamContext(&regCfg, credentialsFile[upstreamAddr])
			options := getCopyOptions(upstreamCtx, localCtx)

			upstreamImageRef, err := getImageRef(upstreamAddr, remoteRepo, tag)
			if err != nil {
				log.Error().Err(err).Msgf("error creating docker reference for repository %s/%s:%s",
					upstreamAddr, remoteRepo, tag)

				imageChannel <- err

				return
			}

			localImageRef, localCachePath, err := getLocalImageRef(imageStore, localRepo, tag)
			if err != nil {
				log.Error().Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
					localCachePath, localRepo, tag)

				imageChannel <- err

				return
			}

			log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

			demandedImageRef := fmt.Sprintf("%s/%s:%s", upstreamAddr, remoteRepo, tag)

			_, copyErr = copy.Image(context.Background(), policyCtx, localImageRef, upstreamImageRef, &options)
			if copyErr != nil {
				log.Error().Err(err).Msgf("error encountered while syncing on demand %s to %s",
					upstreamImageRef.DockerReference(), localCachePath)

				_, found := demandedImgs.loadOrStoreStr(demandedImageRef, "")
				if found || retryOptions.MaxRetry == 0 {
					defer os.RemoveAll(localCachePath)
					log.Info().Msgf("image %s already demanded in background or sync.registries[].MaxRetries == 0", demandedImageRef)
					/* we already have a go routine spawned for this image
					or retryOptions is not configured */
					continue
				}

				// spawn goroutine to later pull the image
				go func() {
					// remove image after syncing
					defer func() {
						_ = os.RemoveAll(localCachePath)

						demandedImgs.delete(demandedImageRef)
						log.Info().Msgf("sync routine: %s exited", demandedImageRef)
					}()

					log.Info().Msgf("sync routine: starting routine to copy image %s, cause err: %v",
						demandedImageRef, copyErr)
					time.Sleep(retryOptions.Delay)

					if err = retry.RetryIfNecessary(context.Background(), func() error {
						_, err := copy.Image(context.Background(), policyCtx, localImageRef, upstreamImageRef, &options)

						return err
					}, retryOptions); err != nil {
						log.Error().Err(err).Msgf("sync routine: error while copying image %s to %s",
							demandedImageRef, localCachePath)
					} else {
						_ = finishSyncing(localRepo, remoteRepo, tag, localCachePath, upstreamURL, storeController,
							retryOptions, httpClient, log)
					}
				}()
			} else {
				err := finishSyncing(localRepo, remoteRepo, tag, localCachePath, upstreamURL, storeController,
					retryOptions, httpClient, log)

				imageChannel <- err

				return
			}
		}
	}

	imageChannel <- err
}

// push the local image into the storage, sync signatures.
func finishSyncing(localRepo, remoteRepo, tag, localCachePath, upstreamURL string,
	storeController storage.StoreController, retryOptions *retry.RetryOptions,
	httpClient *resty.Client, log log.Logger) error {
	err := pushSyncedLocalImage(localRepo, tag, localCachePath, storeController, log)
	if err != nil {
		log.Error().Err(err).Msgf("error while pushing synced cached image %s",
			fmt.Sprintf("%s/%s:%s", localCachePath, localRepo, tag))

		return err
	}

	if err = retry.RetryIfNecessary(context.Background(), func() error {
		err = syncSignatures(httpClient, storeController, upstreamURL, remoteRepo, localRepo, tag, log)

		return err
	}, retryOptions); err != nil {
		log.Error().Err(err).Msgf("couldn't copy image signature for %s/%s:%s", upstreamURL, remoteRepo, tag)
	}

	log.Info().Msgf("successfully synced %s/%s:%s", upstreamURL, remoteRepo, tag)

	return nil
}
