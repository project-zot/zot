package sync

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type syncContextUtils struct {
	policyCtx    *signature.PolicyContext
	localCtx     *types.SystemContext
	upstreamCtx  *types.SystemContext
	upstreamAddr string
	copyOptions  copy.Options
}

//nolint:gochecknoglobals
var demandedImgs demandedImages

type demandedImages struct {
	syncedMap sync.Map
}

func (di *demandedImages) loadOrStoreChan(key string, value chan error) (chan error, bool) {
	val, found := di.syncedMap.LoadOrStore(key, value)
	errChannel, _ := val.(chan error)

	return errChannel, found
}

func (di *demandedImages) loadOrStoreStr(key, value string) (string, bool) {
	val, found := di.syncedMap.LoadOrStore(key, value)
	str, _ := val.(string)

	return str, found
}

func (di *demandedImages) delete(key string) {
	di.syncedMap.Delete(key)
}

func OneImage(ctx context.Context, cfg Config, storeController storage.StoreController,
	repo, reference string, isArtifact bool, log log.Logger,
) error {
	// guard against multiple parallel requests
	demandedImage := fmt.Sprintf("%s:%s", repo, reference)
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

	go syncOneImage(ctx, imageChannel, cfg, storeController, repo, reference, isArtifact, log)

	err, ok := <-imageChannel
	if !ok {
		return nil
	}

	return err
}

func syncOneImage(ctx context.Context, imageChannel chan error, cfg Config, storeController storage.StoreController,
	localRepo, reference string, isArtifact bool, log log.Logger,
) {
	var credentialsFile CredentialsFile

	if cfg.CredentialsFile != "" {
		var err error

		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get registry credentials from %s", cfg.CredentialsFile)

			imageChannel <- err

			return
		}
	}

	localCtx, policyCtx, err := getLocalContexts(log)
	if err != nil {
		imageChannel <- err

		return
	}

	for _, registryCfg := range cfg.Registries {
		regCfg := registryCfg
		if !regCfg.OnDemand {
			log.Info().Msgf("skipping syncing on demand from %v, onDemand flag is false", regCfg.URLs)

			continue
		}

		upstreamRepo := localRepo

		// if content config is not specified, then don't filter, just sync demanded image
		if len(regCfg.Content) != 0 {
			contentID, err := findRepoMatchingContentID(localRepo, regCfg.Content)
			if err != nil {
				log.Info().Msgf("skipping syncing on demand %s from %v registry because it's filtered out by content config",
					localRepo, regCfg.URLs)

				continue
			}

			upstreamRepo = getRepoSource(localRepo, regCfg.Content[contentID])
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

			httpClient, registryURL, err := getHTTPClient(&regCfg, upstreamURL, credentialsFile[upstreamAddr], log)
			if err != nil {
				imageChannel <- err

				return
			}

			sig := newSignaturesCopier(httpClient, *registryURL, storeController, log)

			upstreamCtx := getUpstreamContext(&regCfg, credentialsFile[upstreamAddr])
			options := getCopyOptions(upstreamCtx, localCtx)

			// demanded 'image' is a signature
			if isCosignTag(reference) {
				// at tis point we should already have images synced, but not their signatures.
				// is cosign signature
				cosignManifest, err := sig.getCosignManifest(upstreamRepo, reference)
				if err != nil {
					log.Error().Str("errorType", TypeOf(err)).
						Err(err).Msgf("couldn't get upstream image %s:%s:%s cosign manifest", upstreamURL, upstreamRepo, reference)

					continue
				}

				err = sig.syncCosignSignature(localRepo, upstreamRepo, reference, cosignManifest)
				if err != nil {
					log.Error().Str("errorType", TypeOf(err)).
						Err(err).Msgf("couldn't copy upstream image cosign signature %s/%s:%s", upstreamURL, upstreamRepo, reference)

					continue
				}

				imageChannel <- nil

				return
			} else if isArtifact {
				// is notary signature
				refs, err := sig.getNotaryRefs(upstreamRepo, reference)
				if err != nil {
					log.Error().Str("errorType", TypeOf(err)).
						Err(err).Msgf("couldn't get upstream image %s/%s:%s notary references", upstreamURL, upstreamRepo, reference)

					continue
				}

				err = sig.syncNotarySignature(localRepo, upstreamRepo, reference, refs)
				if err != nil {
					log.Error().Str("errorType", TypeOf(err)).
						Err(err).Msgf("couldn't copy image signature %s/%s:%s", upstreamURL, upstreamRepo, reference)

					continue
				}

				imageChannel <- nil

				return
			}

			syncContextUtils := syncContextUtils{
				policyCtx:    policyCtx,
				localCtx:     localCtx,
				upstreamCtx:  upstreamCtx,
				upstreamAddr: upstreamAddr,
				copyOptions:  options,
			}

			skipped, copyErr := syncRun(regCfg, localRepo, upstreamRepo, reference, syncContextUtils, sig, log)
			if skipped {
				continue
			}

			// key used to check if we already have a go routine syncing this image
			demandedImageRef := fmt.Sprintf("%s/%s:%s", upstreamAddr, upstreamRepo, reference)

			if copyErr != nil {
				// don't retry in background if maxretry is 0
				if retryOptions.MaxRetry == 0 {
					continue
				}

				_, found := demandedImgs.loadOrStoreStr(demandedImageRef, "")
				if found {
					log.Info().Msgf("image %s already demanded in background", demandedImageRef)
					/* we already have a go routine spawned for this image
					or retryOptions is not configured */
					continue
				}

				// spawn goroutine to later pull the image
				go func() {
					// remove image after syncing
					defer func() {
						demandedImgs.delete(demandedImageRef)
						log.Info().Msgf("sync routine: %s exited", demandedImageRef)
					}()

					log.Info().Msgf("sync routine: starting routine to copy image %s, cause err: %v",
						demandedImageRef, copyErr)
					time.Sleep(retryOptions.Delay)

					if err = retry.RetryIfNecessary(ctx, func() error {
						_, err := syncRun(regCfg, localRepo, upstreamRepo, reference, syncContextUtils, sig, log)

						return err
					}, retryOptions); err != nil {
						log.Error().Str("errorType", TypeOf(err)).
							Err(err).Msgf("sync routine: error while copying image %s", demandedImageRef)
					}
				}()
			} else {
				imageChannel <- nil

				return
			}
		}
	}

	imageChannel <- nil
}

func syncRun(regCfg RegistryConfig,
	localRepo, upstreamRepo, reference string, utils syncContextUtils, sig *signaturesCopier,
	log log.Logger,
) (bool, error) {
	upstreamImageDigest, refIsDigest := parseDigest(reference)

	upstreamImageRef, err := getImageRef(utils.upstreamAddr, upstreamRepo, reference)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("error creating docker reference for repository %s/%s:%s",
			utils.upstreamAddr, upstreamRepo, reference)

		return false, err
	}

	if !refIsDigest {
		upstreamImageDigest, err = docker.GetDigest(context.Background(), utils.upstreamCtx, upstreamImageRef)
		if err != nil {
			log.Error().Str("errorType", TypeOf(err)).
				Err(err).Msgf("couldn't get upstream image %s manifest", upstreamImageRef.DockerReference())

			return false, err
		}
	}

	// get upstream signatures
	cosignManifest, err := sig.getCosignManifest(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't get upstream image %s cosign manifest", upstreamImageRef.DockerReference())
	}

	refs, err := sig.getNotaryRefs(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't get upstream image %s notary references", upstreamImageRef.DockerReference())
	}

	// check if upstream image is signed
	if cosignManifest == nil && len(refs.References) == 0 {
		// upstream image not signed
		if regCfg.OnlySigned != nil && *regCfg.OnlySigned {
			// skip unsigned images
			log.Info().Msgf("skipping image without signature %s", upstreamImageRef.DockerReference())

			return true, nil
		}
	}

	imageStore := sig.storeController.GetImageStore(localRepo)

	localCachePath, err := getLocalCachePath(imageStore, localRepo)
	if err != nil {
		log.Error().Err(err).Msgf("couldn't get localCachePath for %s", localRepo)
	}

	localImageRef, err := getLocalImageRef(localCachePath, localRepo, reference)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
			localCachePath, localRepo, reference)

		return false, err
	}

	defer os.RemoveAll(localCachePath)

	log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

	_, err = copy.Image(context.Background(), utils.policyCtx, localImageRef, upstreamImageRef, &utils.copyOptions)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("error encountered while syncing on demand %s to %s",
			upstreamImageRef.DockerReference(), localCachePath)

		return false, err
	}

	err = pushSyncedLocalImage(localRepo, reference, localCachePath, imageStore, log)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("error while pushing synced cached image %s",
			fmt.Sprintf("%s/%s:%s", localCachePath, localRepo, reference))

		return false, err
	}

	err = sig.syncCosignSignature(localRepo, upstreamRepo, upstreamImageDigest.String(), cosignManifest)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't copy image cosign signature %s/%s:%s", utils.upstreamAddr, upstreamRepo, reference)

		return false, err
	}

	err = sig.syncNotarySignature(localRepo, upstreamRepo, upstreamImageDigest.String(), refs)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't copy image notary signature %s/%s:%s", utils.upstreamAddr, upstreamRepo, reference)

		return false, err
	}

	log.Info().Msgf("successfully synced %s/%s:%s", utils.upstreamAddr, upstreamRepo, reference)

	return false, nil
}
