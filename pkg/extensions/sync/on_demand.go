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
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/common"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

const (
	OrasArtifact = "orasArtifact"
	OCIReference = "ociReference"
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

func OneImage(ctx context.Context, cfg extconf.SyncConfig, storeController storage.StoreController,
	repo, reference string, artifactType string, log log.Logger,
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

	go syncOneImage(ctx, imageChannel, cfg, storeController, repo, reference, artifactType, log)

	err, ok := <-imageChannel
	if !ok {
		return nil
	}

	return err
}

func syncOneImage(ctx context.Context, imageChannel chan error,
	cfg extconf.SyncConfig, storeController storage.StoreController,
	localRepo, reference string, artifactType string, log log.Logger,
) {
	var credentialsFile extconf.CredentialsFile

	if cfg.CredentialsFile != "" {
		var err error

		credentialsFile, err = getFileCredentials(cfg.CredentialsFile)
		if err != nil {
			log.Error().Str("errorType", common.TypeOf(err)).
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

			var TLSverify bool

			if regCfg.TLSVerify != nil && *regCfg.TLSVerify {
				TLSverify = true
			}

			registryURL, err := url.Parse(upstreamURL)
			if err != nil {
				log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("url", upstreamURL).Msg("couldn't parse url")
				imageChannel <- err

				return
			}

			httpClient, err := common.CreateHTTPClient(TLSverify, registryURL.Host, regCfg.CertDir)
			if err != nil {
				imageChannel <- err

				return
			}

			sig := newSignaturesCopier(httpClient, credentialsFile[upstreamAddr], *registryURL, storeController, log)

			upstreamCtx := getUpstreamContext(&regCfg, credentialsFile[upstreamAddr])
			options := getCopyOptions(upstreamCtx, localCtx)

			/* demanded object is a signature or artifact
			at tis point we already have images synced, but not their signatures. */
			if isCosignTag(reference) || artifactType != "" {
				err = syncSignaturesArtifacts(sig, localRepo, upstreamRepo, reference, artifactType)
				if err != nil {
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
			//nolint:contextcheck
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
						log.Error().Str("errorType", common.TypeOf(err)).
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

func syncRun(regCfg extconf.RegistryConfig,
	localRepo, upstreamRepo, reference string, utils syncContextUtils, sig *signaturesCopier,
	log log.Logger,
) (bool, error) {
	upstreamImageDigest, refIsDigest := parseReference(reference)

	upstreamImageRef, err := getImageRef(utils.upstreamAddr, upstreamRepo, reference)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("error creating docker reference for repository %s/%s:%s",
			utils.upstreamAddr, upstreamRepo, reference)

		return false, err
	}

	manifestBuf, mediaType, err := getImageRefManifest(context.Background(), utils.upstreamCtx, upstreamImageRef, log)
	if err != nil {
		return false, err
	}

	if !refIsDigest {
		upstreamImageDigest = digest.FromBytes(manifestBuf)
	}

	if !isSupportedMediaType(mediaType) {
		if mediaType == ispec.MediaTypeArtifactManifest {
			err = sig.syncOCIArtifact(localRepo, upstreamRepo, reference, manifestBuf)
			if err != nil {
				return false, err
			}
		}

		return false, nil
	}

	// get upstream signatures
	cosignManifest, err := sig.getCosignManifest(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't get upstream image %s cosign manifest", upstreamImageRef.DockerReference())
	}

	refs, err := sig.getNotaryRefs(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
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
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't obtain a valid image reference for reference %s/%s:%s",
			localCachePath, localRepo, reference)

		return false, err
	}

	defer os.RemoveAll(localCachePath)

	log.Info().Msgf("copying image %s to %s", upstreamImageRef.DockerReference(), localCachePath)

	_, err = copy.Image(context.Background(), utils.policyCtx, localImageRef, upstreamImageRef, &utils.copyOptions)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("error encountered while syncing on demand %s to %s",
			upstreamImageRef.DockerReference(), localCachePath)

		return false, err
	}

	err = pushSyncedLocalImage(localRepo, reference, localCachePath, imageStore, log)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("error while pushing synced cached image %s",
			fmt.Sprintf("%s/%s:%s", localCachePath, localRepo, reference))

		return false, err
	}

	index, err := sig.getOCIRefs(upstreamRepo, upstreamImageDigest.String())
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't get upstream image %s oci references", upstreamImageRef.DockerReference())
	}

	err = sig.syncOCIRefs(localRepo, upstreamRepo, upstreamImageDigest.String(), index)
	if err != nil {
		return false, err
	}

	err = sig.syncCosignSignature(localRepo, upstreamRepo, upstreamImageDigest.String(), cosignManifest)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't copy image cosign signature %s/%s:%s", utils.upstreamAddr, upstreamRepo, reference)

		return false, err
	}

	err = sig.syncNotaryRefs(localRepo, upstreamRepo, upstreamImageDigest.String(), refs)
	if err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msgf("couldn't copy image notary signature %s/%s:%s", utils.upstreamAddr, upstreamRepo, reference)

		return false, err
	}

	log.Info().Msgf("successfully synced %s/%s:%s", utils.upstreamAddr, upstreamRepo, reference)

	return false, nil
}

func syncSignaturesArtifacts(sig *signaturesCopier, localRepo, upstreamRepo, reference, artifactType string) error {
	upstreamURL := sig.upstreamURL.String()

	switch {
	case isCosignTag(reference):
		// is cosign signature
		cosignManifest, err := sig.getCosignManifest(upstreamRepo, reference)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get upstream image %s:%s:%s cosign manifest", upstreamURL, upstreamRepo, reference)

			return err
		}

		err = sig.syncCosignSignature(localRepo, upstreamRepo, reference, cosignManifest)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't copy upstream image cosign signature %s/%s:%s", upstreamURL, upstreamRepo, reference)

			return err
		}
	case artifactType == OrasArtifact:
		// is notary signature
		refs, err := sig.getNotaryRefs(upstreamRepo, reference)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get upstream image %s/%s:%s notary references", upstreamURL, upstreamRepo, reference)

			return err
		}

		err = sig.syncNotaryRefs(localRepo, upstreamRepo, reference, refs)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't copy image signature %s/%s:%s", upstreamURL, upstreamRepo, reference)

			return err
		}
	case artifactType == OCIReference:
		index, err := sig.getOCIRefs(upstreamRepo, reference)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't get oci references %s/%s:%s", upstreamURL, upstreamRepo, reference)

			return err
		}

		err = sig.syncOCIRefs(localRepo, upstreamRepo, reference, index)
		if err != nil {
			sig.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msgf("couldn't copy oci references %s/%s:%s", upstreamURL, upstreamRepo, reference)

			return err
		}
	}

	return nil
}
