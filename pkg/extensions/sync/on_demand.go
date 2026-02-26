//go:build sync

package sync

import (
	"context"
	"errors"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

type request struct {
	repo      string
	reference string
	// used for background retries, at most one background retry per service
	serviceID    int
	isBackground bool
}

/*
BaseOnDemand tracks requests that can be an image/signature/sbom.

It keeps track of all parallel requests, if two requests of same image/signature/sbom comes at the same time,
process just the first one, also keep track of all background retrying routines.
*/
type BaseOnDemand struct {
	services []Service
	// map[request]chan err
	requestStore *sync.Map
	log          log.Logger
}

func NewOnDemand(log log.Logger) *BaseOnDemand {
	return &BaseOnDemand{log: log, requestStore: &sync.Map{}}
}

func (onDemand *BaseOnDemand) Add(service Service) {
	onDemand.services = append(onDemand.services, service)
}

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	req := request{
		repo:      repo,
		reference: reference,
	}

	syncResult := make(chan error)
	val, loaded := onDemand.requestStore.LoadOrStore(req, syncResult)

	if loaded {
		onDemand.log.Info().Str("repo", repo).Str("reference", reference).
			Msg("image already demanded, waiting on channel")

		syncResult, _ := val.(chan error)

		err := <-syncResult

		return err
	}

	defer onDemand.requestStore.Delete(req)

	go onDemand.syncImage(repo, reference, syncResult)

	err := <-syncResult

	return err
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	req := request{
		repo:      repo,
		reference: subjectDigestStr,
	}

	syncResult := make(chan error)
	val, loaded := onDemand.requestStore.LoadOrStore(req, syncResult)

	if loaded {
		onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).
			Msg("referrers for image already demanded, waiting on channel")

		syncResult, _ := val.(chan error)

		err := <-syncResult

		return err
	}

	defer onDemand.requestStore.Delete(req)

	go onDemand.syncReferrers(repo, subjectDigestStr, referenceTypes, syncResult)

	err := <-syncResult

	return err
}

func (onDemand *BaseOnDemand) SyncBlob(ctx context.Context, repo string, digest godigest.Digest) error {
	req := request{
		repo:      repo,
		reference: digest.String(),
	}

	syncResult := make(chan error)
	val, loaded := onDemand.requestStore.LoadOrStore(req, syncResult)

	if loaded {
		onDemand.log.Info().Str("repo", repo).Str("digest", digest.String()).
			Msg("blob already demanded, waiting on channel")

		syncResult, _ := val.(chan error)

		err := <-syncResult

		return err
	}

	defer onDemand.requestStore.Delete(req)

	go onDemand.syncBlob(repo, digest, syncResult)

	err := <-syncResult

	return err
}

func (onDemand *BaseOnDemand) syncReferrers(repo, subjectDigestStr string,
	referenceTypes []string, syncResult chan error,
) {
	defer close(syncResult)

	var err error

	for serviceID, service := range onDemand.services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("reference", subjectDigestStr).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg("starting on-demand referrer sync")

		// Create a detached context with timeout to ensure sync completes even if HTTP client disconnects.
		// This prevents Kubernetes timeout/retries from aborting in-progress referrer downloads.
		syncCtx, cancel := context.WithTimeout(context.Background(), timeout)
		err = service.SyncReferrers(syncCtx, repo, subjectDigestStr, referenceTypes)

		cancel()

		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) ||
				errors.Is(err, zerr.ErrRepoNotFound) ||
				// some public registries may return 401 for not found.
				errors.Is(err, zerr.ErrUnauthorizedAccess) {
				continue
			}

			req := request{
				repo:         repo,
				reference:    subjectDigestStr,
				serviceID:    serviceID,
				isBackground: true,
			}

			// if there is already a background routine, skip
			if _, requested := onDemand.requestStore.LoadOrStore(req, struct{}{}); requested {
				continue
			}

			if service.CanRetryOnError() {
				retryErr := err

				// retry in background
				go func(service Service, serviceTimeout time.Duration) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).Str("err", retryErr.Error()).
						Msg("sync routine: starting routine to copy image, because of error")

					// Use detached context with timeout for background retry
					retryCtx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
					defer cancel()

					err := service.SyncReferrers(retryCtx, repo, subjectDigestStr, referenceTypes)
					if err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", subjectDigestStr).
							Err(err).Msg("sync routine: starting routine to retry copy image due to error")
					}
				}(service, timeout)
			}
		} else {
			break
		}
	}

	syncResult <- err
}

func (onDemand *BaseOnDemand) syncImage(repo, reference string, syncResult chan error) {
	defer close(syncResult)

	var err error

	for serviceID, service := range onDemand.services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("reference", reference).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg("starting on-demand image sync")

		// Create a detached context with timeout to ensure sync completes even if HTTP client disconnects.
		// This prevents Kubernetes timeout/retries from aborting in-progress image downloads.
		syncCtx, cancel := context.WithTimeout(context.Background(), timeout)
		err = service.SyncImage(syncCtx, repo, reference)

		cancel()

		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) ||
				errors.Is(err, zerr.ErrRepoNotFound) ||
				// some public registries may return 401 for not found.
				errors.Is(err, zerr.ErrUnauthorizedAccess) {
				continue
			}

			req := request{
				repo:         repo,
				reference:    reference,
				serviceID:    serviceID,
				isBackground: true,
			}

			// if there is already a background routine, skip
			if _, requested := onDemand.requestStore.LoadOrStore(req, struct{}{}); requested {
				continue
			}

			if service.CanRetryOnError() {
				retryErr := err

				// retry in background
				go func(service Service, serviceTimeout time.Duration) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", reference).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str("reference", reference).Str("err", retryErr.Error()).
						Msg("sync routine: starting routine to retry copy image due to error")

					// Use detached context with timeout for background retry
					retryCtx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
					defer cancel()

					err := service.SyncImage(retryCtx, repo, reference)
					if err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
							Err(err).Msg("sync routine: error while copying image")
					}
				}(service, timeout)
			}
		} else {
			break
		}
	}

	syncResult <- err
}

func (onDemand *BaseOnDemand) syncBlob(repo string, digest godigest.Digest, syncResult chan error) {
	defer close(syncResult)

	var err error

	for serviceID, service := range onDemand.services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("digest", digest.String()).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg("starting on-demand blob sync")

		// Create a detached context with timeout to ensure sync completes even if HTTP client disconnects.
		syncCtx, cancel := context.WithTimeout(context.Background(), timeout)
		err = service.SyncBlob(syncCtx, repo, digest)

		cancel()

		if err != nil {
			if errors.Is(err, zerr.ErrBlobNotFound) ||
				errors.Is(err, zerr.ErrRepoNotFound) ||
				errors.Is(err, zerr.ErrUnauthorizedAccess) {
				continue
			}

			onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("digest", digest.String()).
				Err(err).Msg("sync routine: error while syncing blob")
		} else {
			break
		}
	}

	syncResult <- err
}
