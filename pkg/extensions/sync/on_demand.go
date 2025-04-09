//go:build sync
// +build sync

package sync

import (
	"context"
	"errors"
	"sync"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
)

type request struct {
	repo      string
	reference string
	// used for background retries, at most one background retry per service
	serviceID    int
	isBackground bool
}

/*
	a request can be an image/signature/sbom

keep track of all parallel requests, if two requests of same image/signature/sbom comes at the same time,
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

	val, found := onDemand.requestStore.Load(req)
	if found {
		onDemand.log.Info().Str("repo", repo).Str("reference", reference).
			Msg("image already demanded, waiting on channel")

		syncResult, _ := val.(chan error)

		err, ok := <-syncResult
		// if channel closed exit
		if !ok {
			return nil
		}

		return err
	}

	syncResult := make(chan error)
	onDemand.requestStore.Store(req, syncResult)

	defer onDemand.requestStore.Delete(req)
	defer close(syncResult)

	go onDemand.syncImage(ctx, repo, reference, syncResult)

	err, ok := <-syncResult
	if !ok {
		return nil
	}

	return err
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	req := request{
		repo:      repo,
		reference: subjectDigestStr,
	}

	val, found := onDemand.requestStore.Load(req)
	if found {
		onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).
			Msg("referrers for image already demanded, waiting on channel")

		syncResult, _ := val.(chan error)

		err, ok := <-syncResult
		// if channel closed exit
		if !ok {
			return nil
		}

		return err
	}

	syncResult := make(chan error)
	onDemand.requestStore.Store(req, syncResult)

	defer onDemand.requestStore.Delete(req)
	defer close(syncResult)

	go onDemand.syncReferrers(ctx, repo, subjectDigestStr, referenceTypes, syncResult)

	err, ok := <-syncResult
	if !ok {
		return nil
	}

	return err
}

func (onDemand *BaseOnDemand) syncReferrers(ctx context.Context, repo, subjectDigestStr string,
	referenceTypes []string, syncResult chan error,
) {
	var err error
	for serviceID, service := range onDemand.services {
		err = service.SyncReferrers(ctx, repo, subjectDigestStr, referenceTypes)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) ||
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
				// retry in background
				go func(service Service) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).Str("err", err.Error()).
						Msg("sync routine: starting routine to copy image, because of error")

					err := service.SyncReferrers(context.Background(), repo, subjectDigestStr, referenceTypes)
					if err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", subjectDigestStr).
							Err(err).Msg("sync routine: starting routine to retry copy image due to error")
					}
				}(service)
			}
		} else {
			break
		}
	}

	syncResult <- err
}

func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string, syncResult chan error) {
	var err error

	for serviceID, service := range onDemand.services {
		err = service.SyncImage(ctx, repo, reference)
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) ||
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
				go func(service Service) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", reference).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str("reference", reference).Str("err", retryErr.Error()).
						Msg("sync routine: starting routine to retry copy image due to error")

					err := service.SyncImage(context.Background(), repo, reference)
					if err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
							Err(err).Msg("sync routine: error while copying image")
					}
				}(service)
			}
		} else {
			break
		}
	}

	syncResult <- err
}
