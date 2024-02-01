//go:build sync
// +build sync

package sync

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/containers/common/pkg/retry"

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

func (onDemand *BaseOnDemand) SyncReference(ctx context.Context, repo string,
	subjectDigestStr string, referenceType string,
) error {
	var err error

	for _, service := range onDemand.services {
		err = service.SetNextAvailableURL()
		if err != nil {
			return err
		}

		err = service.SyncReference(ctx, repo, subjectDigestStr, referenceType)
		if err != nil {
			continue
		} else {
			return nil
		}
	}

	return err
}

func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string, syncResult chan error) {
	var err error
	for serviceID, service := range onDemand.services {
		err = service.SetNextAvailableURL()

		isPingErr := errors.Is(err, zerr.ErrSyncPingRegistry)
		if err != nil && !isPingErr {
			syncResult <- err

			return
		}

		// no need to try to sync inline if there is a ping error, we want to retry in background
		if !isPingErr {
			err = service.SyncImage(ctx, repo, reference)
		}

		if err != nil || isPingErr {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) {
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

			retryOptions := service.GetRetryOptions()

			if retryOptions.MaxRetry > 0 {
				// retry in background
				go func(service Service) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", reference).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str(reference, "reference").Str("err", err.Error()).
						Str("component", "sync").Msg("starting routine to copy image, because of error")

					time.Sleep(retryOptions.Delay)

					// retrying in background, can't use the same context which should be cancelled by now.
					if err = retry.RetryIfNecessary(context.Background(), func() error {
						err := service.SyncImage(context.Background(), repo, reference)

						return err
					}, retryOptions); err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
							Err(err).Str("component", "sync").Msg("failed to copy image")
					}
				}(service)
			}
		} else {
			break
		}
	}

	syncResult <- err
}
