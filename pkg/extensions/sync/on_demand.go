//go:build sync

package sync

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type request struct {
	repo      string
	reference string
	// used for background retries, at most one background retry per service
	serviceID    int
	isBackground bool
}

type blobInflight struct {
	done  chan struct{}
	ready chan struct{}
	err   error
	size  int64
}

type cancelOnCloseReadCloser struct {
	reader io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (wrapper *cancelOnCloseReadCloser) Read(p []byte) (int, error) {
	return wrapper.reader.Read(p)
}

func (wrapper *cancelOnCloseReadCloser) Close() error {
	err := wrapper.reader.Close()
	wrapper.once.Do(wrapper.cancel)

	return err
}

/*
BaseOnDemand tracks requests that can be an image/signature/sbom.

It keeps track of all parallel requests, if two requests of same image/signature/sbom comes at the same time,
process just the first one, also keep track of all background retrying routines.
*/
type BaseOnDemand struct {
	services []Service
	// map[request]chan err
	requestStore   *sync.Map
	blobInflight   map[string]*blobInflight
	blobInflightMu sync.Mutex
	streamEnabled  bool
	log            log.Logger
}

func NewOnDemand(log log.Logger) *BaseOnDemand {
	return &BaseOnDemand{
		log:          log,
		requestStore: &sync.Map{},
		blobInflight: make(map[string]*blobInflight),
	}
}

func (onDemand *BaseOnDemand) Add(service Service) {
	onDemand.services = append(onDemand.services, service)

	if service.IsStreamEnabled() {
		onDemand.streamEnabled = true
	}
}

func (onDemand *BaseOnDemand) IsStreamEnabled() bool {
	return onDemand.streamEnabled
}

func (onDemand *BaseOnDemand) SyncBlobOnDemand(ctx context.Context, repo string,
	digest godigest.Digest, imgStore storageTypes.ImageStore,
) (io.ReadCloser, int64, bool, <-chan struct{}, error) {
	key := repo + "@" + digest.String()

	ok, _, checkErr := imgStore.CheckBlob(repo, digest)
	if checkErr != nil {
		return nil, 0, false, nil, checkErr
	}

	if ok {
		reader, size, err := imgStore.GetBlob(repo, digest, "")

		return reader, size, false, nil, err
	}

	onDemand.blobInflightMu.Lock()

	if inf, exists := onDemand.blobInflight[key]; exists {
		onDemand.blobInflightMu.Unlock()

		onDemand.log.Info().Str("repo", repo).Str("digest", digest.String()).
			Msg("blob already being downloaded, waiting on channel")

		select {
		case <-inf.ready:
			if inf.err != nil {
				return nil, 0, false, nil, inf.err
			}
		case <-ctx.Done():
			return nil, 0, false, nil, ctx.Err()
		}

		return nil, inf.size, false, inf.done, nil
	}

	inf := &blobInflight{done: make(chan struct{}), ready: make(chan struct{})}
	onDemand.blobInflight[key] = inf
	onDemand.blobInflightMu.Unlock()

	var upstreamReader io.ReadCloser

	var size int64

	var err error

	for _, service := range onDemand.services {
		if !service.IsStreamEnabled() {
			continue
		}

		timeout := service.GetSyncTimeout()

		// Use a detached context so upstream blob fetch can continue if the client disconnects,
		// while still preserving request-scoped values (trace IDs, auth context, etc.).
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)

		upstreamReader, size, err = service.GetBlobStream(syncCtx, repo, digest)
		if err == nil {
			wrappedReader := &cancelOnCloseReadCloser{
				reader: upstreamReader,
				cancel: cancel,
			}
			inf.size = size
			close(inf.ready)

			return wrappedReader, size, true, nil, nil
		}

		cancel()
	}

	inf.err = err
	close(inf.ready)
	close(inf.done)

	onDemand.blobInflightMu.Lock()
	delete(onDemand.blobInflight, key)
	onDemand.blobInflightMu.Unlock()

	return nil, 0, false, nil, err
}

func (onDemand *BaseOnDemand) BlobDownloadDone(repo string, digest godigest.Digest, err error) {
	key := repo + "@" + digest.String()

	onDemand.blobInflightMu.Lock()
	defer onDemand.blobInflightMu.Unlock()

	if inf, exists := onDemand.blobInflight[key]; exists {
		inf.err = err
		close(inf.done)
		delete(onDemand.blobInflight, key)
	}
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

	go onDemand.syncImage(ctx, repo, reference, syncResult)

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

	go onDemand.syncReferrers(ctx, repo, subjectDigestStr, referenceTypes, syncResult)

	err := <-syncResult

	return err
}

func (onDemand *BaseOnDemand) syncReferrers(ctx context.Context, repo, subjectDigestStr string,
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
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
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
					retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), serviceTimeout)
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

func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string, syncResult chan error) {
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
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
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
					retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), serviceTimeout)
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
