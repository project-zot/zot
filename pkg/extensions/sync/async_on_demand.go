//go:build sync

package sync

import "context"

type asyncOnDemandService interface {
	IsAsyncOnDemandForRepo(repo string) bool
}

func (onDemand *BaseOnDemand) IsAsyncOnDemandEnabledForRepo(repo string) bool {
	for _, service := range onDemand.services {
		asyncService, ok := service.(asyncOnDemandService)
		if ok && asyncService.IsAsyncOnDemandForRepo(repo) {
			return true
		}
	}

	return false
}

// onDemandKindQueuedImage keys QueueImage scheduling separately from background retries, so a
// queued fill that fails can still schedule its own retry via maybeRetryInBackground.
const onDemandKindQueuedImage = "queued-image"

// QueueImage starts a background SyncImage for repo:reference unless one is already scheduled,
// so a burst of cache misses for the same image costs a single goroutine.
func (onDemand *BaseOnDemand) QueueImage(ctx context.Context, repo, reference string) {
	req := request{kind: onDemandKindQueuedImage, repo: repo, reference: reference, isBackground: true}

	if _, queued := onDemand.requestStore.LoadOrStore(req, struct{}{}); queued {
		return
	}

	detachedContext := context.WithoutCancel(ctx)

	go func() {
		defer onDemand.requestStore.Delete(req)

		if err := onDemand.SyncImage(detachedContext, repo, reference); err != nil {
			onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", reference).
				Msg("asynchronous on-demand image sync failed")
		}
	}()
}
