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

func (onDemand *BaseOnDemand) QueueImage(ctx context.Context, repo, reference string) {
	detachedContext := context.WithoutCancel(ctx)

	go func() {
		if err := onDemand.SyncImage(detachedContext, repo, reference); err != nil {
			onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", reference).
				Msg("asynchronous on-demand image sync failed")
		}
	}()
}
