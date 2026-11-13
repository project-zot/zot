//go:build sync

package sync

import (
	"context"
	"errors"
	"sync"

	"zotregistry.dev/zot/v2/pkg/log"
)

var errBackgroundSyncPreempted = errors.New("background sync preempted by streaming sync")

// syncPriority is shared through the stream manager, including across config reloads.
// Stopping background work isolates client bandwidth without doubling the request budget,
// but sustained streams can starve replication and cancellation can discard partial downloads.
type syncPriority struct {
	mu         sync.Mutex
	streams    int
	background map[*backgroundSync]struct{}
	changed    chan struct{}
}

type backgroundSync struct {
	cancel context.CancelCauseFunc
}

func priorityFor(sm StreamManager) *syncPriority {
	if chunking, ok := sm.(*ChunkingStreamManager); ok {
		return &chunking.priority
	}

	return nil
}

func (p *syncPriority) notifyLocked() {
	if p.changed != nil {
		close(p.changed)
	}

	p.changed = make(chan struct{})
}

func (p *syncPriority) startStream(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if p == nil {
		return func() {}, nil
	}

	p.mu.Lock()
	// Reserve priority before cancellation so no new background task can slip in.
	p.streams++
	p.notifyLocked()

	for work := range p.background {
		work.cancel(errBackgroundSyncPreempted)
	}

	for len(p.background) != 0 && ctx.Err() == nil {
		changed := p.changed
		p.mu.Unlock()

		select {
		case <-ctx.Done():
		case <-changed:
		}

		p.mu.Lock()
	}

	p.mu.Unlock()

	release := func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		p.streams--
		p.notifyLocked()
	}

	if err := ctx.Err(); err != nil {
		release()

		return nil, err
	}

	return release, nil
}

func (p *syncPriority) runBackground(ctx context.Context, logger log.Logger, run func(context.Context) error) error {
	if p == nil {
		return run(ctx)
	}

	for {
		p.mu.Lock()

		for p.streams != 0 && ctx.Err() == nil {
			logger.Debug().Msg("background sync backing off while streaming sync is active")
			changed := p.changed
			p.mu.Unlock()

			select {
			case <-ctx.Done():
			case <-changed:
			}

			p.mu.Lock()
		}

		if err := ctx.Err(); err != nil {
			p.mu.Unlock()

			return err
		}

		workCtx, cancel := context.WithCancelCause(ctx)
		work := &backgroundSync{cancel: cancel}

		if p.background == nil {
			p.background = map[*backgroundSync]struct{}{}
		}

		p.background[work] = struct{}{}
		p.mu.Unlock()

		err := run(workCtx)
		preempted := errors.Is(context.Cause(workCtx), errBackgroundSyncPreempted)
		cancel(nil)

		// Cancellation alone is not exclusion: wait for the entire attempt to unwind.
		p.mu.Lock()
		delete(p.background, work)
		p.notifyLocked()
		p.mu.Unlock()

		if !preempted || err == nil || !errors.Is(err, context.Canceled) {
			return err
		}

		logger.Info().Msg("background sync preempted by streaming sync; retrying after streams finish")

		// On-demand retries must release their singleflight before waiting for streaming.
		if isBackgroundSync(ctx) {
			return errBackgroundSyncPreempted
		}
	}
}

type backgroundSyncContextKey struct{}

func backgroundSyncContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundSyncContextKey{}, true)
}

func isBackgroundSync(ctx context.Context) bool {
	background, _ := ctx.Value(backgroundSyncContextKey{}).(bool)

	return background
}
