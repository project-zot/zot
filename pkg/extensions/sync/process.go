package sync

import (
	"context"
	"sync"
)

type SyncProcessor interface {
	Get(image string)
}

type syncProcessor struct {
	wgWorkers sync.WaitGroup
	fetchCh   chan syncImageReq
	is        *storage.imgStore
	log       log
}

type syncImageReq struct {
	image string
}

// Example: sp := NewSyncProcessor(ctx, wg, is, 16, log)
// sp.Get("repo/image:tag") <- blocks only if channel is full, else returns

func NewSyncProcessor(ctx context.Context, wg sync.WaitGroup, is *imageStore, workers int, log log) {
	sp := &syncProcessor{fetchCh: make(chan syncImageReq, workers), is: is, log: log}
	go sp.demux(ctx)
	return sp
}

// before calling this method, we expect the caller to have first checked if the image is already present
// also make sure no locks held because we write to a channel and it can block if full
func (sp *syncProcessor) Get(image string) {
	sp.fetchCh <- syncImageReq{image: image}
}

// you will need a way to stop this thread, so maybe pass a cancellable context to this, plus that shutdown wg
func (sp *syncProcessor) demux(ctx context.Context) {
	sp.log("starting the sync processor")

	for {
		select {
		case work := <-sp.fetchCh:
			image := work.image
			if ImageAlreadyPresent(image) {
				// image already downloaded in a worker, so no need to do it again
				continue
			}

			sp.wgWorkers.Add(1)
			go sp.worker(ctx, image)

		case <-ctx.Done():
			// a cancel received, so this thread is done - won't pick up any new requests
			wgWorkers.Wait()
			wg.Done()
		}
	}
}

func (sp *syncProcess) worker(ctx context.Context) {
	sp.log("downloading image <image>")

	// download image

	// signal done
	sp.wgWorkers.Done()
}
