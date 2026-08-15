package sync

import (
	"io"
	"net/http"
	"os"
	"sync/atomic"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// InFlightBlobCopier represents a client that wants to stream an image while it is being downloaded.
// The data is copied first from disk up to the latest byte and further copies wait for an announcement
// over a channel when a new offset is available.
type InFlightBlobCopier struct {
	Source     *ChunkedBlobReader
	onDiskPath string
	dest       io.Writer
	flusher    http.Flusher // nil if dest does not implement http.Flusher
	log        log.Logger

	// announceChan and clientID are set at construction time (during ConnectClient)
	// so that the client is registered with the ChunkedBlobReader before Copy() is
	// called. This prevents a race where WaitForClientEmpty passes between
	// ConnectClient returning and Copy starting.
	announceChan chan int64
	clientID     int

	// latestOffset holds the latest byte offset announced by the ChunkedBlobReader.
	// Updated atomically by the announcement goroutine.
	latestOffset atomic.Int64
}

func NewInFlightBlobCopier(
	source *ChunkedBlobReader, onDiskPath string, dest io.Writer, logger log.Logger,
) *InFlightBlobCopier {
	flusher, _ := dest.(http.Flusher)

	// Subscribe eagerly so that WaitForClientEmpty cannot pass before Copy() runs.
	announceChan, clientID := source.Subscribe()

	return &InFlightBlobCopier{
		Source:       source,
		onDiskPath:   onDiskPath,
		dest:         dest,
		flusher:      flusher,
		log:          logger,
		announceChan: announceChan,
		clientID:     clientID,
	}
}

func (ifbc *InFlightBlobCopier) Copy() error {
	ifbc.log.Debug().Str("onDiskPath", ifbc.onDiskPath).Msg("starting inflight copy")

	onDiskFile, err := os.Open(ifbc.onDiskPath)
	if err != nil {
		ifbc.log.Error().Err(err).Str("onDiskPath", ifbc.onDiskPath).Msg("failed to open on disk path")

		return err
	}
	defer onDiskFile.Close()

	// Use the channel registered at construction time (in ConnectClient/NewInFlightBlobCopier).
	byteAnnounceChan := ifbc.announceChan
	defer ifbc.Source.Unsubscribe(ifbc.clientID)

	blobSize := ifbc.Source.Descriptor().Size

	// copyChan signals Copy() that new bytes are available.
	copyChan := make(chan struct{}, 1)

	// shutdown tells the announcement goroutine to exit. Closed by Copy() on
	// any error path so the goroutine does not leak.
	shutdown := make(chan struct{})

	// done is closed by the announcement goroutine on exit, confirming it has
	// fully exited regardless of whether it terminated normally or via shutdown.
	done := make(chan struct{})

	var copierErr error

	// Goroutine: listens for byte-offset announcements from ChunkedBlobReader.
	// Always exits quickly and never blocks the reader, regardless of how busy
	// copyChan is (buffered) or how slow the Copy loop is.
	go func() {
		defer close(done)

		for {
			select {
			case <-shutdown:
				return

			case latestByteNum, ok := <-byteAnnounceChan:
				if !ok {
					// Channel was closed before reaching EOF - upstream download failure.
					copierErr = zerr.ErrSyncUpstreamDownloadFailed

					return
				}

				latest := ifbc.latestOffset.Swap(latestByteNum)

				// Only signal a copy when the offset actually advanced.
				if latestByteNum > latest || latest == 0 {
					select {
					case copyChan <- struct{}{}:
					default:
					}
				}

				if latestByteNum >= blobSize {
					return
				}
			}
		}
	}()

	copied := false
	copierDone := false

	// numBytesCopied tracks how many bytes have been copied from disk to the client so far
	numBytesCopied := int64(0)

	for !copied && !copierDone {
		select {
		case <-copyChan:
			latest := ifbc.latestOffset.Load()

			if latest <= numBytesCopied {
				continue
			}

			// As the blob size is known ahead of time, CopyN is not expected
			// to encounter a partial read if the onDiskFile is healthy.
			written, err := io.CopyN(ifbc.dest, onDiskFile, latest-numBytesCopied)
			if err != nil {
				ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

				close(shutdown)
				<-done

				return err
			}

			numBytesCopied += written

			// Flush immediately so the client receives bytes without waiting for
			// Go's default HTTP response buffering to fill up. This reduces
			// perceived latency and prevents client-side idle timeouts.
			if ifbc.flusher != nil {
				ifbc.flusher.Flush()
			}

			if numBytesCopied >= blobSize {
				copied = true
			}

		case <-done:
			copierDone = true
		}
	}

	// Drain any remaining bytes that arrived after the last copyChan signal.
	latest := ifbc.latestOffset.Load()

	if latest > numBytesCopied {
		_, err := io.CopyN(ifbc.dest, onDiskFile, latest-numBytesCopied)
		if err != nil {
			ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

			return err
		}

		if ifbc.flusher != nil {
			ifbc.flusher.Flush()
		}
	}

	// Wait for the announcement goroutine to finish before returning.
	<-done

	return copierErr
}
