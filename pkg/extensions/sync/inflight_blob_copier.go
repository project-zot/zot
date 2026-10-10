//go:build sync

package sync

import (
	"context"
	"io"
	"os"
	"sync/atomic"

	"github.com/regclient/regclient/types/descriptor"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// InFlightBlobCopier streams one blob to one client while it is still downloading: it copies what
// is already on disk, then waits for each newly announced offset.
type InFlightBlobCopier struct {
	Source     *ChunkedBlobReader
	onDiskPath string
	dest       io.Writer
	log        log.Logger

	// From ConnectClient's Subscribe, taken before the response headers are written.
	announceChan   chan int64
	subscriptionID int

	// latestOffset is the newest announced on-disk offset, set by the announcement goroutine.
	latestOffset atomic.Int64
}

// NewInFlightBlobCopier returns a copier from source's temp file at onDiskPath to dest, using a
// subscription already taken on source.
func NewInFlightBlobCopier(
	source *ChunkedBlobReader, onDiskPath string, dest io.Writer,
	announceChan chan int64, subscriptionID int, logger log.Logger,
) *InFlightBlobCopier {
	return &InFlightBlobCopier{
		Source:         source,
		onDiskPath:     onDiskPath,
		dest:           dest,
		announceChan:   announceChan,
		subscriptionID: subscriptionID,
		log:            logger,
	}
}

// Close releases the subscription when Copy will never run (e.g. Descriptor failed). Harmless
// after Copy.
func (ifbc *InFlightBlobCopier) Close() {
	ifbc.Source.Unsubscribe(ifbc.subscriptionID)
}

// Descriptor returns the blob's descriptor, waiting for its download to start or ctx to be done.
func (ifbc *InFlightBlobCopier) Descriptor(ctx context.Context) (descriptor.Descriptor, error) {
	return ifbc.Source.Descriptor(ctx)
}

// Copy streams the whole blob; same as CopyRange(0, -1).
func (ifbc *InFlightBlobCopier) Copy() error {
	return ifbc.CopyRange(0, -1)
}

// CopyRange streams bytes [start, end] (inclusive; -1 means the last byte), waiting for bytes not
// on disk yet, and returns once end has arrived. Callers validate the range first; the check here
// is a backstop.
func (ifbc *InFlightBlobCopier) CopyRange(start, end int64) error {
	ifbc.log.Debug().Str("onDiskPath", ifbc.onDiskPath).Int64("start", start).Int64("end", end).
		Msg("starting inflight copy")

	// Release the subscription on every return path.
	defer ifbc.Source.Unsubscribe(ifbc.subscriptionID)

	onDiskFile, err := os.Open(ifbc.onDiskPath)
	if err != nil {
		ifbc.log.Error().Err(err).Str("onDiskPath", ifbc.onDiskPath).Msg("failed to open on disk path")

		return err
	}
	defer onDiskFile.Close()

	byteAnnounceChan := ifbc.announceChan

	// Usually instant: the caller already waited on Descriptor.
	desc, err := ifbc.Source.Descriptor(context.Background())
	if err != nil {
		return err
	}

	blobSize := desc.Size
	if end == -1 {
		end = blobSize - 1
	}

	if start < 0 || end < start-1 || end >= blobSize {
		return zerr.ErrBadRange
	}

	// target is the range's exclusive end, as an absolute file offset.
	target := end + 1

	if start > 0 {
		if _, err := onDiskFile.Seek(start, io.SeekStart); err != nil {
			ifbc.log.Error().Err(err).Str("onDiskPath", ifbc.onDiskPath).Msg("failed to seek to range start")

			return err
		}
	}

	if start >= target {
		// Empty range: only a zero-length blob via Copy().
		return nil
	}

	copyChan := make(chan struct{}, 1) // new bytes available
	shutdown := make(chan struct{})    // stops the announcement goroutine on error
	done := make(chan struct{})        // closed when the announcement goroutine exits

	var copierErr error

	// Record each announced offset and wake the copy loop; exit once the range's end arrives.
	go func() {
		defer close(done)

		for {
			select {
			case <-shutdown:
				return

			case latestByteNum, ok := <-byteAnnounceChan:
				if !ok {
					// Closed early: the download failed or teardown disconnected us.
					copierErr = zerr.ErrSyncUpstreamDownloadFailed

					return
				}

				latest := ifbc.latestOffset.Swap(latestByteNum)

				// Wake the loop on progress, and always on the first announcement.
				if latestByteNum > latest || latest == 0 {
					select {
					case copyChan <- struct{}{}:
					default:
					}
				}

				if latestByteNum >= target {
					return
				}
			}
		}
	}()

	copied := false
	copierDone := false

	// numBytesCopied is the absolute file offset copied so far.
	numBytesCopied := start

	for !copied && !copierDone {
		select {
		case <-copyChan:
			// Never copy past the requested range.
			latest := min(ifbc.latestOffset.Load(), target)

			if latest <= numBytesCopied {
				continue
			}

			// These bytes are already on disk, so CopyN shouldn't short-read.
			written, err := io.CopyN(ifbc.dest, onDiskFile, latest-numBytesCopied)
			if err != nil {
				ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

				close(shutdown)
				<-done

				return err
			}

			numBytesCopied += written

			if numBytesCopied >= target {
				copied = true
			}

		case <-done:
			copierDone = true
		}
	}

	// Copy bytes announced after the last wake-up.
	latest := min(ifbc.latestOffset.Load(), target)

	if latest > numBytesCopied {
		_, err := io.CopyN(ifbc.dest, onDiskFile, latest-numBytesCopied)
		if err != nil {
			ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

			return err
		}
	}

	<-done

	return copierErr
}
