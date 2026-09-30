//go:build sync

package sync

import (
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

	// announceChan/subscriptionID come from the Subscribe call in ConnectClient, made before the
	// response headers are written (see ConnectClient).
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

// Descriptor returns the blob's descriptor, waiting for its download to start.
func (ifbc *InFlightBlobCopier) Descriptor() (descriptor.Descriptor, error) {
	return ifbc.Source.Descriptor()
}

// Copy streams the whole blob; same as CopyRange(0, -1).
func (ifbc *InFlightBlobCopier) Copy() error {
	return ifbc.CopyRange(0, -1)
}

// CopyRange streams bytes [start, end] (inclusive; end == -1 means the last byte), waiting for
// bytes not on disk yet. It returns as soon as end has arrived, without waiting for the rest of
// the blob. Callers validate the range before writing headers; the check here is a backstop.
func (ifbc *InFlightBlobCopier) CopyRange(start, end int64) error {
	ifbc.log.Debug().Str("onDiskPath", ifbc.onDiskPath).Int64("start", start).Int64("end", end).
		Msg("starting inflight copy")

	// Release the subscription ConnectClient took on every return path, including os.Open failing.
	defer ifbc.Source.Unsubscribe(ifbc.subscriptionID)

	onDiskFile, err := os.Open(ifbc.onDiskPath)
	if err != nil {
		ifbc.log.Error().Err(err).Str("onDiskPath", ifbc.onDiskPath).Msg("failed to open on disk path")

		return err
	}
	defer onDiskFile.Close()

	byteAnnounceChan := ifbc.announceChan

	// Usually instant (the caller already waited on Descriptor); otherwise this bounds the wait
	// for a download that never starts.
	desc, err := ifbc.Source.Descriptor()
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

	// target is the exclusive end of the range, as an absolute file offset like the announcements.
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

	// copyChan signals the loop below that new bytes are available.
	copyChan := make(chan struct{}, 1)

	// shutdown stops the announcement goroutine on an error path, so it doesn't leak.
	shutdown := make(chan struct{})

	// done is closed when the announcement goroutine exits, for any reason.
	done := make(chan struct{})

	var copierErr error

	// Announcement goroutine: records each new offset and wakes the copy loop without ever
	// blocking the reader. Exits once this range's end has arrived.
	go func() {
		defer close(done)

		for {
			select {
			case <-shutdown:
				return

			case latestByteNum, ok := <-byteAnnounceChan:
				if !ok {
					// Closed before the range arrived: the download failed or cleanup disconnected us.
					copierErr = zerr.ErrSyncUpstreamDownloadFailed

					return
				}

				latest := ifbc.latestOffset.Swap(latestByteNum)

				// Only signal a copy when the offset actually advanced. latest == 0 also signals,
				// so the very first announcement always wakes the copy loop.
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
			// Clamp to target so a sub-range never reads past what the client asked for.
			latest := min(ifbc.latestOffset.Load(), target)

			if latest <= numBytesCopied {
				continue
			}

			// As the range's bound is known ahead of time, CopyN is not expected
			// to encounter a partial read if the onDiskFile is healthy.
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

	// Drain any remaining bytes that arrived after the last copyChan signal.
	latest := min(ifbc.latestOffset.Load(), target)

	if latest > numBytesCopied {
		_, err := io.CopyN(ifbc.dest, onDiskFile, latest-numBytesCopied)
		if err != nil {
			ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

			return err
		}
	}

	// Wait for the announcement goroutine to finish before returning.
	<-done

	return copierErr
}
