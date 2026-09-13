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

// InFlightBlobCopier represents a client that wants to stream an image while it is being downloaded.
// The data is copied first from disk up to the latest byte and further copies wait for an announcement
// over a channel when a new offset is available.
type InFlightBlobCopier struct {
	Source     *ChunkedBlobReader
	onDiskPath string
	dest       io.Writer
	log        log.Logger

	// announceChan/subscriptionID are obtained via Source.Subscribe() by ConnectClient, before
	// this copier is even constructed - not lazily in Copy() - so the caller is already a
	// registered subscriber by the time ConnectClient returns and response headers get written.
	// See ConnectClient's doc comment for the truncated-body race this avoids.
	announceChan   chan int64
	subscriptionID int

	// latestOffset holds the latest byte offset announced by the ChunkedBlobReader.
	// Updated atomically by the announcement goroutine.
	latestOffset atomic.Int64
}

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

// Close releases this copier's subscription without streaming any bytes - used when a caller
// obtains a copier (registering a subscription as of ConnectClient) but then never calls Copy(),
// e.g. because Descriptor() timed out. Calling this is unnecessary, but harmless, if Copy() has
// already run (Unsubscribe on an already-removed subscription is a no-op).
func (ifbc *InFlightBlobCopier) Close() {
	ifbc.Source.Unsubscribe(ifbc.subscriptionID)
}

// Descriptor returns the descriptor of the blob being streamed.
func (ifbc *InFlightBlobCopier) Descriptor() (descriptor.Descriptor, error) {
	return ifbc.Source.Descriptor()
}

// Copy streams the entire blob to the client - equivalent to CopyRange(0, -1).
func (ifbc *InFlightBlobCopier) Copy() error {
	return ifbc.CopyRange(0, -1)
}

// CopyRange streams bytes [start, end] (inclusive) of the blob to the client, waiting for bytes
// not yet written to disk to arrive from upstream the same way Copy does - so a range request can
// finish as soon as its own upper bound has arrived, without waiting for the rest of the blob.
// end == -1 means through the last byte of the blob (Copy's behavior).
//
// The caller is expected to have already validated start/end against the blob's actual size (e.g.
// via StreamManager.CachedBlobInfo, which - unlike Descriptor - is available immediately from the
// staged manifest, before the download even starts) before committing to a response
// status/headers that promise a specific range; CopyRange re-validates once the real descriptor is
// available, purely as a defensive backstop.
func (ifbc *InFlightBlobCopier) CopyRange(start, end int64) error {
	ifbc.log.Debug().Str("onDiskPath", ifbc.onDiskPath).Int64("start", start).Int64("end", end).
		Msg("starting inflight copy")

	// Deferred before the temp file is even opened: ConnectClient already registered this
	// subscription (see its doc comment) before Copy was ever called, so every early return below
	// - os.Open failing included - must still release it, or it lingers until
	// RemoveStreamingImage's drain timeout forces it out instead.
	defer ifbc.Source.Unsubscribe(ifbc.subscriptionID)

	onDiskFile, err := os.Open(ifbc.onDiskPath)
	if err != nil {
		ifbc.log.Error().Err(err).Str("onDiskPath", ifbc.onDiskPath).Msg("failed to open on disk path")

		return err
	}
	defer onDiskFile.Close()

	byteAnnounceChan := ifbc.announceChan

	// By the time Copy is called, a caller normally already resolved Descriptor once (e.g.
	// streamBlobToClient does, to set response headers before ever calling Copy) - the reader is
	// then already initialized, so this hits the fast path with no meaningful further wait.
	// Also the mechanism that bounds this call in time if the background sync stalls or never
	// reaches this blob at all - see Descriptor's doc comment.
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

	// target is the exclusive upper bound of this range, in absolute on-disk-offset terms - the
	// same terms latestOffset/announcements use, since those describe the whole file regardless of
	// which subset of it any one client asked for.
	target := end + 1

	if start > 0 {
		if _, err := onDiskFile.Seek(start, io.SeekStart); err != nil {
			ifbc.log.Error().Err(err).Str("onDiskPath", ifbc.onDiskPath).Msg("failed to seek to range start")

			return err
		}
	}

	if start >= target {
		// Empty range - only reachable via Copy() on a zero-length blob (start=0, end=-1 -> target=0).
		return nil
	}

	// copyChan signals the loop below that new bytes are available.
	copyChan := make(chan struct{}, 1)

	// shutdown tells the announcement goroutine to exit. Closed on
	// any error path so the goroutine does not leak.
	shutdown := make(chan struct{})

	// done is closed by the announcement goroutine on exit, confirming it has
	// fully exited regardless of whether it terminated normally or via shutdown.
	done := make(chan struct{})

	var copierErr error

	// Goroutine: listens for byte-offset announcements from ChunkedBlobReader.
	// Always exits quickly and never blocks the reader, regardless of how busy
	// copyChan is (buffered) or how slow the copy loop is. Exits as soon as this range's own
	// target has arrived, without waiting for the rest of the blob to finish downloading.
	go func() {
		defer close(done)

		for {
			select {
			case <-shutdown:
				return

			case latestByteNum, ok := <-byteAnnounceChan:
				if !ok {
					// Channel was closed before reaching EOF - upstream download failure,
					// integrity check failure, or a forced disconnect during cleanup.
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

				if latestByteNum >= target {
					return
				}
			}
		}
	}()

	copied := false
	copierDone := false

	// numBytesCopied tracks the absolute on-disk offset copied up to so far.
	numBytesCopied := start

	for !copied && !copierDone {
		select {
		case <-copyChan:
			// Clamped to target: for Copy() (target == blobSize) latestOffset can never exceed it
			// anyway, so this is a no-op there: it only matters for a true sub-range, to avoid
			// reading past what the client actually asked for once the download continues beyond it.
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
