package sync

import (
	"errors"
	"io"
	"os"
	"sync"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// InFlightBlobCopier represents a client that wants to stream an image while it is being downloaded.
// The data is copied first from disk up to the latest byte and further copies wait for an announcement
// over a channel when a new set of bytes are available.
// Announcements are made after a set of bytes are copied to the disk.
type InFlightBlobCopier struct {
	sync.Mutex

	numBytesCopied int64
	Source         *ChunkedBlobReader
	onDiskPath     string
	dest           io.Writer
	log            log.Logger
}

func NewInFlightBlobCopier(
	source *ChunkedBlobReader, onDiskPath string, dest io.Writer, logger log.Logger,
) *InFlightBlobCopier {
	return &InFlightBlobCopier{
		numBytesCopied: 0,
		Source:         source,
		dest:           dest,
		onDiskPath:     onDiskPath,
		log:            logger,
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

	// Register channel for latest byte count updates
	byteAnnounceChan := make(chan int64, 1)

	id := ifbc.Source.Subscribe(byteAnnounceChan)
	defer ifbc.Source.Unsubscribe(id)

	for {
		latestByteNum, ok := <-byteAnnounceChan
		if !ok {
			ifbc.log.Error().Str("onDiskPath", ifbc.onDiskPath).
				Msg("failed to download from upstream, aborting inflight copy")

			return zerr.ErrSyncUpstreamDownloadFailed
		}

		ifbc.Lock()

		// If somehow, the copier receives an announcement for a byte number
		// that has already been copied, skip the copy and wait for the next announcement.
		if latestByteNum <= ifbc.numBytesCopied {
			ifbc.Unlock()

			continue
		}

		// As the blob size is known ahead of time, CopyN is not expected
		// to encounter a partial read if the onDiskFile is healthy.
		_, err = io.CopyN(ifbc.dest, onDiskFile, latestByteNum-ifbc.numBytesCopied)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

				return err
			}
		}
		ifbc.numBytesCopied = latestByteNum
		ifbc.Unlock()

		if latestByteNum >= ifbc.Source.numBytesTotal {
			// transfer is complete
			break
		}
	}

	return nil
}
