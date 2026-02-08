package sync

import (
	"errors"
	"io"
	"os"
	"sync"

	"zotregistry.dev/zot/v2/pkg/log"
)

// InFlightBlobCopier represents a client that wants to stream an image while it is being downloaded.
// The data is copied first from disk up to the latest chunk and further copies wait for an announcement
// over a channel when a new chunk is available.
type InFlightBlobCopier struct {
	sync.Mutex

	numChunksCopied int64
	Source          *ChunkedBlobReader
	onDiskPath      string
	dest            io.Writer
	log             log.Logger
	chunkSizeBytes  int64
}

func NewInFlightBlobCopier(
	source *ChunkedBlobReader, onDiskPath string, dest io.Writer, chunkSizeBytes int64, logger log.Logger,
) *InFlightBlobCopier {
	return &InFlightBlobCopier{
		numChunksCopied: 0,
		Source:          source,
		dest:            dest,
		onDiskPath:      onDiskPath,
		chunkSizeBytes:  chunkSizeBytes,
		log:             logger,
	}
}

func (ifbc *InFlightBlobCopier) Copy() error {
	ifbc.log.Info().Msg("starting inflight copy")

	onDiskFile, err := os.Open(ifbc.onDiskPath)
	if err != nil {
		ifbc.log.Error().Err(err).Msg("failed to open on disk path")

		return err
	}
	defer onDiskFile.Close()

	// Register channel for latest chunk count updates
	chunkChan := make(chan int64, 1)

	id := ifbc.Source.Subscribe(chunkChan)

	defer ifbc.Source.Unsubscribe(id)
	defer close(chunkChan)

	for {
		latestChunkNum := <-chunkChan

		ifbc.Lock()
		if latestChunkNum <= ifbc.numChunksCopied {
			ifbc.Unlock()

			continue
		}

		_, err = io.CopyN(ifbc.dest, onDiskFile, (latestChunkNum-ifbc.numChunksCopied)*ifbc.chunkSizeBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				ifbc.log.Error().Err(err).Msg("failed to copy data to downstream client")

				return err
			}
		}
		ifbc.numChunksCopied = latestChunkNum
		ifbc.Unlock()

		if latestChunkNum == ifbc.Source.numChunksTotal {
			// transfer is complete
			break
		}
	}

	return nil
}
