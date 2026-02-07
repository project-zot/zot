package sync

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/regclient/regclient/types/blob"
	"zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

// ChunkedBlobReader is a helper that splits a blob into chunks based on chunkSize
// It then copies chunks to disk.
// The latest chunk number is announced to channels of subscribers.
type ChunkedBlobReader struct {
	numChunksTotal int64
	numChunksRead  int64
	onDiskPath     string

	inFlightReader  *blob.BReader
	clientMu        sync.Mutex
	chunksMu        sync.RWMutex
	clients         map[int]chan int64
	numClientsTotal int

	logger log.Logger
}

func NewChunkedBlobReader(r *blob.BReader, numChunksTotal int64, onDiskPath string, logger log.Logger) *ChunkedBlobReader {
	return &ChunkedBlobReader{
		numChunksTotal: numChunksTotal,
		inFlightReader: r,
		clients:        make(map[int]chan int64),
		logger:         logger,
		onDiskPath:     onDiskPath,
	}
}

func (cbr *ChunkedBlobReader) Read(b []byte) (int, error) {
	cbr.chunksMu.Lock()
	var file *os.File
	if cbr.numChunksRead == 0 {
		createdFile, err := os.Create(cbr.onDiskPath)
		if err != nil {
			return 0, err
		}
		file = createdFile
	} else {
		openedFile, err := os.OpenFile(cbr.onDiskPath, os.O_APPEND, 0o644)
		if err != nil {
			return 0, err
		}
		file = openedFile
	}
	defer file.Close()

	// TODO: This is duplicating file IO so that the stream logic can access it easily. It would be more efficient to
	// Access the file that regclient is writing to avoid this extra duplication.
	multiWriter := io.MultiWriter(file, bytes.NewBuffer(b))

	numBytesRead, err := io.CopyN(multiWriter, cbr.inFlightReader, constants.StreamChunkSizeBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		cbr.logger.Error().Err(err).Msg("failed to copy from in flight reader")
		// TODO: This means there was an upstream read error. Should the in-progress streams be terminated?
		cbr.chunksMu.Unlock()
		return int(numBytesRead), err
	}

	cbr.numChunksRead++
	cbr.chunksMu.Unlock()

	cbr.clientMu.Lock()
	// Update all clients about the new chunk
	// Clients always read the chunk from disk
	var wg sync.WaitGroup
	for _, c := range cbr.clients {
		wg.Go(func() {
			c <- cbr.numChunksRead
		})
	}
	cbr.clientMu.Unlock()

	wg.Wait()

	return int(numBytesRead), err
}

// Everytime a new client is interested in the current blob, the client would create a subscription
// here with a channel where latest chunk info is sent.
func (cbr *ChunkedBlobReader) Subscribe(channel chan int64) int {
	cbr.clientMu.Lock()
	defer cbr.clientMu.Unlock()

	cbr.clients[cbr.numClientsTotal] = channel
	chanId := cbr.numClientsTotal
	cbr.numClientsTotal++

	// Announce the current number of available chunks to the new client
	cbr.chunksMu.RLock()
	defer cbr.chunksMu.RUnlock()

	go func() {
		channel <- cbr.numChunksRead
	}()

	return chanId
}

func (cbr *ChunkedBlobReader) Unsubscribe(id int) {
	cbr.clientMu.Lock()
	defer cbr.clientMu.Unlock()

	delete(cbr.clients, id)
}

func (cbr *ChunkedBlobReader) ToBReader() *blob.BReader {
	return blob.NewReader(
		blob.WithDesc(cbr.inFlightReader.GetDescriptor()),
		blob.WithReader(cbr),
	)
}
