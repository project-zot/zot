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
	onDiskFile     *os.File

	InFlightReader  *blob.BReader
	clientMu        sync.Mutex
	chunksMu        sync.RWMutex
	clients         map[int]chan int64
	numClientsTotal int

	logger log.Logger
}

func NewChunkedBlobReader(r *blob.BReader, numChunksTotal int64, onDiskPath string, logger log.Logger) (*ChunkedBlobReader, error) {
	createdFile, err := os.OpenFile(onDiskPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	return &ChunkedBlobReader{
		numChunksTotal: numChunksTotal,
		InFlightReader: r,
		clients:        make(map[int]chan int64),
		logger:         logger,
		onDiskPath:     onDiskPath,
		onDiskFile:     createdFile,
	}, nil
}

func (cbr *ChunkedBlobReader) Read(b []byte) (int, error) {
	cbr.chunksMu.Lock()

	// TODO: This is duplicating file IO so that the stream logic can access it easily. It would be more efficient to
	// Access the file that regclient is writing to avoid this extra duplication.
	var internalBuffBytes []byte = make([]byte, 0, constants.StreamChunkSizeBytes)
	internalBuff := bytes.NewBuffer(internalBuffBytes)

	multiWriter := io.MultiWriter(cbr.onDiskFile, internalBuff)

	numBytesRead, err := io.CopyN(multiWriter, cbr.InFlightReader, constants.StreamChunkSizeBytes)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			cbr.logger.Error().Err(err).Msg("failed to copy from in flight reader")
			// TODO: This means there was an upstream read error. Should the in-progress streams be terminated?
			copy(b, internalBuff.Bytes())
			cbr.chunksMu.Unlock()
			return int(numBytesRead), err
		}
	}

	copy(b, internalBuff.Bytes())
	cbr.numChunksRead++
	if cbr.numChunksRead == cbr.numChunksTotal {
		cbr.onDiskFile.Close()
	}

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
		blob.WithHeader(cbr.InFlightReader.RawHeaders()),
		blob.WithDesc(cbr.InFlightReader.GetDescriptor()),
		blob.WithReader(cbr),
	)
}
