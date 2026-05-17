package sync

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/regclient/regclient/types/blob"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// ChunkedBlobReader is a helper that splits a blob into chunks based on chunkSize
// It then copies chunks to disk.
// The latest chunk number is announced to channels of subscribers.
type ChunkedBlobReader struct {
	numChunksTotal int64
	numChunksRead  int64
	chunkSizeBytes int64
	onDiskPath     string
	onDiskFile     *os.File

	InFlightReader  *blob.BReader
	clientMu        sync.Mutex
	clientCond      *sync.Cond
	chunksMu        sync.RWMutex
	clients         map[int]chan int64
	numClientsTotal int

	logger log.Logger
}

func NewChunkedBlobReader(onDiskPath string, chunkSizeBytes int64, logger log.Logger) (*ChunkedBlobReader, error) {
	createdFile, err := os.OpenFile(onDiskPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	cbr := &ChunkedBlobReader{
		clients:        make(map[int]chan int64),
		logger:         logger,
		onDiskPath:     onDiskPath,
		onDiskFile:     createdFile,
		chunkSizeBytes: chunkSizeBytes,
	}

	cbr.clientCond = sync.NewCond(&cbr.clientMu)

	return cbr, nil
}

func (cbr *ChunkedBlobReader) InitReader(r *blob.BReader, numChunksTotal int64) {
	if cbr.InFlightReader == nil {
		cbr.numChunksTotal = numChunksTotal
		cbr.InFlightReader = r
	}
}

func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	if cbr.InFlightReader == nil {
		return 0, zerr.ErrStreamReaderNotInitialized
	}

	cbr.chunksMu.Lock()

	// Access the file that regclient is writing to avoid this extra duplication.
	var internalBuffBytes []byte = make([]byte, 0, cbr.chunkSizeBytes)
	internalBuff := bytes.NewBuffer(internalBuffBytes)

	multiWriter := io.MultiWriter(cbr.onDiskFile, internalBuff)

	numBytesRead, err := io.CopyN(multiWriter, cbr.InFlightReader, cbr.chunkSizeBytes)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			// upstream download error
			cbr.logger.Error().Err(err).Msg("failed to copy from in flight reader")
			cbr.chunksMu.Unlock()

			// drain all clients and close their channels
			for clientId := range cbr.clients {
				cbr.Unsubscribe(clientId)
			}

			return -1, err
		}
	}

	copy(buff, internalBuff.Bytes())

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

// Subscribe to the reader each time a new client is interested in the current blob,
// the client would create a subscription here with a channel where latest chunk info is sent.
func (cbr *ChunkedBlobReader) Subscribe(channel chan int64) int {
	cbr.clientMu.Lock()
	defer func() {
		cbr.clientCond.Broadcast()
		cbr.clientMu.Unlock()
	}()

	cbr.clients[cbr.numClientsTotal] = channel
	chanId := cbr.numClientsTotal
	cbr.numClientsTotal++

	// Announce the current number of available chunks to the new client only if the reader is initialized
	if cbr.InFlightReader != nil {
		cbr.chunksMu.RLock()
		defer cbr.chunksMu.RUnlock()

		go func() {
			channel <- cbr.numChunksRead
		}()
	}

	return chanId
}

func (cbr *ChunkedBlobReader) Unsubscribe(clientId int) {
	cbr.clientMu.Lock()
	defer func() {
		cbr.clientCond.Broadcast()
		cbr.clientMu.Unlock()
	}()

	channel, ok := cbr.clients[clientId]
	if ok {
		close(channel)

		cbr.numClientsTotal--
		delete(cbr.clients, clientId)
	}
}

func (cbr *ChunkedBlobReader) ToBReader() *blob.BReader {
	return blob.NewReader(
		blob.WithHeader(cbr.InFlightReader.RawHeaders()),
		blob.WithDesc(cbr.InFlightReader.GetDescriptor()),
		blob.WithReader(cbr),
	)
}

func (cbr *ChunkedBlobReader) WaitForClientEmpty() {
	cbr.clientMu.Lock()
	defer cbr.clientMu.Unlock()

	for len(cbr.clients) > 0 {
		cbr.clientCond.Wait()
	}
}
