package sync

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/regclient/regclient/types/blob"

	"zotregistry.dev/zot/v2/pkg/log"
)

// ChunkedBlobReader is a helper that copies blobs to disk
// and keeps track of clients that are being served the blob.
// The latest byte number is announced to channels of subscribers.
type ChunkedBlobReader struct {
	numBytesTotal      int64
	numBytesReadToDisk int64
	bytesMu            sync.RWMutex

	onDiskPath string
	onDiskFile *os.File

	InFlightReader  *blob.BReader
	clientMu        sync.RWMutex
	clientCond      *sync.Cond
	clients         map[int]chan int64
	numClientsTotal int

	logger log.Logger
}

func NewChunkedBlobReader(onDiskPath string, logger log.Logger) (*ChunkedBlobReader, error) {
	createdFile, err := os.OpenFile(onDiskPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	cbr := &ChunkedBlobReader{
		clients:    make(map[int]chan int64),
		logger:     logger,
		onDiskPath: onDiskPath,
		onDiskFile: createdFile,
	}

	cbr.clientCond = sync.NewCond(&cbr.clientMu)

	return cbr, nil
}

// InitReader sets the regclient blob reader and the total number of bytes to read for the blob.
func (cbr *ChunkedBlobReader) InitReader(blobReader *blob.BReader, numBytesTotal int64) {
	cbr.bytesMu.Lock()
	defer cbr.bytesMu.Unlock()

	if cbr.InFlightReader == nil {
		cbr.numBytesTotal = numBytesTotal
		cbr.InFlightReader = blobReader
	}
}

func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	// InitReader is called inside the regclient callback
	// When Read is called the reader will always be initialized.
	cbr.bytesMu.Lock()

	n, err := io.ReadFull(cbr.InFlightReader, buff)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			// upstream download error
			cbr.logger.Error().Err(err).Msg("failed to read from in flight reader")
			cbr.bytesMu.Unlock()

			cbr.clientMu.RLock()
			clients := cbr.clients
			cbr.clientMu.RUnlock()

			// drain all clients and close their channels
			for clientId := range clients {
				cbr.Unsubscribe(clientId)
			}

			return -1, err
		}
		// partial read at end of stream; normalise to EOF for callers
		err = io.EOF
	}

	if n > 0 {
		if _, werr := cbr.onDiskFile.Write(buff[:n]); werr != nil {
			cbr.logger.Error().Err(werr).Msg("failed to write blob data to disk")
			cbr.bytesMu.Unlock()

			return -1, werr
		}

		cbr.numBytesReadToDisk += int64(n)
	}

	if cbr.numBytesReadToDisk >= cbr.numBytesTotal {
		clsErr := cbr.onDiskFile.Close()
		if clsErr != nil {
			cbr.logger.Error().Err(clsErr).Msg("failed to close on disk file")
		}
	}

	numBytesRead := cbr.numBytesReadToDisk
	cbr.bytesMu.Unlock()

	cbr.clientMu.Lock()
	// Update all clients about the latest byte offset available on disk.
	var wg sync.WaitGroup
	for _, c := range cbr.clients {
		wg.Go(func() {
			c <- numBytesRead
		})
	}
	wg.Wait()

	cbr.clientMu.Unlock()

	// If the reader has finished reading the blob, close all clients.
	if err == io.EOF {
		cbr.clientMu.RLock()
		clients := cbr.clients
		cbr.clientMu.RUnlock()

		for clientId := range clients {
			cbr.Unsubscribe(clientId)
		}
	}

	return n, err
}

// Subscribe to the reader each time a new client is interested in the current blob,
// the client would create a subscription here with a channel where latest chunk info is sent.
func (cbr *ChunkedBlobReader) Subscribe() (chan int64, int) {
	cbr.clientMu.Lock()
	defer func() {
		cbr.clientCond.Broadcast()
		cbr.clientMu.Unlock()
	}()

	channel := make(chan int64, 1)

	cbr.clients[cbr.numClientsTotal] = channel
	chanId := cbr.numClientsTotal
	cbr.numClientsTotal++

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()
	// Announce the current number of available chunks to the new client only if the reader is initialized
	if cbr.InFlightReader != nil {
		go func() {
			channel <- cbr.numBytesReadToDisk
		}()
	}

	return channel, chanId
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
