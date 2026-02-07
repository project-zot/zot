package sync

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"

	"zotregistry.dev/zot/v2/pkg/log"
)

// ChunkedBlobReader is a helper that copies blobs to disk
// and keeps track of clients that are being served the blob.
// The latest byte number is announced to channels of subscribers.
type ChunkedBlobReader struct {
	numBytesTotal      int64
	numBytesReadToDisk int64
	bytesMu            sync.RWMutex
	readerReady        chan struct{}
	blobDesc           descriptor.Descriptor

	onDiskPath string
	onDiskFile *os.File

	inFlightReader *blob.BReader
	clientMu       sync.RWMutex
	clientCond     *sync.Cond
	clients        map[int]chan int64
	nextClientId   int

	logger log.Logger
}

func NewChunkedBlobReader(onDiskPath string, logger log.Logger) (*ChunkedBlobReader, error) {
	createdFile, err := os.OpenFile(onDiskPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	cbr := &ChunkedBlobReader{
		clients:     make(map[int]chan int64),
		logger:      logger,
		onDiskPath:  onDiskPath,
		onDiskFile:  createdFile,
		readerReady: make(chan struct{}),
	}

	cbr.clientCond = sync.NewCond(&cbr.clientMu)

	return cbr, nil
}

// Descriptor returns the descriptor of the blob being read.
// If the descriptor is not yet available, it waits until it is set by InitReader.
func (cbr *ChunkedBlobReader) Descriptor() descriptor.Descriptor {
	cbr.bytesMu.RLock()
	if cbr.inFlightReader != nil {
		desc := cbr.blobDesc
		cbr.bytesMu.RUnlock()

		return desc
	}
	cbr.bytesMu.RUnlock()

	// Block without holding any lock until InitReader signals readiness.
	<-cbr.readerReady

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.blobDesc
}

// InitReader sets the regclient blob reader and the total number of bytes to read for the blob.
// Returns true if the init modified the reader, else false if the reader was already
// initialized.
func (cbr *ChunkedBlobReader) InitReader(blobReader *blob.BReader, desc descriptor.Descriptor) bool {
	cbr.bytesMu.Lock()
	defer cbr.bytesMu.Unlock()

	if cbr.inFlightReader == nil {
		cbr.numBytesTotal = desc.Size
		cbr.inFlightReader = blobReader
		cbr.blobDesc = desc
		close(cbr.readerReady)

		return true
	}

	return false
}

func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	// InitReader is called inside the regclient callback
	// When Read is called the reader will always be initialized.
	cbr.bytesMu.Lock()

	n, err := io.ReadFull(cbr.inFlightReader, buff)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			// upstream download error
			cbr.logger.Error().Err(err).Msg("failed to read from in flight reader")
			cbr.bytesMu.Unlock()

			cbr.clientMu.RLock()

			clientIDs := make([]int, 0, len(cbr.clients))
			for id := range cbr.clients {
				clientIDs = append(clientIDs, id)
			}
			cbr.clientMu.RUnlock()

			// drain all clients and close their channels
			for _, clientId := range clientIDs {
				cbr.Unsubscribe(clientId)
			}

			return n, err
		}
		// partial read at end of stream; normalise to EOF for callers
		err = io.EOF
	}

	if n > 0 {
		if _, werr := cbr.onDiskFile.Write(buff[:n]); werr != nil {
			cbr.logger.Error().Err(werr).Msg("failed to write blob data to disk")
			cbr.bytesMu.Unlock()

			return n, werr
		}

		cbr.numBytesReadToDisk += int64(n)
	}

	if cbr.numBytesReadToDisk >= cbr.numBytesTotal {
		clsErr := cbr.onDiskFile.Close()
		if clsErr != nil {
			cbr.logger.Error().Err(clsErr).Msg("failed to close on disk file")
		}
		// All bytes have been written to disk; treat as EOF regardless of
		// what io.ReadFull returned. This handles the case where the caller's
		// buffer is exactly the remaining data size and io.ReadFull returns
		// (n, nil) instead of (n, io.ErrUnexpectedEOF).
		err = io.EOF
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

		clientIDs := make([]int, 0, len(cbr.clients))
		for id := range cbr.clients {
			clientIDs = append(clientIDs, id)
		}
		cbr.clientMu.RUnlock()

		for _, clientId := range clientIDs {
			cbr.Unsubscribe(clientId)
		}
	}

	return n, err
}

// Subscribe to the reader each time a new client is interested in the current blob,
// the client would create a subscription here with a channel where latest bytes info is sent.
func (cbr *ChunkedBlobReader) Subscribe() (chan int64, int) {
	cbr.clientMu.Lock()
	defer func() {
		cbr.clientCond.Broadcast()
		cbr.clientMu.Unlock()
	}()

	channel := make(chan int64, 1)

	cbr.clients[cbr.nextClientId] = channel
	chanId := cbr.nextClientId
	cbr.nextClientId++

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()
	// Announce the current number of available bytes to the new client only if
	// the reader is initialized. Send synchronously while clientMu is held so
	// that Unsubscribe cannot close the channel between the map insertion above
	// and this send.
	if cbr.inFlightReader != nil {
		channel <- cbr.numBytesReadToDisk
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
		delete(cbr.clients, clientId)
	}
}

func (cbr *ChunkedBlobReader) ToBReader() *blob.BReader {
	return blob.NewReader(
		blob.WithHeader(cbr.inFlightReader.RawHeaders()),
		blob.WithDesc(cbr.inFlightReader.GetDescriptor()),
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
