//go:build sync

package stream

import (
	"context"
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

	// failed is set when the in-flight upstream read (or the disk write) fails.
	// A failed reader can be re-armed with ReinitReader on the next sync retry.
	failed bool

	// aborted is a terminal state: the sync gave up on this blob (all retries
	// exhausted). No re-arm will follow; subscribers are closed and new
	// subscriptions are refused so clients never hang on a dead stream.
	aborted bool

	// ready records whether readerReady has been closed, so that Abort can
	// unblock Descriptor() waiters exactly once even if InitReader never ran.
	ready bool

	onDiskPath string
	onDiskFile *os.File

	// skipDiskWriteBytes is the number of leading bytes from the reader that
	// are already on disk (prefix from a partial resume). These bytes are
	// passed through to the caller (regclient) for digest verification but
	// are NOT written to disk again.
	skipDiskWriteBytes int64

	inFlightReader *blob.BReader
	clientMu       sync.RWMutex
	clientCond     *sync.Cond
	clients        map[int]chan int64
	nextClientId   int

	logger log.Logger
}

func NewChunkedBlobReader(onDiskPath string, logger log.Logger) (*ChunkedBlobReader, error) {
	// Check if a partial file already exists from a previous incomplete download.
	var existingBytes int64

	if info, statErr := os.Stat(onDiskPath); statErr == nil && info.Size() > 0 {
		existingBytes = info.Size()
		logger.Info().Str("path", onDiskPath).Int64("existingBytes", existingBytes).
			Msg("found partial blob file from previous download, will resume")
	}

	// Open in append mode if resuming, create/truncate otherwise.
	flags := os.O_CREATE | os.O_WRONLY
	if existingBytes > 0 {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	createdFile, err := os.OpenFile(onDiskPath, flags, 0o644)
	if err != nil {
		return nil, err
	}

	cbr := &ChunkedBlobReader{
		clients:            make(map[int]chan int64),
		logger:             logger,
		onDiskPath:         onDiskPath,
		onDiskFile:         createdFile,
		numBytesReadToDisk: existingBytes,
		readerReady:        make(chan struct{}),
	}

	cbr.clientCond = sync.NewCond(&cbr.clientMu)

	return cbr, nil
}

// ResumeOffset returns the number of bytes already written to disk from a
// previous incomplete download. If zero, no resume is needed.
func (cbr *ChunkedBlobReader) ResumeOffset() int64 {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	// Only meaningful before InitReader is called — once the reader is active,
	// numBytesReadToDisk grows as data arrives.
	if cbr.inFlightReader != nil {
		return 0
	}

	return cbr.numBytesReadToDisk
}

// Descriptor returns the descriptor of the blob being read.
// If the descriptor is not yet available, it waits until it is set by InitReader.
func (cbr *ChunkedBlobReader) Descriptor() descriptor.Descriptor {
	desc, _ := cbr.DescriptorContext(context.Background())

	return desc
}

// DescriptorContext is like Descriptor but aborts the wait when ctx is
// cancelled (e.g. the downstream HTTP client disconnected before the reader
// was initialized).
func (cbr *ChunkedBlobReader) DescriptorContext(ctx context.Context) (descriptor.Descriptor, error) {
	cbr.bytesMu.RLock()
	if cbr.inFlightReader != nil {
		desc := cbr.blobDesc
		cbr.bytesMu.RUnlock()

		return desc, nil
	}
	cbr.bytesMu.RUnlock()

	// Block without holding any lock until InitReader signals readiness.
	select {
	case <-cbr.readerReady:
	case <-ctx.Done():
		return descriptor.Descriptor{}, ctx.Err()
	}

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.blobDesc, nil
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
		cbr.markReady()

		return true
	}

	return false
}

// InitReaderComplete marks this blob as already fully downloaded.
// It signals readiness and notifies all waiting clients that the full blob is on disk.
// The caller should NOT call Read() after this — the blob file is complete.
func (cbr *ChunkedBlobReader) InitReaderComplete(blobReader *blob.BReader, desc descriptor.Descriptor) bool {
	cbr.bytesMu.Lock()

	if cbr.inFlightReader != nil {
		cbr.bytesMu.Unlock()

		return false
	}

	cbr.numBytesTotal = desc.Size
	cbr.numBytesReadToDisk = desc.Size
	cbr.inFlightReader = blobReader
	cbr.blobDesc = desc
	cbr.markReady()

	// Close the on-disk file since no more writing is needed.
	if cbr.onDiskFile != nil {
		cbr.onDiskFile.Close()
		cbr.onDiskFile = nil
	}

	cbr.bytesMu.Unlock()

	// Announce the final offset to clients that subscribed BEFORE this init:
	// Read() will never run for an already-complete blob, so this announcement
	// is their only chance to learn that all bytes are on disk. Without it,
	// early subscribers would wait forever (docker hangs at "Pulling fs layer").
	// Announcing after releasing bytesMu keeps the clientMu -> bytesMu lock
	// order used by Subscribe.
	cbr.announce(desc.Size)

	return true
}

// Initialized returns true once InitReader or InitReaderComplete has been called.
func (cbr *ChunkedBlobReader) Initialized() bool {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.inFlightReader != nil
}

// Completed returns true if the full blob has been written to disk.
func (cbr *ChunkedBlobReader) Completed() bool {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.inFlightReader != nil && cbr.numBytesTotal > 0 &&
		cbr.numBytesReadToDisk >= cbr.numBytesTotal
}

// Failed returns true if the in-flight download failed and the reader
// is waiting to be re-armed by a sync retry.
func (cbr *ChunkedBlobReader) Failed() bool {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.failed
}

// ReinitReader re-arms a failed reader with a fresh upstream stream so that a
// sync retry can continue the download in-place. The new stream re-delivers the
// blob from byte 0; bytes already on disk are passed through to the caller for
// digest verification but are not written to disk again. Announcements to
// subscribed clients resume from the current disk offset.
// Returns false if the reader is not in a failed state.
func (cbr *ChunkedBlobReader) ReinitReader(blobReader *blob.BReader, desc descriptor.Descriptor) bool {
	cbr.bytesMu.Lock()
	defer cbr.bytesMu.Unlock()

	if cbr.inFlightReader == nil || !cbr.failed || cbr.aborted {
		return false
	}

	cbr.inFlightReader = blobReader
	cbr.blobDesc = desc
	cbr.numBytesTotal = desc.Size
	cbr.skipDiskWriteBytes = cbr.numBytesReadToDisk
	cbr.failed = false

	cbr.logger.Info().Str("path", cbr.onDiskPath).
		Int64("resumeFrom", cbr.numBytesReadToDisk).Int64("totalSize", desc.Size).
		Msg("re-armed failed blob reader for retry, resuming from disk offset")

	return true
}

// SetSkipDiskWriteBytes sets the number of leading bytes in the reader stream
// that should be passed through for digest verification but NOT written to disk
// (because they are already on disk from a previous partial download).
func (cbr *ChunkedBlobReader) SetSkipDiskWriteBytes(n int64) {
	cbr.skipDiskWriteBytes = n
}

func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	// InitReader is called inside the regclient callback
	// When Read is called the reader will always be initialized.
	cbr.bytesMu.RLock()
	inFlightReader := cbr.inFlightReader
	cbr.bytesMu.RUnlock()

	// The upstream (network) read happens without holding bytesMu so that a
	// stalled upstream can never block Subscribe -- and, through ConnectClient
	// (which holds the manager's streamLock while subscribing), the entire
	// streaming subsystem. Read is only ever called serially by regclient, and
	// ReinitReader only swaps the reader after a failed attempt has returned,
	// so reading without the lock is safe.
	n, err := io.ReadFull(inFlightReader, buff)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			// upstream download error
			cbr.logger.Error().Err(err).Msg("failed to read from in flight reader")

			cbr.bytesMu.Lock()
			cbr.failed = true
			cbr.bytesMu.Unlock()

			// drain all clients and close their channels so they don't hang
			cbr.closeAllClients()

			return n, err
		}
		// partial read at end of stream; normalise to EOF for callers
		err = io.EOF
	}

	cbr.bytesMu.Lock()

	if n > 0 {
		// Determine how many of these bytes should actually be written to disk.
		// When resuming with MultiReader, the leading bytes (the disk prefix) are
		// passed through for regclient digest verification but already exist on disk.
		writeBytes := buff[:n]
		if cbr.skipDiskWriteBytes > 0 {
			skip := int64(n)
			if skip > cbr.skipDiskWriteBytes {
				skip = cbr.skipDiskWriteBytes
			}

			cbr.skipDiskWriteBytes -= skip
			writeBytes = buff[skip:n]
		}

		if len(writeBytes) > 0 {
			if _, werr := cbr.onDiskFile.Write(writeBytes); werr != nil {
				cbr.logger.Error().Err(werr).Msg("failed to write blob data to disk")
				cbr.failed = true
				cbr.bytesMu.Unlock()

				// drain all clients and close their channels so they don't hang
				cbr.closeAllClients()

				return n, werr
			}

			cbr.numBytesReadToDisk += int64(len(writeBytes))
		}
	}

	if cbr.numBytesTotal > 0 && cbr.numBytesReadToDisk >= cbr.numBytesTotal {
		if cbr.onDiskFile != nil {
			if clsErr := cbr.onDiskFile.Close(); clsErr != nil {
				cbr.logger.Error().Err(clsErr).Msg("failed to close on disk file")
			}

			cbr.onDiskFile = nil
		}
		// All bytes have been written to disk; treat as EOF regardless of
		// what io.ReadFull returned. This handles the case where the caller's
		// buffer is exactly the remaining data size and io.ReadFull returns
		// (n, nil) instead of (n, io.ErrUnexpectedEOF).
		err = io.EOF
	}

	numBytesRead := cbr.numBytesReadToDisk
	cbr.bytesMu.Unlock()

	cbr.announce(numBytesRead)

	return n, err
}

// announce publishes the latest on-disk byte offset to all subscribed clients.
// Sends never block: each client channel is buffered with capacity 1 and holds
// only the most recent offset -- a stale queued value is replaced by the new
// one. Copiers only act on the latest offset, so dropping intermediate values
// is harmless, and a slow (or already finished) consumer can never stall the
// download or deadlock clientMu.
func (cbr *ChunkedBlobReader) announce(numBytesRead int64) {
	cbr.clientMu.Lock()
	defer cbr.clientMu.Unlock()

	for _, channel := range cbr.clients {
		select {
		case channel <- numBytesRead:
		default:
			// Channel full: drop the stale offset and push the latest one.
			// Read (the only announcer) is serial and Subscribe's initial send
			// holds clientMu too, so the send after the drain cannot race with
			// another sender and always succeeds.
			select {
			case <-channel:
			default:
			}
			select {
			case channel <- numBytesRead:
			default:
			}
		}
	}
}

// closeAllClients unsubscribes every client and closes their channels so that
// waiting copiers wake up (and report a download error to their downstream).
func (cbr *ChunkedBlobReader) closeAllClients() {
	cbr.clientMu.Lock()
	defer func() {
		cbr.clientCond.Broadcast()
		cbr.clientMu.Unlock()
	}()

	for clientId, channel := range cbr.clients {
		close(channel)
		delete(cbr.clients, clientId)
	}
}

// markReady closes readerReady exactly once. Callers must hold bytesMu.
func (cbr *ChunkedBlobReader) markReady() {
	if !cbr.ready {
		cbr.ready = true
		close(cbr.readerReady)
	}
}

// Abort puts the reader in a terminal state: the sync gave up on this blob and
// no re-arm will follow. All current subscribers are closed, Descriptor()
// waiters are unblocked, and future Subscribe calls receive an already-closed
// channel so no client can ever hang on this reader. Any partial on-disk file
// is kept for a potential future resume.
func (cbr *ChunkedBlobReader) Abort() {
	cbr.bytesMu.Lock()
	cbr.aborted = true
	cbr.failed = true

	// Unblock any Descriptor() waiters in case the reader was never initialized.
	cbr.markReady()

	if cbr.onDiskFile != nil {
		if err := cbr.onDiskFile.Close(); err != nil {
			cbr.logger.Error().Err(err).Msg("failed to close on disk file on abort")
		}

		cbr.onDiskFile = nil
	}
	cbr.bytesMu.Unlock()

	cbr.closeAllClients()
}

// Aborted returns true if the reader is in the terminal aborted state.
func (cbr *ChunkedBlobReader) Aborted() bool {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.aborted
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

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	// A terminally-aborted reader accepts no new subscribers: hand back an
	// already-closed channel so the copier fails fast instead of hanging on a
	// stream that will never advance.
	if cbr.aborted {
		close(channel)

		return channel, -1
	}

	cbr.clients[cbr.nextClientId] = channel
	chanId := cbr.nextClientId
	cbr.nextClientId++
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
