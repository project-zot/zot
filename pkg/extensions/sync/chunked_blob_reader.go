//go:build sync

package sync

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// ChunkedBlobReader writes a blob to disk as it is read from upstream and announces each new
// on-disk offset to the clients streaming it.
type ChunkedBlobReader struct {
	numBytesTotal      int64
	numBytesReadToDisk int64
	// readMu serializes the producer (Read). It, not bytesMu, is held across the blocking upstream
	// read and disk write, so a stalled upstream never blocks Descriptor, Err or Subscribe (the
	// last two run under the stream manager's manager-wide streamLock).
	readMu  sync.Mutex
	bytesMu sync.RWMutex
	// readerReady is closed once the producer is known: by InitReader, or by Abort if it never
	// will be.
	readerReady chan struct{}
	// readerClosed is set by the first InitReader or Abort; after that no producer is accepted.
	readerClosed bool
	abortErr     error
	// readErr is set when the producer fails partway; no more bytes will ever be announced.
	readErr  error
	blobDesc descriptor.Descriptor

	onDiskPath string
	onDiskFile *os.File

	inFlightReader *blob.BReader
	diskFileClosed bool
	clientMu       sync.RWMutex
	clientCond     *sync.Cond
	clients        map[int]chan int64
	nextClientId   int

	logger log.Logger
}

// streamInitTimeout is a last-resort bound on how long Descriptor waits for a blob's download to
// start (normally Abort ends the wait once the sync is over). It is generous because regclient
// queues blobs behind a small per-host concurrency limit, so a healthy blob can wait minutes
// behind large earlier layers.
const streamInitTimeout = 15 * time.Minute

func NewChunkedBlobReader(onDiskPath string, logger log.Logger) (*ChunkedBlobReader, error) {
	createdFile, err := os.OpenFile(onDiskPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
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

// OnDiskPath returns the temp file the blob is written to.
func (cbr *ChunkedBlobReader) OnDiskPath() string {
	return cbr.onDiskPath
}

// Descriptor returns the blob's descriptor, waiting up to streamInitTimeout for its download to
// start. See DescriptorWithTimeout.
func (cbr *ChunkedBlobReader) Descriptor() (descriptor.Descriptor, error) {
	return cbr.DescriptorWithTimeout(streamInitTimeout)
}

// DescriptorWithTimeout is Descriptor with an explicit timeout (so tests needn't wait the full
// streamInitTimeout). It waits until InitReader or Abort runs, or timeout elapses. It returns an
// error if the download never started or failed partway.
func (cbr *ChunkedBlobReader) DescriptorWithTimeout(timeout time.Duration) (descriptor.Descriptor, error) {
	cbr.bytesMu.RLock()
	if cbr.inFlightReader != nil {
		desc, readErr := cbr.blobDesc, cbr.readErr
		cbr.bytesMu.RUnlock()

		if readErr != nil {
			return descriptor.Descriptor{}, upstreamFailure(readErr)
		}

		return desc, nil
	}
	cbr.bytesMu.RUnlock()

	// Wait without holding the lock; readerReady is never reassigned, so reading it unlocked is safe.
	select {
	case <-cbr.readerReady:
	case <-time.After(timeout):
		return descriptor.Descriptor{}, zerr.ErrStreamInitTimeout
	}

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	if cbr.inFlightReader == nil {
		// Closed by Abort, not InitReader: the blob is never coming.
		return descriptor.Descriptor{}, cbr.abortErr
	}

	if cbr.readErr != nil {
		return descriptor.Descriptor{}, upstreamFailure(cbr.readErr)
	}

	return cbr.blobDesc, nil
}

// upstreamFailure wraps a failed producer's err in ErrSyncUpstreamDownloadFailed, the error an
// attached client's Copy already reports for the same failure.
func upstreamFailure(err error) error {
	return fmt.Errorf("%w: %w", zerr.ErrSyncUpstreamDownloadFailed, err)
}

// Err returns the error the producer failed with, or nil if it hasn't failed.
func (cbr *ChunkedBlobReader) Err() error {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.readErr
}

// InitReader makes blobReader this blob's producer. It returns false if a producer was already
// set or the reader was aborted.
//
// Only the first producer is ever accepted, even after it fails: reusing the temp file for a retry
// would corrupt what clients of the first attempt are still reading. A failed blob therefore
// fails for every reference sharing it, and each recovers through its own sync's retry, which
// restages a fresh reader.
func (cbr *ChunkedBlobReader) InitReader(blobReader *blob.BReader, desc descriptor.Descriptor) bool {
	cbr.bytesMu.Lock()
	defer cbr.bytesMu.Unlock()

	if cbr.readerClosed {
		return false
	}

	cbr.numBytesTotal = desc.Size
	cbr.inFlightReader = blobReader
	cbr.blobDesc = desc
	cbr.readerClosed = true
	close(cbr.readerReady)

	return true
}

// Abort is called at teardown, once no sync will feed this blob again, so the temp file can be
// closed and deleted:
//   - never started: ends the wait in Descriptor with ErrStreamNeverInitialized.
//   - started but incomplete (the sync stopped mid-blob, e.g. another blob failed): fails the
//     producer with ErrStreamIncomplete, so attached clients fail now instead of waiting out the
//     drain timeout for bytes that will never come.
//   - complete or already failed: no-op, so clients reading a finished file can drain it.
//
// It takes only bytesMu, never readMu, so a producer stalled in an upstream read can't block
// teardown; that read then fails writing to the closed file.
func (cbr *ChunkedBlobReader) Abort() {
	cbr.bytesMu.Lock()

	if !cbr.readerClosed {
		defer cbr.bytesMu.Unlock()

		cbr.abortErr = zerr.ErrStreamNeverInitialized
		cbr.readerClosed = true
		close(cbr.readerReady)
		cbr.closeDiskFileLocked()

		return
	}

	// diskFileClosed is set on completion and on failure, so false means started but incomplete.
	incomplete := cbr.inFlightReader != nil && !cbr.diskFileClosed
	cbr.bytesMu.Unlock()

	if incomplete {
		cbr.logger.Warn().Str("onDiskPath", cbr.onDiskPath).
			Msg("sync ended before streamed blob finished downloading, failing its clients")
		cbr.fail(zerr.ErrStreamIncomplete)
	}
}

// fail records err as the producer's failure, closes the temp file and fails every client. readErr
// is set before abortAllClients runs, so it also turns away later subscribers.
func (cbr *ChunkedBlobReader) fail(err error) {
	cbr.bytesMu.Lock()

	if cbr.readErr == nil {
		cbr.readErr = err
	}

	cbr.closeDiskFileLocked()
	cbr.bytesMu.Unlock()

	cbr.abortAllClients()
}

// closeDiskFileLocked closes onDiskFile once. Must be called with bytesMu held.
func (cbr *ChunkedBlobReader) closeDiskFileLocked() {
	if cbr.diskFileClosed {
		return
	}

	if err := cbr.onDiskFile.Close(); err != nil {
		cbr.logger.Error().Err(err).Str("onDiskPath", cbr.onDiskPath).Msg("failed to close blob temp file")
	}

	cbr.diskFileClosed = true
}

// Read reads the next chunk from upstream, writes it to disk, and announces the new offset to
// every client.
//
// regclient checks the digest only when its source hits EOF, and wraps a mismatch so that
// errors.Is(err, io.EOF) is still true. classifyReadErr checks for integrity errors first, so a
// corrupt blob is never treated as a clean end of stream.
func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	cbr.readMu.Lock()
	defer cbr.readMu.Unlock()

	// regclient only calls Read after the hook ran InitReader, so inFlightReader is set and it and
	// numBytesTotal no longer change. After InitReader only Read writes numBytesReadToDisk and
	// diskFileClosed, so under readMu the snapshot stays current until Read publishes below.
	cbr.bytesMu.RLock()
	upstream, numBytesTotal := cbr.inFlightReader, cbr.numBytesTotal
	numBytesRead, diskFileClosed := cbr.numBytesReadToDisk, cbr.diskFileClosed
	cbr.bytesMu.RUnlock()

	n, err := io.ReadFull(upstream, buff)

	switch classifyReadErr(err) {
	case readErrIntegrityFailure, readErrUpstream:
		// Integrity or upstream failure: don't write or announce these bytes; fail every client.
		cbr.logIntegrityOrUpstreamError(err)
		cbr.fail(err)

		return n, err

	case readErrEOF:
		// partial read at end of stream; normalise to EOF for callers
		err = io.EOF
	}

	if n > 0 {
		// Only the producer touches onDiskFile once InitReader ran, so readMu covers the write.
		if _, werr := cbr.onDiskFile.Write(buff[:n]); werr != nil {
			cbr.logger.Error().Err(werr).Msg("failed to write blob data to disk")
			// Fail clients now rather than leave them waiting for the drain timeout.
			cbr.fail(werr)

			return n, werr
		}

		numBytesRead += int64(n)
	}

	complete := !diskFileClosed && numBytesRead >= numBytesTotal
	if complete && err == nil {
		// The buffer filled exactly at the blob's end, so upstream hasn't hit EOF and its digest
		// check hasn't run yet. Read one more byte to force it before calling the blob complete.
		var probe [1]byte

		_, verifyErr := upstream.Read(probe[:])
		if class := classifyReadErr(verifyErr); class == readErrIntegrityFailure || class == readErrUpstream {
			cbr.logIntegrityOrUpstreamError(verifyErr)
			cbr.fail(verifyErr)

			return n, verifyErr
		}
	}

	cbr.bytesMu.Lock()
	cbr.numBytesReadToDisk = numBytesRead

	if complete {
		cbr.closeDiskFileLocked()

		err = io.EOF
	}
	cbr.bytesMu.Unlock()

	cbr.clientMu.Lock()
	// Announce the new offset without ever blocking: channels hold one value and clients only need
	// the latest, so drop a stale one first. A blocking send would let one stalled client wedge the
	// whole download.
	for _, clientChan := range cbr.clients {
		select {
		case <-clientChan:
		default:
		}

		clientChan <- numBytesRead
	}

	cbr.clientMu.Unlock()

	return n, err
}

// logIntegrityOrUpstreamError logs err as an integrity failure or an upstream read failure.
func (cbr *ChunkedBlobReader) logIntegrityOrUpstreamError(err error) {
	if isIntegrityErr(err) {
		cbr.logger.Error().Err(err).Msg("failed to verify blob integrity, aborting stream")

		return
	}

	cbr.logger.Error().Err(err).Msg("failed to read from in flight reader")
}

// isIntegrityErr reports whether err is regclient's digest or size check failing.
func isIntegrityErr(err error) bool {
	return errors.Is(err, errs.ErrDigestMismatch) ||
		errors.Is(err, errs.ErrShortRead) ||
		errors.Is(err, errs.ErrSizeLimitExceeded)
}

// readErrClass categorizes the error returned by a read from the upstream blob reader.
type readErrClass int

const (
	readErrNone readErrClass = iota
	// readErrEOF is a clean end of stream: the digest check ran and passed.
	readErrEOF
	// readErrIntegrityFailure is a failed digest/size check. It also matches io.EOF, so it must be
	// checked first.
	readErrIntegrityFailure
	// readErrUpstream is any other (network/upstream) error.
	readErrUpstream
)

func classifyReadErr(err error) readErrClass {
	switch {
	case err == nil:
		return readErrNone
	case isIntegrityErr(err):
		return readErrIntegrityFailure
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return readErrEOF
	default:
		return readErrUpstream
	}
}

// abortAllClients closes every client's channel, telling each copier the download failed.
func (cbr *ChunkedBlobReader) abortAllClients() {
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

// Subscribe registers a client and returns the channel its new offsets are sent on, plus an id
// for Unsubscribe.
//
// If the producer already failed, the channel comes back closed and unregistered (id -1), so a
// late client doesn't wait for announcements that will never come. Read sets readErr before
// abortAllClients runs, so every client is either aborted there or turned away here.
func (cbr *ChunkedBlobReader) Subscribe() (chan int64, int) {
	cbr.clientMu.Lock()
	defer func() {
		cbr.clientCond.Broadcast()
		cbr.clientMu.Unlock()
	}()

	channel := make(chan int64, 1)

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	if cbr.readErr != nil {
		close(channel)

		return channel, -1
	}

	cbr.clients[cbr.nextClientId] = channel
	chanId := cbr.nextClientId
	cbr.nextClientId++
	// Send the current offset (if the download has started) while still holding clientMu, so
	// Unsubscribe can't close the channel first.
	if cbr.inFlightReader != nil {
		channel <- cbr.numBytesReadToDisk
	}

	return channel, chanId
}

// Unsubscribe removes a client and closes its channel. Unknown ids (including -1) are ignored.
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

// ToBReader returns a regclient reader that reads through this ChunkedBlobReader, so the copy
// into storage also writes the temp file and feeds clients.
func (cbr *ChunkedBlobReader) ToBReader() *blob.BReader {
	return blob.NewReader(
		blob.WithHeader(cbr.inFlightReader.RawHeaders()),
		blob.WithDesc(cbr.inFlightReader.GetDescriptor()),
		blob.WithReader(cbr),
	)
}

// WaitForClientEmpty waits until every client has unsubscribed, or timeout elapses. On timeout
// the remaining clients are disconnected (their copies fail), so cleanup never waits forever.
func (cbr *ChunkedBlobReader) WaitForClientEmpty(timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	// sync.Cond has no timed wait, so a ticker re-broadcasts to let the loop check the deadline.
	stopTicker := make(chan struct{})
	defer close(stopTicker)

	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stopTicker:
				return
			case <-ticker.C:
				cbr.clientMu.Lock()
				cbr.clientCond.Broadcast()
				cbr.clientMu.Unlock()
			}
		}
	}()

	cbr.clientMu.Lock()

	for len(cbr.clients) > 0 && time.Now().Before(deadline) {
		cbr.clientCond.Wait()
	}

	if len(cbr.clients) > 0 {
		cbr.logger.Warn().Int("remainingClients", len(cbr.clients)).
			Msg("timed out waiting for streaming clients to drain, forcing disconnect")

		for clientId, channel := range cbr.clients {
			close(channel)
			delete(cbr.clients, clientId)
		}
	}

	cbr.clientMu.Unlock()
}
