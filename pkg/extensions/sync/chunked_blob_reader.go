//go:build sync

package sync

import (
	"context"
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

// ChunkedBlobReader writes a blob to a temp file as it is downloaded from upstream, and announces
// each new offset to the clients streaming it. Once complete, the background sync links the file
// into its layout (see ChunkingStreamManager.DownloadStreamedBlobs), so it is the only copy.
type ChunkedBlobReader struct {
	numBytesTotal      int64
	numBytesReadToDisk int64
	// readMu serializes Read and is held across the blocking upstream read; bytesMu is not, so a
	// stalled upstream can't block Descriptor, Err or Subscribe (and so streamLock).
	readMu  sync.Mutex
	bytesMu sync.RWMutex
	// readerReady is closed by InitReader, or by Abort if no producer will come.
	readerReady chan struct{}
	// readerClosed is set by the first InitReader, Abort or FailStart; after that no producer is
	// accepted.
	readerClosed bool
	// claimed is set by the first Claim, so one sync downloads the blob and the rest wait.
	claimed bool
	// done is closed with the temp file: on completion, failure, or Abort before a start.
	done     chan struct{}
	abortErr error
	// readErr is set when the producer fails; nothing more will be announced.
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
		done:        make(chan struct{}),
	}

	cbr.clientCond = sync.NewCond(&cbr.clientMu)

	return cbr, nil
}

// OnDiskPath returns the temp file the blob is written to.
func (cbr *ChunkedBlobReader) OnDiskPath() string {
	return cbr.onDiskPath
}

// Descriptor returns the blob's descriptor, waiting for its download to start (InitReader), for
// Abort or FailStart, or for ctx (a gone client must not hold its handler). It errors if the
// download never started or failed.
//
// There is no deadline of its own: a healthy blob can be queued behind others for as long as the
// sync runs (regclient limits concurrent downloads per host), and the wait is bounded anyway. The
// sync runs under the registry's syncTimeout, and its teardown (RemoveStreamingImage) always
// follows and Aborts every stream it leaves unstarted.
func (cbr *ChunkedBlobReader) Descriptor(ctx context.Context) (descriptor.Descriptor, error) {
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

	// readerReady is never reassigned, so waiting on it unlocked is safe.
	select {
	case <-cbr.readerReady:
	case <-ctx.Done():
		return descriptor.Descriptor{}, ctx.Err()
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

// upstreamFailure wraps err in ErrSyncUpstreamDownloadFailed, as a client's Copy reports it.
func upstreamFailure(err error) error {
	return fmt.Errorf("%w: %w", zerr.ErrSyncUpstreamDownloadFailed, err)
}

// Err returns the error the producer failed with, or nil if it hasn't failed.
func (cbr *ChunkedBlobReader) Err() error {
	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	return cbr.readErr
}

// Claim reports whether the caller is the first to claim this blob's download; the caller must then
// call InitReader or FailStart. Others wait for the download with Wait.
func (cbr *ChunkedBlobReader) Claim() bool {
	cbr.bytesMu.Lock()
	defer cbr.bytesMu.Unlock()

	if cbr.readerClosed || cbr.claimed {
		return false
	}

	cbr.claimed = true

	return true
}

// FailStart fails a claimed download that couldn't start (e.g. upstream refused the GET): waiting
// clients get err rather than wait for teardown, and later ones are turned away.
func (cbr *ChunkedBlobReader) FailStart(err error) {
	cbr.bytesMu.Lock()

	if cbr.readerClosed {
		cbr.bytesMu.Unlock()

		return
	}

	cbr.readErr = err
	cbr.abortErr = upstreamFailure(err)
	cbr.readerClosed = true
	close(cbr.readerReady)
	cbr.closeDiskFileLocked()
	cbr.bytesMu.Unlock()

	cbr.abortAllClients()
}

// Wait waits for the download to finish, or ctx. It returns nil only if the blob is complete and
// verified.
func (cbr *ChunkedBlobReader) Wait(ctx context.Context) error {
	select {
	case <-cbr.done:
	case <-ctx.Done():
		return ctx.Err()
	}

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	switch {
	case cbr.readErr != nil:
		return cbr.readErr
	case cbr.inFlightReader == nil:
		return cbr.abortErr
	case cbr.numBytesReadToDisk < cbr.numBytesTotal:
		return zerr.ErrStreamIncomplete
	}

	return nil
}

// InitReader makes blobReader this blob's producer, or returns false if one was already set or the
// reader was aborted.
//
// Only the first producer is accepted, even if it fails: a retry rewriting the temp file would
// corrupt what earlier clients are reading. A retry restages with a fresh reader instead.
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

// Abort runs at teardown, once nothing will feed this blob:
//   - never started: Descriptor's wait ends with ErrStreamNeverInitialized.
//   - incomplete (e.g. another blob failed the sync): fails with ErrStreamIncomplete, so clients
//     fail now rather than wait out the drain timeout.
//   - complete or already failed: no-op, so clients can drain a finished file.
//
// It never takes readMu, so a producer stalled upstream can't block teardown.
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

// fail records err, closes the temp file and fails every client. readErr is set first, so later
// subscribers are turned away too.
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
	close(cbr.done)
}

// fillChunkSize is how much Fill reads per Read, and so how often clients hear of new bytes. It is
// io.Copy's buffer size, which the sync's own write into its layout used before.
const fillChunkSize = 32 * 1024

// Fill reads the whole blob from the producer set by InitReader, writing it to the temp file and
// announcing each chunk. It returns nil once the blob is complete and verified.
func (cbr *ChunkedBlobReader) Fill() error {
	buf := make([]byte, fillChunkSize)

	for {
		_, err := cbr.Read(buf)
		if err == nil {
			continue
		}

		// regclient's digest mismatch also matches io.EOF, so check for a failure first.
		if readErr := cbr.Err(); readErr != nil {
			return readErr
		}

		if !errors.Is(err, io.EOF) {
			return err
		}

		break
	}

	cbr.bytesMu.RLock()
	complete := cbr.diskFileClosed && cbr.numBytesReadToDisk >= cbr.numBytesTotal
	cbr.bytesMu.RUnlock()

	// A clean EOF short of the descriptor's size: regclient checks the size, but don't leave
	// clients waiting for bytes that will never come.
	if !complete {
		cbr.fail(zerr.ErrStreamIncomplete)

		return zerr.ErrStreamIncomplete
	}

	return nil
}

// Read reads the next chunk from upstream, writes it to the temp file, and announces the new
// offset. regclient's digest mismatch also matches io.EOF, so integrity errors are checked first.
func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	cbr.readMu.Lock()
	defer cbr.readMu.Unlock()

	// After InitReader, only Read writes these fields, so under readMu the snapshot stays current.
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
		// Partial read at the end: report a plain EOF.
		err = io.EOF
	}

	if n > 0 {
		// Only the producer writes onDiskFile, so readMu covers it.
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
		// Filled exactly at the end: upstream hasn't hit EOF, so its digest check hasn't run.
		// Read one more byte to force it before calling the blob complete.
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
	// Never block: a stalled client must not wedge the download. Clients only need the latest
	// offset, so replace any unread one.
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
	// readErrIntegrityFailure is a failed digest/size check (also matches io.EOF: check first).
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

// Subscribe registers a client and returns its offset channel and an id for Unsubscribe. If the
// producer already failed, the channel comes back closed with id -1.
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
	// Send the current offset under clientMu, so Unsubscribe can't close the channel first.
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

// WaitForClientEmpty waits for every client to unsubscribe, or timeout. On timeout the remaining
// clients are disconnected (their copies fail).
func (cbr *ChunkedBlobReader) WaitForClientEmpty(timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	// sync.Cond has no timed wait: a ticker re-broadcasts so the loop checks the deadline.
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
