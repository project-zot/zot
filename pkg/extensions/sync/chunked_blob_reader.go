//go:build sync

package sync

import (
	"errors"
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

// ChunkedBlobReader copies a blob to disk as it is read from upstream, and keeps track of
// clients that are being served the blob. The latest byte offset written to disk is announced
// to each subscribed client's channel.
type ChunkedBlobReader struct {
	numBytesTotal      int64
	numBytesReadToDisk int64
	bytesMu            sync.RWMutex
	readerReady        chan struct{}
	readerClosed       bool
	abortErr           error
	blobDesc           descriptor.Descriptor

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

// streamInitTimeout is a last-resort bound on how long Descriptor waits for InitReader to run,
// covering only the case where nothing else ever unblocks it - ordinarily Abort (called once the
// owning background sync is known to be finished, successfully or not, without ever reaching this
// blob - see stream_manager.go's drainAndDeleteStreams) does that promptly instead. It has to be
// generous: regclient's ImageCopy launches every blob's copy concurrently, but the default
// per-host request concurrency (3) still queues most blobs behind others, so a blob that is
// perfectly healthy - the sync is still running and will get to it - can easily wait several
// minutes behind large earlier layers, well within a sync that's allowed to run for hours (see
// RegistryConfig.SyncTimeout).
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

// OnDiskPath returns the path this reader is writing (and has already written) the blob to.
func (cbr *ChunkedBlobReader) OnDiskPath() string {
	return cbr.onDiskPath
}

// Descriptor returns the descriptor of the blob being read, waiting up to streamInitTimeout for
// InitReader to set it if it is not yet available. See DescriptorWithTimeout.
func (cbr *ChunkedBlobReader) Descriptor() (descriptor.Descriptor, error) {
	return cbr.DescriptorWithTimeout(streamInitTimeout)
}

// DescriptorWithTimeout is Descriptor with an explicit timeout, split out so tests don't have to
// wait streamInitTimeout out in full - the same reason WaitForClientEmpty takes its timeout as a
// parameter rather than a package constant.
//
// If the descriptor is not yet available, it waits until InitReader or Abort resolves it, or
// timeout elapses - whichever comes first. InitReader only runs once regclient's copy actually
// reaches this blob (via the StreamingBlobReader hook); Abort runs once the owning background
// sync is known to be finished without ever reaching it (see its doc comment). Without either of
// those, or the timeout, a caller blocked here would hang indefinitely.
func (cbr *ChunkedBlobReader) DescriptorWithTimeout(timeout time.Duration) (descriptor.Descriptor, error) {
	cbr.bytesMu.RLock()
	if cbr.inFlightReader != nil {
		desc := cbr.blobDesc
		cbr.bytesMu.RUnlock()

		return desc, nil
	}
	cbr.bytesMu.RUnlock()

	// Block without holding any lock until InitReader/Abort signals resolution, or timeout elapses.
	select {
	case <-cbr.readerReady:
	case <-time.After(timeout):
		return descriptor.Descriptor{}, zerr.ErrStreamInitTimeout
	}

	cbr.bytesMu.RLock()
	defer cbr.bytesMu.RUnlock()

	if cbr.inFlightReader == nil {
		// readerReady was closed by Abort, not InitReader - the blob is never coming.
		return descriptor.Descriptor{}, cbr.abortErr
	}

	return cbr.blobDesc, nil
}

// InitReader sets the regclient blob reader and the total number of bytes to read for the blob.
// Returns true if the init modified the reader, else false if the reader was already initialized
// or already aborted (see Abort).
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

// Abort unblocks any waiter in Descriptor/DescriptorWithTimeout with err, for a reader whose
// InitReader is now known to never run - the background sync that would have reached this blob
// has finished (successfully, having skipped the copy entirely, or with a failure/cancellation)
// without doing so. Called from drainAndDeleteStreams for every reader RemoveStreamingImage is
// tearing down. A no-op if InitReader (or an earlier Abort) already resolved this reader.
func (cbr *ChunkedBlobReader) Abort(err error) {
	cbr.bytesMu.Lock()
	defer cbr.bytesMu.Unlock()

	if cbr.readerClosed {
		return
	}

	cbr.abortErr = err
	cbr.readerClosed = true
	close(cbr.readerReady)
}

// Read reads the next chunk from the upstream blob reader, writes it to disk, and announces the
// new on-disk byte offset to every subscribed client.
//
// The upstream reader (regclient's blob.BReader) computes a running digest as bytes are read and
// only compares it against the expected digest on the final Read call, once its source reports
// literal io.EOF. That comparison error, and an equivalent short-read/oversized-read error, are
// wrapped so that errors.Is(err, io.EOF) is true even though the real problem is a failed
// integrity check - see classifyReadErr, which the integrity sentinels must be checked through
// before treating anything as a normal end of stream, or a corrupted/tampered blob would be
// silently treated as a complete, valid download and streamed to clients as such.
func (cbr *ChunkedBlobReader) Read(buff []byte) (int, error) {
	// InitReader is called inside the regclient callback
	// When Read is called the reader will always be initialized.
	cbr.bytesMu.Lock()

	n, err := io.ReadFull(cbr.inFlightReader, buff)

	switch classifyReadErr(err) {
	case readErrIntegrityFailure, readErrUpstream:
		// Real error: either a failed integrity check, or a genuine upstream/network failure.
		// Never write these bytes to disk or announce them as if the blob completed successfully
		// - abort every subscriber with the real error instead.
		cbr.logIntegrityOrUpstreamError(err)
		cbr.bytesMu.Unlock()
		cbr.abortAllClients()

		return n, err

	case readErrEOF:
		// partial read at end of stream; normalise to EOF for callers
		err = io.EOF
	}

	if n > 0 {
		if _, werr := cbr.onDiskFile.Write(buff[:n]); werr != nil {
			cbr.logger.Error().Err(werr).Msg("failed to write blob data to disk")
			cbr.bytesMu.Unlock()
			// Same reasoning as the integrity/upstream error branch above: subscribers waiting on
			// an announcement would otherwise block until RemoveStreamingImage's drain timeout
			// forces them out, well after this Read loop has already given up.
			cbr.abortAllClients()

			return n, werr
		}

		cbr.numBytesReadToDisk += int64(n)
	}

	if !cbr.diskFileClosed && cbr.numBytesReadToDisk >= cbr.numBytesTotal {
		if err == nil {
			// The caller's buffer happened to fill exactly at the blob's boundary, so the
			// underlying reader has not yet been asked for one more byte and so has not yet
			// observed a literal EOF - which is the only place its digest check runs (see the
			// doc comment above). Force that call now rather than declaring success without it:
			// a well-formed, exactly buffer-aligned blob is exactly the case where skipping this
			// would let a corrupted blob's mismatch go completely unverified by this reader.
			var probe [1]byte

			_, verifyErr := cbr.inFlightReader.Read(probe[:])
			if class := classifyReadErr(verifyErr); class == readErrIntegrityFailure || class == readErrUpstream {
				cbr.logIntegrityOrUpstreamError(verifyErr)
				cbr.bytesMu.Unlock()
				cbr.abortAllClients()

				return n, verifyErr
			}
		}

		clsErr := cbr.onDiskFile.Close()
		if clsErr != nil {
			cbr.logger.Error().Err(clsErr).Msg("failed to close on disk file")
		}

		cbr.diskFileClosed = true
		err = io.EOF
	}

	numBytesRead := cbr.numBytesReadToDisk
	cbr.bytesMu.Unlock()

	cbr.clientMu.Lock()
	// Update all clients about the latest byte offset available on disk. Each client's channel is
	// buffer-1 (see Subscribe); a client only ever cares about the newest offset (InFlightBlobCopier
	// just reads latestOffset.Load()), so a stale, undrained notification is discarded before
	// sending the new one instead of blocking on it. This must never block while clientMu is held:
	// a blocking send here would let one stalled/disconnected client wedge this Read call - and so
	// the upstream copy driving it - forever, since the only things that could unblock it
	// (Unsubscribe, WaitForClientEmpty) need this same lock to run.
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

// logIntegrityOrUpstreamError logs err with detail appropriate to which of the two real-error
// classifyReadErr categories it falls into.
func (cbr *ChunkedBlobReader) logIntegrityOrUpstreamError(err error) {
	if isIntegrityErr(err) {
		cbr.logger.Error().Err(err).Msg("failed to verify blob integrity, aborting stream")

		return
	}

	cbr.logger.Error().Err(err).Msg("failed to read from in flight reader")
}

// isIntegrityErr reports whether err is one of the upstream blob reader's own digest/size
// checks failing - shared by logIntegrityOrUpstreamError and classifyReadErr, which must agree
// on exactly which errors count as an integrity failure rather than a plain EOF or a generic
// upstream error.
func isIntegrityErr(err error) bool {
	return errors.Is(err, errs.ErrDigestMismatch) ||
		errors.Is(err, errs.ErrShortRead) ||
		errors.Is(err, errs.ErrSizeLimitExceeded)
}

// readErrClass categorizes the error returned by a read from the upstream blob reader.
type readErrClass int

const (
	readErrNone readErrClass = iota
	// readErrEOF is a normal end of stream: the upstream reader's own digest/size check (which
	// only runs once its source reports literal io.EOF) already ran and passed.
	readErrEOF
	// readErrIntegrityFailure is the upstream reader's digest/size check having failed - wrapped
	// around an io.EOF/io.ErrUnexpectedEOF, so errors.Is(err, io.EOF) is true for this case too;
	// callers must check this category first.
	readErrIntegrityFailure
	// readErrUpstream is any other error: a genuine network/upstream failure.
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

// abortAllClients unsubscribes and closes the channel of every current subscriber, signalling
// to InFlightBlobCopier that the stream ended without reaching the blob's full size.
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

// WaitForClientEmpty blocks until every subscribed client has unsubscribed, or until timeout
// elapses - whichever comes first. On timeout, every remaining client is force-unsubscribed (its
// channel closed) so callers always make progress in bounded time regardless of how long a
// stalled or abandoned client takes to disconnect on its own. A force-unsubscribed client's
// InFlightBlobCopier observes its channel close and aborts with ErrSyncUpstreamDownloadFailed,
// which is the correct outcome for a client that stopped consuming.
func (cbr *ChunkedBlobReader) WaitForClientEmpty(timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	// sync.Cond has no timed wait, so a ticker goroutine periodically re-broadcasts to unblock
	// the Wait() loop below and let it re-check the deadline.
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
