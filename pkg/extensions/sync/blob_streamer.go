//go:build sync

package sync

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
)

const defaultChunkSize = 10 * 1024 * 1024 // 10MB default chunk size

// BlobStreamer manages streaming of a blob from upstream to local storage
// while serving multiple concurrent clients.
type BlobStreamer struct {
	digest       godigest.Digest
	tempPath     string
	finalPath    string
	totalSize    int64
	chunkSize    int64
	chunksTotal  int
	chunksOnDisk int
	clients      map[int]chan int
	clientID     int
	clientMu     sync.Mutex
	downloadErr  error
	downloadDone bool
	downloadMu   sync.RWMutex
	log          log.Logger
}

// NewBlobStreamer creates a new blob streamer instance.
func NewBlobStreamer(digest godigest.Digest, tempPath, finalPath string, totalSize int64, log log.Logger) *BlobStreamer {
	chunksTotal := int(totalSize / defaultChunkSize)
	if totalSize%defaultChunkSize > 0 {
		chunksTotal++
	}

	return &BlobStreamer{
		digest:       digest,
		tempPath:     tempPath,
		finalPath:    finalPath,
		totalSize:    totalSize,
		chunkSize:    defaultChunkSize,
		chunksTotal:  chunksTotal,
		chunksOnDisk: 0,
		clients:      make(map[int]chan int),
		clientID:     0,
		log:          log,
	}
}

// Subscribe registers a client to receive notifications when new chunks are available.
// Returns a channel that will receive the latest chunk number and a subscriber ID.
func (bs *BlobStreamer) Subscribe() (int, chan int) {
	bs.clientMu.Lock()
	defer bs.clientMu.Unlock()

	chunkChan := make(chan int, 1)
	id := bs.clientID
	bs.clientID++
	bs.clients[id] = chunkChan

	// Send current chunk count to new subscriber
	go func() {
		bs.downloadMu.RLock()
		currentChunk := bs.chunksOnDisk
		bs.downloadMu.RUnlock()
		chunkChan <- currentChunk
	}()

	return id, chunkChan
}

// Unsubscribe removes a client from receiving further notifications.
func (bs *BlobStreamer) Unsubscribe(id int) {
	bs.clientMu.Lock()
	defer bs.clientMu.Unlock()

	delete(bs.clients, id)
}

// Download downloads the blob from upstream reader to temp storage,
// notifying all subscribed clients as chunks become available.
func (bs *BlobStreamer) Download(ctx context.Context, reader io.Reader) error {
	bs.log.Debug().
		Str("digest", bs.digest.String()).
		Str("tempPath", bs.tempPath).
		Int64("totalSize", bs.totalSize).
		Msg("starting blob download")

	// Create temp file, truncating if it exists to ensure clean state
	tempFile, err := os.OpenFile(bs.tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		bs.setDownloadError(err)
		return err
	}
	defer tempFile.Close()

	// Download blob in chunks
	for bs.chunksOnDisk < bs.chunksTotal {
		// Check context cancellation
		select {
		case <-ctx.Done():
			err := ctx.Err()
			bs.setDownloadError(err)
			return err
		default:
		}

		// Calculate bytes to read for this chunk
		bytesToRead := bs.chunkSize
		if bs.chunksOnDisk == bs.chunksTotal-1 {
			// Last chunk: read remaining bytes
			remainder := bs.totalSize % bs.chunkSize
			if remainder > 0 {
				bytesToRead = remainder
			}
		}

		n, err := io.CopyN(tempFile, reader, bytesToRead)
		if err != nil && !errors.Is(err, io.EOF) {
			// Real error occurred
			bs.setDownloadError(err)
			return err
		}

		// Check if we got fewer bytes than expected (but only if not EOF)
		if n < bytesToRead && !errors.Is(err, io.EOF) {
			err := io.ErrUnexpectedEOF
			bs.setDownloadError(err)
			return err
		}

		// Update chunk count and notify clients
		bs.downloadMu.Lock()
		bs.chunksOnDisk++
		currentChunk := bs.chunksOnDisk
		bs.downloadMu.Unlock()

		bs.notifyClients(currentChunk)
	}

	// Mark download as complete
	bs.downloadMu.Lock()
	bs.downloadDone = true
	bs.downloadMu.Unlock()

	bs.log.Debug().
		Str("digest", bs.digest.String()).
		Msg("blob download completed")

	return nil
}

// GetDownloadStatus returns the current download status.
func (bs *BlobStreamer) GetDownloadStatus() (done bool, err error) {
	bs.downloadMu.RLock()
	defer bs.downloadMu.RUnlock()

	return bs.downloadDone, bs.downloadErr
}

// setDownloadError sets the download error and notifies all clients.
func (bs *BlobStreamer) setDownloadError(err error) {
	bs.downloadMu.Lock()
	bs.downloadErr = err
	bs.downloadDone = true
	bs.downloadMu.Unlock()

	// Notify all clients of completion (with error)
	bs.notifyClients(bs.chunksTotal)
}

// notifyClients sends the current chunk number to all subscribed clients.
func (bs *BlobStreamer) notifyClients(chunkNum int) {
	bs.clientMu.Lock()
	defer bs.clientMu.Unlock()

	for _, ch := range bs.clients {
		select {
		case ch <- chunkNum:
		default:
			// Channel full, skip this notification
		}
	}
}

// StreamToClient streams the blob content to a client writer as chunks become available.
func (bs *BlobStreamer) StreamToClient(ctx context.Context, writer io.Writer) error {
	// Subscribe to chunk notifications
	id, chunkChan := bs.Subscribe()
	defer bs.Unsubscribe(id)
	defer close(chunkChan)

	// Open temp file for reading
	file, err := os.Open(bs.tempPath)
	if err != nil {
		return err
	}
	defer file.Close()

	chunksRead := 0

	for {
		// Wait for next chunk or completion
		select {
		case <-ctx.Done():
			return ctx.Err()
		case latestChunk := <-chunkChan:
			// Copy available chunks
			if latestChunk > chunksRead {
				bytesToCopy := int64(latestChunk-chunksRead) * bs.chunkSize

				// Adjust for last chunk
				if latestChunk == bs.chunksTotal {
					remainder := bs.totalSize % bs.chunkSize
					if remainder > 0 {
						bytesToCopy = int64(latestChunk-chunksRead-1)*bs.chunkSize + remainder
					}
				}

				_, err := io.CopyN(writer, file, bytesToCopy)
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}

				chunksRead = latestChunk
			}

			// Check if download is complete
			done, downloadErr := bs.GetDownloadStatus()
			if done {
				if downloadErr != nil {
					return downloadErr
				}
				if chunksRead >= bs.chunksTotal {
					return nil
				}
			}
		}
	}
}

// MoveToFinal moves the downloaded blob from temp to final storage location.
func (bs *BlobStreamer) MoveToFinal() error {
	return os.Rename(bs.tempPath, bs.finalPath)
}

// Cleanup removes the temporary file.
func (bs *BlobStreamer) Cleanup() error {
	return os.Remove(bs.tempPath)
}
