//go:build sync

package sync

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

func newTestBReader(data []byte) *blob.BReader {
	dig := godigest.FromBytes(data)

	return blob.NewReader(
		blob.WithDesc(descriptor.Descriptor{
			Digest:    dig,
			Size:      int64(len(data)),
			MediaType: "application/octet-stream",
		}),
		blob.WithReader(bytes.NewReader(data)),
	)
}

func TestNewChunkedBlobReader(t *testing.T) {
	Convey("NewChunkedBlobReader", t, func() {
		Convey("creates file and returns reader on valid path", func() {
			dir := t.TempDir()
			path := filepath.Join(dir, "blob.bin")

			cbr, err := NewChunkedBlobReader(path, log.NewTestLogger())
			So(err, ShouldBeNil)
			So(cbr, ShouldNotBeNil)
			So(cbr.onDiskPath, ShouldEqual, path)
			So(cbr.onDiskFile, ShouldNotBeNil)

			// File should exist on disk
			_, statErr := os.Stat(path)
			So(statErr, ShouldBeNil)

			cbr.onDiskFile.Close()
		})

		Convey("returns error on invalid path", func() {
			cbr, err := NewChunkedBlobReader("/nonexistent/dir/blob.bin", log.NewTestLogger())
			So(err, ShouldNotBeNil)
			So(cbr, ShouldBeNil)
		})
	})
}

func TestInitReader(t *testing.T) {
	Convey("InitReader", t, func() {
		dir := t.TempDir()
		cbr, err := NewChunkedBlobReader(filepath.Join(dir, "blob.bin"), log.NewTestLogger())
		So(err, ShouldBeNil)

		data := []byte("hello world")
		reader := newTestBReader(data)

		Convey("sets the in-flight reader and total bytes", func() {
			So(cbr.inFlightReader, ShouldBeNil)

			cbr.InitReader(reader, reader.GetDescriptor())

			So(cbr.inFlightReader, ShouldEqual, reader)
			So(cbr.numBytesTotal, ShouldEqual, int64(len(data)))
		})

		Convey("is idempotent — second call does not overwrite first reader", func() {
			cbr.InitReader(reader, reader.GetDescriptor())

			secondReader := newTestBReader([]byte("other data"))
			cbr.InitReader(secondReader, secondReader.GetDescriptor())

			So(cbr.inFlightReader, ShouldEqual, reader)
			So(cbr.numBytesTotal, ShouldEqual, int64(len(data)))
		})
	})
}

func TestRead(t *testing.T) {
	Convey("Read", t, func() {
		dir := t.TempDir()
		blobPath := filepath.Join(dir, "blob.bin")
		cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
		So(err, ShouldBeNil)

		data := []byte("hello world")
		testBReader := newTestBReader(data)
		cbr.InitReader(testBReader, testBReader.GetDescriptor())

		Convey("reads all data and writes it to disk", func() {
			buf := make([]byte, len(data))
			n, err := cbr.Read(buf)
			// When the buffer is exactly the data size, all bytes are consumed in
			// one call; Read detects numBytesReadToDisk == numBytesTotal and
			// returns io.EOF to signal completion.
			So(err, ShouldEqual, io.EOF)
			So(n, ShouldEqual, len(data))
			So(buf[:n], ShouldResemble, data)

			// File should contain the data written so far
			onDisk, readErr := os.ReadFile(blobPath)
			So(readErr, ShouldBeNil)
			So(onDisk, ShouldResemble, data)
		})

		Convey("partial read at end of stream preserves all bytes", func() {
			// Read the first 5 bytes with an exact-fit buffer → (5, nil).
			firstBuf := make([]byte, 5)
			numBytesRead1, err1 := cbr.Read(firstBuf)
			So(err1, ShouldBeNil)
			So(numBytesRead1, ShouldEqual, 5)

			// Read the remaining 6 bytes with a buffer of 10: io.ReadFull can
			// only fill 6 bytes before hitting EOF and returns (6, ErrUnexpectedEOF).
			// Read normalises that to (6, io.EOF) at line 87.
			secondBuf := make([]byte, 10)
			numBytesRead2, err2 := cbr.Read(secondBuf)
			So(err2, ShouldEqual, io.EOF)
			So(numBytesRead2, ShouldEqual, 6)

			// Reconstruct what was read in memory and compare to source.
			So(append(firstBuf[:numBytesRead1], secondBuf[:numBytesRead2]...), ShouldResemble, data)

			// On-disk file must contain every byte — none dropped.
			onDisk, readErr := os.ReadFile(blobPath)
			So(readErr, ShouldBeNil)
			So(onDisk, ShouldResemble, data)
		})

		Convey("increments numBytesReadToDisk correctly", func() {
			chunk := make([]byte, 5)
			n, readErr := cbr.Read(chunk)
			So(readErr, ShouldBeNil)
			So(n, ShouldEqual, 5)

			cbr.bytesMu.RLock()
			bytesRead := cbr.numBytesReadToDisk
			cbr.bytesMu.RUnlock()

			So(bytesRead, ShouldEqual, 5)
		})

		Convey("notifies subscribed clients with latest byte offset", func() {
			ch, id := cbr.Subscribe()
			defer cbr.Unsubscribe(id)

			buf := make([]byte, len(data))
			done := make(chan struct{})

			go func() {
				_, _ = cbr.Read(buf)
				close(done)
			}()

			// Consume client channel
			var lastOffset int64
			for offset := range ch {
				lastOffset = offset
				if lastOffset == int64(len(data)) {
					break
				}
			}

			<-done

			So(lastOffset, ShouldEqual, int64(len(data)))
		})

		Convey("returns error and closes clients on upstream read error", func() {
			errDir := t.TempDir()
			errPath := filepath.Join(errDir, "blob.bin")
			errCBR, cerr := NewChunkedBlobReader(errPath, log.NewTestLogger())
			So(cerr, ShouldBeNil)

			// Subscribe before InitReader: InFlightReader is nil so no initial
			// value is placed in the channel. Subscribing after InitReader would
			// buffer a 0 in the channel (the current byte offset), causing the
			// first receive below to return (0, true) instead of (0, false).
			bytesUpdateChan, _ := errCBR.Subscribe()

			errReader := blob.NewReader(
				blob.WithDesc(descriptor.Descriptor{
					Digest:    godigest.FromBytes([]byte("x")),
					Size:      100, // larger than actual data to force a non-EOF error
					MediaType: "application/octet-stream",
				}),
				blob.WithReader(errReaderFunc(func(p []byte) (int, error) {
					return 0, zerr.ErrSyncUpstreamDownloadFailed
				})),
			)
			errCBR.InitReader(errReader, errReader.GetDescriptor())

			buf := make([]byte, 50)
			_, readErr := errCBR.Read(buf)
			So(readErr, ShouldNotBeNil)

			// Channel should have been closed.
			_, open := <-bytesUpdateChan
			So(open, ShouldBeFalse)
		})
	})
}

func TestSubscribeUnsubscribe(t *testing.T) {
	Convey("Subscribe and Unsubscribe", t, func() {
		dir := t.TempDir()
		cbr, err := NewChunkedBlobReader(filepath.Join(dir, "blob.bin"), log.NewTestLogger())
		So(err, ShouldBeNil)
		defer cbr.onDiskFile.Close()

		Convey("Subscribe returns a channel and a unique client ID", func() {
			ch1, id1 := cbr.Subscribe()
			ch2, id2 := cbr.Subscribe()

			So(ch1, ShouldNotBeNil)
			So(ch2, ShouldNotBeNil)
			So(id1, ShouldNotEqual, id2)

			cbr.Unsubscribe(id1)
			cbr.Unsubscribe(id2)
		})

		Convey("Subscribe sends current byte offset when reader is already initialized", func() {
			data := []byte("preloaded")
			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			// Manually advance numBytesReadToDisk to simulate partial read.
			cbr.bytesMu.Lock()
			cbr.numBytesReadToDisk = 5
			cbr.bytesMu.Unlock()

			ch, id := cbr.Subscribe()
			defer cbr.Unsubscribe(id)

			offset := <-ch
			So(offset, ShouldEqual, int64(5))
		})

		Convey("Subscribe does not send initial offset when reader is not yet initialized", func() {
			ch, id := cbr.Subscribe()
			defer cbr.Unsubscribe(id)

			// Channel should be empty since reader is not initialized.
			So(len(ch), ShouldEqual, 0)
		})

		Convey("Unsubscribe closes the channel and removes the client", func() {
			ch, clientId := cbr.Subscribe()
			cbr.Unsubscribe(clientId)

			_, open := <-ch
			So(open, ShouldBeFalse)

			cbr.clientMu.RLock()
			_, exists := cbr.clients[clientId]
			cbr.clientMu.RUnlock()

			So(exists, ShouldBeFalse)
		})

		Convey("Unsubscribe is a no-op for unknown client ID", func() {
			So(func() { cbr.Unsubscribe(9999) }, ShouldNotPanic)
		})
	})
}

func TestWaitForClientEmpty(t *testing.T) {
	Convey("WaitForClientEmpty", t, func() {
		dir := t.TempDir()
		cbr, err := NewChunkedBlobReader(filepath.Join(dir, "blob.bin"), log.NewTestLogger())
		So(err, ShouldBeNil)
		defer cbr.onDiskFile.Close()

		Convey("returns immediately when there are no clients", func() {
			done := make(chan struct{})

			go func() {
				cbr.WaitForClientEmpty()
				close(done)
			}()

			<-done // should not block
		})

		Convey("blocks until all clients unsubscribe", func() {
			_, id := cbr.Subscribe()

			done := make(chan struct{})

			go func() {
				cbr.WaitForClientEmpty()
				close(done)
			}()

			// Verify it's blocking.
			select {
			case <-done:
				So("WaitForClientEmpty returned before client unsubscribed", ShouldBeEmpty)
			default:
				// expected: still waiting
			}

			cbr.Unsubscribe(id)
			<-done
		})

		Convey("blocks while multiple clients are subscribed and wakes on each unsubscribe", func() {
			_, id1 := cbr.Subscribe()
			_, id2 := cbr.Subscribe()
			_, id3 := cbr.Subscribe()

			done := make(chan struct{})

			go func() {
				cbr.WaitForClientEmpty()
				close(done)
			}()

			// Still blocking with three clients present.
			select {
			case <-done:
				So("WaitForClientEmpty returned before all clients unsubscribed", ShouldBeEmpty)
			default:
			}

			// Unsubscribe one at a time. WaitForClientEmpty must not return
			// until the last client is gone.
			cbr.Unsubscribe(id1)
			cbr.Unsubscribe(id2)

			select {
			case <-done:
				So("WaitForClientEmpty returned with one client still subscribed", ShouldBeEmpty)
			default:
			}

			cbr.Unsubscribe(id3)
			<-done
		})
	})
}

func TestToBReader(t *testing.T) {
	Convey("ToBReader", t, func() {
		dir := t.TempDir()
		cbr, err := NewChunkedBlobReader(filepath.Join(dir, "blob.bin"), log.NewTestLogger())
		So(err, ShouldBeNil)
		defer cbr.onDiskFile.Close()

		data := []byte("to-breader test data")
		original := newTestBReader(data)
		cbr.InitReader(original, original.GetDescriptor())

		br := cbr.ToBReader()
		So(br, ShouldNotBeNil)

		// The returned BReader should have the same descriptor as the original.
		So(br.GetDescriptor().Digest, ShouldEqual, original.GetDescriptor().Digest)
		So(br.GetDescriptor().Size, ShouldEqual, original.GetDescriptor().Size)
	})
}

func TestDescriptor(t *testing.T) {
	Convey("Descriptor", t, func() {
		dir := t.TempDir()
		cbr, err := NewChunkedBlobReader(filepath.Join(dir, "blob.bin"), log.NewTestLogger())
		So(err, ShouldBeNil)
		defer cbr.onDiskFile.Close()

		data := []byte("descriptor test data")
		testBReader := newTestBReader(data)
		expectedDesc := testBReader.GetDescriptor()

		Convey("returns descriptor immediately when reader is already initialized", func() {
			cbr.InitReader(testBReader, expectedDesc)

			desc := cbr.Descriptor()
			So(desc.Digest, ShouldEqual, expectedDesc.Digest)
			So(desc.Size, ShouldEqual, expectedDesc.Size)
		})

		Convey("blocks until InitReader is called and returns the correct descriptor", func() {
			result := make(chan descriptor.Descriptor, 1)

			go func() {
				result <- cbr.Descriptor()
			}()

			// Give the goroutine time to block on readerReady.
			// It must not have returned yet since InitReader has not been called.
			select {
			case <-result:
				So("Descriptor returned before InitReader was called", ShouldBeEmpty)
			default:
			}

			cbr.InitReader(testBReader, expectedDesc)

			desc := <-result
			So(desc.Digest, ShouldEqual, expectedDesc.Digest)
			So(desc.Size, ShouldEqual, expectedDesc.Size)
		})

		Convey("multiple concurrent callers all receive the descriptor", func() {
			const numCallers = 5

			results := make([]chan descriptor.Descriptor, numCallers)
			for i := range results {
				results[i] = make(chan descriptor.Descriptor, 1)
				go func(ch chan descriptor.Descriptor) {
					ch <- cbr.Descriptor()
				}(results[i])
			}

			cbr.InitReader(testBReader, expectedDesc)

			for _, ch := range results {
				desc := <-ch
				So(desc.Digest, ShouldEqual, expectedDesc.Digest)
				So(desc.Size, ShouldEqual, expectedDesc.Size)
			}
		})
	})
}

type errReaderFunc func(p []byte) (int, error)

func (f errReaderFunc) Read(p []byte) (int, error) {
	return f(p)
}

func TestInitReaderComplete(t *testing.T) {
	Convey("InitReaderComplete", t, func() {
		dir := t.TempDir()
		blobPath := filepath.Join(dir, "blob.bin")

		// Write some data to simulate a complete file.
		fullData := []byte("complete blob on disk")
		writeErr := os.WriteFile(blobPath, fullData, 0o644)
		So(writeErr, ShouldBeNil)

		cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
		So(err, ShouldBeNil)

		data := fullData
		reader := newTestBReader(data)
		desc := reader.GetDescriptor()

		Convey("marks blob as complete and sets numBytesReadToDisk to full size", func() {
			result := cbr.InitReaderComplete(reader, desc)
			So(result, ShouldBeTrue)

			cbr.bytesMu.RLock()
			So(cbr.numBytesTotal, ShouldEqual, desc.Size)
			So(cbr.numBytesReadToDisk, ShouldEqual, desc.Size)
			So(cbr.inFlightReader, ShouldNotBeNil)
			cbr.bytesMu.RUnlock()
		})

		Convey("is idempotent — second call returns false", func() {
			cbr.InitReaderComplete(reader, desc)

			secondReader := newTestBReader([]byte("other"))
			result := cbr.InitReaderComplete(secondReader, secondReader.GetDescriptor())
			So(result, ShouldBeFalse)

			// Original values unchanged.
			cbr.bytesMu.RLock()
			So(cbr.numBytesTotal, ShouldEqual, desc.Size)
			cbr.bytesMu.RUnlock()
		})

		Convey("signals readerReady so Descriptor() unblocks", func() {
			resultCh := make(chan descriptor.Descriptor, 1)
			go func() {
				resultCh <- cbr.Descriptor()
			}()

			cbr.InitReaderComplete(reader, desc)

			gotDesc := <-resultCh
			So(gotDesc.Digest, ShouldEqual, desc.Digest)
			So(gotDesc.Size, ShouldEqual, desc.Size)
		})

		Convey("Subscribe sends full size offset immediately after InitReaderComplete", func() {
			cbr.InitReaderComplete(reader, desc)

			ch, id := cbr.Subscribe()
			defer cbr.Unsubscribe(id)

			offset := <-ch
			So(offset, ShouldEqual, desc.Size)
		})
	})
}

func TestReadWithSkipDiskWriteBytes(t *testing.T) {
	Convey("Read with skipDiskWriteBytes (partial resume)", t, func() {
		dir := t.TempDir()
		blobPath := filepath.Join(dir, "blob.bin")

		// Simulate partial file: prefix already on disk.
		prefix := []byte("XXXXX") // 5 bytes
		suffix := []byte("YYYYY") // 5 bytes
		fullData := append(prefix, suffix...)

		// Write prefix to disk.
		writeErr := os.WriteFile(blobPath, prefix, 0o644)
		So(writeErr, ShouldBeNil)

		cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Verify it detected the existing bytes.
		So(cbr.ResumeOffset(), ShouldEqual, int64(len(prefix)))

		// Set skip bytes (prefix already on disk, don't re-write).
		cbr.SetSkipDiskWriteBytes(int64(len(prefix)))

		// InitReader with a combined reader that has full data.
		combinedReader := newTestBReader(fullData)
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(fullData),
			Size:      int64(len(fullData)),
			MediaType: "application/octet-stream",
		}
		cbr.InitReader(combinedReader, desc)

		Convey("reads full data but only appends suffix to disk", func() {
			buf := make([]byte, len(fullData)+10)
			totalRead := 0

			for {
				n, readErr := cbr.Read(buf[totalRead:])
				totalRead += n
				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)
					break
				}
			}

			So(totalRead, ShouldEqual, len(fullData))
			So(buf[:totalRead], ShouldResemble, fullData)

			// On-disk file should contain prefix + suffix (appended).
			onDisk, diskErr := os.ReadFile(blobPath)
			So(diskErr, ShouldBeNil)
			So(onDisk, ShouldResemble, fullData)
		})

		Convey("skipDiskWriteBytes crossing buffer boundary works correctly", func() {
			// Read in small chunks smaller than prefix.
			chunk := make([]byte, 3) // smaller than prefix (5)
			var allRead []byte

			for {
				n, readErr := cbr.Read(chunk)
				allRead = append(allRead, chunk[:n]...)
				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)
					break
				}
			}

			So(allRead, ShouldResemble, fullData)

			// On-disk should have full blob (prefix was already there + suffix appended).
			onDisk, diskErr := os.ReadFile(blobPath)
			So(diskErr, ShouldBeNil)
			So(onDisk, ShouldResemble, fullData)
		})
	})
}

func TestFailedAndReinitReader(t *testing.T) {
	Convey("Failed and ReinitReader", t, func() {
		dir := t.TempDir()
		blobPath := filepath.Join(dir, "blob.bin")
		cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
		So(err, ShouldBeNil)

		prefix := []byte("AAAAA")
		suffix := []byte("BBBBB")
		fullData := append(append([]byte{}, prefix...), suffix...)
		desc := descriptor.Descriptor{
			Digest:    godigest.FromBytes(fullData),
			Size:      int64(len(fullData)),
			MediaType: "application/octet-stream",
		}

		Convey("ReinitReader returns false when reader is not initialized", func() {
			So(cbr.ReinitReader(newTestBReader(fullData), desc), ShouldBeFalse)
		})

		Convey("ReinitReader returns false when reader is active and not failed", func() {
			cbr.InitReader(newTestBReader(fullData), desc)
			So(cbr.ReinitReader(newTestBReader(fullData), desc), ShouldBeFalse)
		})

		Convey("upstream failure marks the reader failed; ReinitReader re-arms it", func() {
			// First attempt: delivers the prefix, then fails mid-download.
			failingReader := blob.NewReader(
				blob.WithDesc(desc),
				blob.WithReader(io.MultiReader(
					bytes.NewReader(prefix),
					errReaderFunc(func(p []byte) (int, error) {
						return 0, zerr.ErrSyncUpstreamDownloadFailed
					}),
				)),
			)
			cbr.InitReader(failingReader, desc)
			So(cbr.Initialized(), ShouldBeTrue)
			So(cbr.Failed(), ShouldBeFalse)

			buf := make([]byte, len(prefix))
			n, readErr := cbr.Read(buf)
			So(readErr, ShouldBeNil)
			So(n, ShouldEqual, len(prefix))

			_, readErr = cbr.Read(buf)
			So(readErr, ShouldNotBeNil)
			So(cbr.Failed(), ShouldBeTrue)
			So(cbr.Completed(), ShouldBeFalse)

			// Re-arm with a fresh reader that re-delivers the blob from byte 0.
			So(cbr.ReinitReader(newTestBReader(fullData), desc), ShouldBeTrue)
			So(cbr.Failed(), ShouldBeFalse)

			// A second re-init without a new failure is refused.
			So(cbr.ReinitReader(newTestBReader(fullData), desc), ShouldBeFalse)

			// The full stream passes through for digest verification, but only
			// the missing suffix is appended to disk.
			out := make([]byte, 0, len(fullData))
			chunk := make([]byte, 3)

			for {
				n, readErr := cbr.Read(chunk)
				out = append(out, chunk[:n]...)

				if readErr != nil {
					So(readErr, ShouldEqual, io.EOF)

					break
				}
			}

			So(out, ShouldResemble, fullData)
			So(cbr.Completed(), ShouldBeTrue)

			onDisk, diskErr := os.ReadFile(blobPath)
			So(diskErr, ShouldBeNil)
			So(onDisk, ShouldResemble, fullData)
		})
	})
}

func TestAnnounceNonBlocking(t *testing.T) {
	Convey("announcements never block on subscribers that do not consume", t, func() {
		dir := t.TempDir()
		blobPath := filepath.Join(dir, "blob.bin")
		cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
		So(err, ShouldBeNil)

		data := bytes.Repeat([]byte("x"), 64)
		So(cbr.InitReader(newTestBReader(data), descriptor.Descriptor{
			Digest: godigest.FromBytes(data),
			Size:   int64(len(data)),
		}), ShouldBeTrue)

		// Subscribe a client that never consumes announcements. Its channel
		// (capacity 1) fills up after the initial announcement; every further
		// announcement must overwrite the stale value instead of blocking.
		channel, clientID := cbr.Subscribe()
		defer cbr.Unsubscribe(clientID)

		done := make(chan struct{})

		go func() {
			defer close(done)

			buff := make([]byte, 8)

			for {
				_, rerr := cbr.Read(buff)
				if rerr != nil {
					return
				}
			}
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Read blocked on a subscriber that does not consume announcements")
		}

		// The channel must hold the latest offset (the full blob size).
		select {
		case latest := <-channel:
			So(latest, ShouldEqual, int64(len(data)))
		default:
			t.Fatal("expected the latest offset to be queued on the client channel")
		}
	})
}

func TestAbort(t *testing.T) {
	Convey("Abort", t, func() {
		dir := t.TempDir()

		Convey("closes current subscribers and refuses new ones", func() {
			blobPath := filepath.Join(dir, "blob1.bin")
			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			data := []byte("some data")
			So(cbr.InitReader(newTestBReader(data), descriptor.Descriptor{
				Digest: godigest.FromBytes(data),
				Size:   int64(len(data)),
			}), ShouldBeTrue)

			channel, _ := cbr.Subscribe()

			cbr.Abort()
			So(cbr.Aborted(), ShouldBeTrue)

			// The existing subscriber channel must be closed (after draining
			// the initial announcement).
			closedSeen := false

			for range 2 {
				if _, ok := <-channel; !ok {
					closedSeen = true

					break
				}
			}

			So(closedSeen, ShouldBeTrue)

			// WaitForClientEmpty returns promptly: the map was emptied.
			waitDone := make(chan struct{})
			go func() {
				cbr.WaitForClientEmpty()
				close(waitDone)
			}()

			select {
			case <-waitDone:
			case <-time.After(2 * time.Second):
				t.Fatal("WaitForClientEmpty blocked after Abort")
			}

			// New subscriptions get an already-closed channel.
			lateChannel, lateID := cbr.Subscribe()
			So(lateID, ShouldEqual, -1)

			_, ok := <-lateChannel
			So(ok, ShouldBeFalse)

			// A re-arm attempt must be refused.
			So(cbr.ReinitReader(newTestBReader(data), descriptor.Descriptor{
				Digest: godigest.FromBytes(data),
				Size:   int64(len(data)),
			}), ShouldBeFalse)
		})

		Convey("unblocks Descriptor waiters when aborted before init", func() {
			blobPath := filepath.Join(dir, "blob2.bin")
			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			descDone := make(chan descriptor.Descriptor, 1)
			go func() {
				descDone <- cbr.Descriptor()
			}()

			// Give the goroutine time to block on readerReady.
			time.Sleep(50 * time.Millisecond)

			cbr.Abort()

			select {
			case desc := <-descDone:
				So(desc.Size, ShouldEqual, 0)
			case <-time.After(2 * time.Second):
				t.Fatal("Descriptor still blocked after Abort")
			}
		})

		Convey("keeps the partial on-disk file for a future resume", func() {
			blobPath := filepath.Join(dir, "blob3.bin")
			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			data := bytes.Repeat([]byte("y"), 32)
			So(cbr.InitReader(newTestBReader(data), descriptor.Descriptor{
				Digest: godigest.FromBytes(data),
				Size:   64, // pretend the blob is larger so the download stays partial
			}), ShouldBeTrue)

			buff := make([]byte, 32)
			_, rerr := cbr.Read(buff)
			So(rerr, ShouldBeNil)

			cbr.Abort()

			info, statErr := os.Stat(blobPath)
			So(statErr, ShouldBeNil)
			So(info.Size(), ShouldEqual, int64(32))
		})
	})
}
