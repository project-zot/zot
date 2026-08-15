//go:build sync

package sync

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestInFlightBlobCopierCopy(t *testing.T) {
	Convey("InFlightBlobCopier.Copy", t, func() {
		Convey("copies entire blob to destination", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")
			data := []byte("hello inflight world")

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			// Run the read concurrently. Copy() blocks until it receives the
			// final byte-offset notification or sees the file data via a late subscribe.
			done := make(chan struct{})
			go func() {
				buf := make([]byte, len(data))
				_, _ = cbr.Read(buf)
				close(done)
			}()

			copyErr := ifbc.Copy()
			So(copyErr, ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data)
			<-done
		})

		Convey("copies blob delivered in multiple chunks", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")
			data := []byte("hello inflight world")
			const firstChunk = 8

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			// NewInFlightBlobCopier already subscribed — verify client is registered.
			cbr.clientMu.Lock()
			So(len(cbr.clients), ShouldEqual, 1)
			cbr.clientMu.Unlock()

			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.Copy()
			}()

			// First chunk: exactly firstChunk bytes — returns (firstChunk, nil).
			buf1 := make([]byte, firstChunk)
			n1, readErr1 := cbr.Read(buf1)
			So(readErr1, ShouldBeNil)
			So(n1, ShouldEqual, firstChunk)

			// Second chunk: remainder — exact-size buffer triggers the
			// numBytesReadToDisk >= numBytesTotal check which returns io.EOF.
			buf2 := make([]byte, len(data)-firstChunk)
			n2, readErr2 := cbr.Read(buf2)
			So(readErr2, ShouldEqual, io.EOF)
			So(n2, ShouldEqual, len(data)-firstChunk)

			So(<-copyResult, ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data)
		})

		Convey("returns error when on-disk file cannot be opened", func() {
			dir := t.TempDir()
			cbr, err := NewChunkedBlobReader(filepath.Join(dir, "blob.bin"), log.NewTestLogger())
			So(err, ShouldBeNil)
			defer cbr.onDiskFile.Close()

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, "/nonexistent/path/blob.bin", &dest, log.NewTestLogger())

			copyErr := ifbc.Copy()
			So(copyErr, ShouldNotBeNil)
		})

		Convey("returns ErrSyncUpstreamDownloadFailed when upstream download fails", func() {
			errDir := t.TempDir()
			errPath := filepath.Join(errDir, "blob.bin")
			errCBR, cerr := NewChunkedBlobReader(errPath, log.NewTestLogger())
			So(cerr, ShouldBeNil)

			testReader := blob.NewReader(
				blob.WithDesc(descriptor.Descriptor{
					Digest:    godigest.FromBytes([]byte("x")),
					Size:      100,
					MediaType: "application/octet-stream",
				}),
				blob.WithReader(errReaderFunc(func(p []byte) (int, error) {
					return 0, zerr.ErrSyncUpstreamDownloadFailed
				})),
			)

			errCBR.InitReader(testReader, testReader.GetDescriptor())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(errCBR, errPath, &dest, log.NewTestLogger())

			// NewInFlightBlobCopier already subscribed — verify.
			errCBR.clientMu.Lock()
			So(len(errCBR.clients), ShouldEqual, 1)
			errCBR.clientMu.Unlock()

			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.Copy()
			}()

			// Trigger the upstream error; Read() closes all subscriber channels.
			buf := make([]byte, 50)
			_, _ = errCBR.Read(buf)

			So(<-copyResult, ShouldEqual, zerr.ErrSyncUpstreamDownloadFailed)
		})

		Convey("WaitForClientEmpty blocks until Copy finishes (race fix verification)", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")
			data := []byte("race-fix-test-data-0123456789")

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			// Key assertion: after NewInFlightBlobCopier, the client is already
			// subscribed, so WaitForClientEmpty must block.
			cbr.clientMu.Lock()
			So(len(cbr.clients), ShouldEqual, 1)
			cbr.clientMu.Unlock()

			// Start WaitForClientEmpty in a goroutine — it must not return until
			// Copy() completes and Unsubscribes.
			waitDone := make(chan struct{})
			go func() {
				cbr.WaitForClientEmpty()
				close(waitDone)
			}()

			// Verify WaitForClientEmpty is actually blocked.
			select {
			case <-waitDone:
				So("WaitForClientEmpty returned too early", ShouldBeEmpty)
			default:
				// Expected — still waiting
			}

			// Now run Copy + Read to completion.
			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.Copy()
			}()

			buf := make([]byte, len(data))
			_, _ = cbr.Read(buf)

			So(<-copyResult, ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data)

			// Now WaitForClientEmpty should return.
			<-waitDone
		})

		Convey("Copy succeeds when blob is already complete at Subscribe time", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")
			data := []byte("already-complete-blob-data!!!")

			// Write full blob to disk and set up ChunkedBlobReader as complete.
			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			// Read the entire blob (simulates regclient reading it).
			buf := make([]byte, len(data))
			n, readErr := cbr.Read(buf)
			So(readErr, ShouldEqual, io.EOF)
			So(n, ShouldEqual, len(data))

			// At this point the blob is fully on disk and numBytesReadToDisk == blobSize.
			// All previously-subscribed clients have already been notified of blobSize.
			// A NEW client connecting now (late joiner) should still get the full data.
			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			copyErr := ifbc.Copy()
			So(copyErr, ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data)
		})

		Convey("multiple concurrent clients all receive full data", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")
			data := []byte("concurrent-client-test-with-enough-data-to-matter!")

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			const numClients = 5
			dests := make([]*bytes.Buffer, numClients)
			copyResults := make([]chan error, numClients)

			for i := range numClients {
				dests[i] = &bytes.Buffer{}
				copyResults[i] = make(chan error, 1)
				copier := NewInFlightBlobCopier(cbr, blobPath, dests[i], log.NewTestLogger())

				go func(c *InFlightBlobCopier, ch chan error) {
					ch <- c.Copy()
				}(copier, copyResults[i])
			}

			// Verify all clients are subscribed.
			cbr.clientMu.Lock()
			So(len(cbr.clients), ShouldEqual, numClients)
			cbr.clientMu.Unlock()

			// Feed data in two chunks.
			half := len(data) / 2
			buf1 := make([]byte, half)
			_, _ = cbr.Read(buf1)

			buf2 := make([]byte, len(data)-half)
			_, _ = cbr.Read(buf2)

			// All clients should succeed with full data.
			for i := range numClients {
				So(<-copyResults[i], ShouldBeNil)
				So(dests[i].Bytes(), ShouldResemble, data)
			}
		})
	})
}

func TestInFlightBlobCopierCopyRange(t *testing.T) {
	Convey("InFlightBlobCopier.CopyRange", t, func() {
		data := []byte("0123456789abcdefghij") // 20 bytes

		newCompleteCBR := func(dir string) (*ChunkedBlobReader, string) {
			blobPath := filepath.Join(dir, "blob.bin")
			writeErr := os.WriteFile(blobPath, data, 0o644)
			So(writeErr, ShouldBeNil)

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			testBReader := newTestBReader(data)
			cbr.InitReaderComplete(testBReader, testBReader.GetDescriptor())

			return cbr, blobPath
		}

		Convey("serves an open-ended suffix range of a completed blob", func() {
			cbr, blobPath := newCompleteCBR(t.TempDir())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			So(ifbc.CopyRange(5, -1), ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data[5:])
		})

		Convey("serves a bounded middle range of a completed blob", func() {
			cbr, blobPath := newCompleteCBR(t.TempDir())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			So(ifbc.CopyRange(5, 9), ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data[5:10])
		})

		Convey("bounded range finishes before the blob download completes", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.CopyRange(0, 7)
			}()

			// Deliver only the first half of the blob.
			buf := make([]byte, 10)
			n, readErr := cbr.Read(buf)
			So(readErr, ShouldBeNil)
			So(n, ShouldEqual, 10)

			// The copier must complete with the requested range even though the
			// download is still in flight.
			So(<-copyResult, ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data[:8])
		})

		Convey("range starting beyond current progress waits for bytes", func() {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")

			cbr, err := NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			testBReader := newTestBReader(data)
			cbr.InitReader(testBReader, testBReader.GetDescriptor())

			var dest bytes.Buffer
			ifbc := NewInFlightBlobCopier(cbr, blobPath, &dest, log.NewTestLogger())

			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.CopyRange(15, -1)
			}()

			// Deliver the blob in two chunks; the second read hits EOF.
			buf := make([]byte, 10)
			n1, readErr1 := cbr.Read(buf)
			So(readErr1, ShouldBeNil)
			So(n1, ShouldEqual, 10)

			n2, readErr2 := cbr.Read(buf)
			So(readErr2, ShouldEqual, io.EOF)
			So(n2, ShouldEqual, 10)

			So(<-copyResult, ShouldBeNil)
			So(dest.Bytes(), ShouldResemble, data[15:])
		})
	})
}
