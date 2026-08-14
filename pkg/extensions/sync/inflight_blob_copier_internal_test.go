//go:build sync

package sync

import (
	"bytes"
	"io"
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

			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.Copy()
			}()

			// Wait until Copy() has subscribed so it sees each chunk notification
			// individually rather than only the final byte count.
			cbr.clientMu.Lock()
			for len(cbr.clients) == 0 {
				cbr.clientCond.Wait()
			}
			cbr.clientMu.Unlock()

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

			copyResult := make(chan error, 1)
			go func() {
				copyResult <- ifbc.Copy()
			}()

			// Wait until Copy() has subscribed so that the Read() error below is
			// guaranteed to close Copy's channel.
			// Whether Copy() has already consumed the initial 0 from Subscribe or
			// it is still buffered, the channel close returns (0, false) which
			// causes Copy() to return ErrSyncUpstreamDownloadFailed.
			errCBR.clientMu.Lock()
			for len(errCBR.clients) == 0 {
				errCBR.clientCond.Wait()
			}
			errCBR.clientMu.Unlock()

			// Trigger the upstream error; Read() closes all subscriber channels.
			buf := make([]byte, 50)
			_, _ = errCBR.Read(buf)

			So(<-copyResult, ShouldEqual, zerr.ErrSyncUpstreamDownloadFailed)
		})
	})
}
