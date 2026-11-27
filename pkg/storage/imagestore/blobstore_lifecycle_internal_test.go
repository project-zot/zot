package imagestore

// Tests of the global blobstore methods of blobLifecycle.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errInjectedReferenceCheck = errors.New("injected reference-check failure")

type lifecycleStubDriver struct {
	storageTypes.Driver

	nameFn     func() string
	statFn     func(path string) (driver.FileInfo, error)
	readerFn   func(path string, offset int64) (io.ReadCloser, error)
	writerFn   func(path string, isAppend bool) (driver.FileWriter, error)
	linkFn     func(src, dst string) error
	deleteFn   func(path string) error
	moveFn     func(src, dst string) error
	putContent func(path string, content []byte)
}

func (s *lifecycleStubDriver) Name() string {
	if s.nameFn != nil {
		return s.nameFn()
	}

	return ""
}

func (s *lifecycleStubDriver) EnsureDir(path string) error { return nil }
func (s *lifecycleStubDriver) DirExists(path string) bool  { return true }

func (s *lifecycleStubDriver) Reader(path string, offset int64) (io.ReadCloser, error) {
	if s.readerFn != nil {
		return s.readerFn(path, offset)
	}

	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (s *lifecycleStubDriver) ReadFile(path string) ([]byte, error) { return nil, nil }

func (s *lifecycleStubDriver) Delete(path string) error {
	if s.deleteFn != nil {
		return s.deleteFn(path)
	}

	return nil
}

func (s *lifecycleStubDriver) Stat(path string) (driver.FileInfo, error) {
	if s.statFn != nil {
		return s.statFn(path)
	}

	return nil, driver.PathNotFoundError{Path: path}
}

func (s *lifecycleStubDriver) Writer(path string, isAppend bool) (driver.FileWriter, error) {
	if s.writerFn != nil {
		return s.writerFn(path, isAppend)
	}

	return &lifecycleWriterStub{}, nil
}

func (s *lifecycleStubDriver) WriteFile(path string, content []byte) (int, error) {
	if s.putContent != nil {
		s.putContent(path, content)
	}

	return len(content), nil
}

func (s *lifecycleStubDriver) Walk(path string, f driver.WalkFn) error { return nil }
func (s *lifecycleStubDriver) List(fullpath string) ([]string, error)  { return nil, nil }
func (s *lifecycleStubDriver) Move(sourcePath string, destPath string) error {
	if s.moveFn != nil {
		return s.moveFn(sourcePath, destPath)
	}

	return nil
}
func (s *lifecycleStubDriver) SameFile(path1, path2 string) bool { return path1 == path2 }

func (s *lifecycleStubDriver) Link(src, dest string) error {
	if s.linkFn != nil {
		return s.linkFn(src, dest)
	}

	if s.putContent != nil {
		s.putContent(dest, []byte{})
	}

	return nil
}

func (s *lifecycleStubDriver) RedirectURL(r *http.Request, path string) (string, error) {
	return "", nil
}

type lifecycleWriterStub struct {
	writeFn  func(p []byte) (int, error)
	closeFn  func() error
	commitFn func() error
	cancelFn func() error
}

func (w *lifecycleWriterStub) Size() int64 { return 0 }

func (w *lifecycleWriterStub) Write(p []byte) (int, error) {
	if w.writeFn != nil {
		return w.writeFn(p)
	}

	return len(p), nil
}

func (w *lifecycleWriterStub) Close() error {
	if w.closeFn != nil {
		return w.closeFn()
	}

	return nil
}

func (w *lifecycleWriterStub) Commit(_ context.Context) error {
	if w.commitFn != nil {
		return w.commitFn()
	}

	return nil
}

func (w *lifecycleWriterStub) Cancel(_ context.Context) error {
	if w.cancelFn != nil {
		return w.cancelFn()
	}

	return nil
}

func TestBlobLifecycleSelection(t *testing.T) {
	Convey("blobLifecycle selection excludes _blobstore from mount candidates", t, func() {
		localDriver := &lifecycleStubDriver{nameFn: func() string { return constants.LocalStorageDriverName }}
		localLifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: localDriver, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		So(localLifecycle.IncludeRepoInMountCandidates(constants.GlobalBlobsRepo), ShouldBeFalse)
		So(localLifecycle.IncludeRepoInMountCandidates("repo"), ShouldBeTrue)

		remoteDriver := &lifecycleStubDriver{nameFn: func() string { return constants.S3StorageDriverName }}
		remoteLifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: remoteDriver, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		So(remoteLifecycle.IncludeRepoInMountCandidates(constants.GlobalBlobsRepo), ShouldBeFalse)
		So(remoteLifecycle.IncludeRepoInMountCandidates("repo"), ShouldBeTrue)
	})
}

func TestRemoteBlobLifecycleGetsTheReferenceIndex(t *testing.T) {
	Convey("The remote lifecycle records ownership in the store's cache", t, func() {
		remoteDriver := &lifecycleStubDriver{nameFn: func() string { return constants.S3StorageDriverName }}
		cacheMock := mocks.CacheMock{}

		refsOf := func(cacheDriver storageTypes.Cache) storageTypes.BlobRefIndex {
			// dedupe off: the wiring is the same, and the stub driver has no store to upgrade
			imgStore, ok := NewImageStore("/root", "/root", false, false, zlog.NewTestLogger(),
				monitoring.NewNopMetricServer(), nil, remoteDriver, cacheDriver, nil, nil).(*ImageStore)
			So(ok, ShouldBeTrue)

			lifecycle, ok := imgStore.lifecycle.(*remoteSharedBlobLifecycle)
			So(ok, ShouldBeTrue)

			return lifecycle.refs
		}

		So(refsOf(cacheMock), ShouldEqual, cacheMock)
		So(refsOf(nil), ShouldBeNil)

		// a typed nil is no cache either
		var noCache *mocks.CacheMock
		So(refsOf(noCache), ShouldBeNil)
	})
}

func TestLocalBlobLifecycleDelegatesToLink(t *testing.T) {
	Convey("Local lifecycle delegates PromoteCandidate/LinkBlob to driver.Link", t, func() {
		linkCalls := 0

		driverStub := &lifecycleStubDriver{
			nameFn: func() string { return constants.LocalStorageDriverName },
			linkFn: func(src, dst string) error {
				linkCalls++
				So(src, ShouldNotBeEmpty)
				So(dst, ShouldNotBeEmpty)

				return nil
			},
		}

		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		So(lifecycle.PromoteCandidate(godigest.FromString("blob"), 4, "src/blob", "", "dst/blob"), ShouldBeNil)
		So(lifecycle.LinkBlob("dst/blob", "dst/blob2"), ShouldBeNil)
		So(linkCalls, ShouldEqual, 2)
	})
}

// Local migration keeps each repository hardlink after promoting the canonical blob.
func TestLocalBlobLifecycleRemoveMigratedRepoBlobIsNoOp(t *testing.T) {
	Convey("RemoveMigratedRepoBlob must not touch the driver on local storage", t, func() {
		linkCalled := false

		driverStub := &lifecycleStubDriver{
			nameFn: func() string { return constants.LocalStorageDriverName },
			linkFn: func(src, dst string) error {
				linkCalled = true

				return nil
			},
		}

		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		So(lifecycle.RemoveMigratedRepoBlob("global/blob", "repo/blob"), ShouldBeNil)
		So(linkCalled, ShouldBeFalse)
	})
}

// A migration that crashed before writing its marker is re-run from the start and revisits
// repo objects it already removed; S3's Delete reports those as PathNotFound.
func TestRemoteBlobLifecycleRemoveMigratedRepoBlob(t *testing.T) {
	Convey("Remote RemoveMigratedRepoBlob replaces a copy with content by a placeholder", t, func() {
		var (
			statErr error
			size    int64
			linked  []string
		)

		driverStub := &lifecycleStubDriver{
			nameFn: func() string { return constants.S3StorageDriverName },
			statFn: func(path string) (driver.FileInfo, error) {
				if statErr != nil {
					return nil, statErr
				}

				return driver.FileInfoInternal{FileInfoFields: driver.FileInfoFields{Path: path, Size: size}}, nil
			},
			linkFn: func(src, dest string) error {
				linked = append(linked, src+"->"+dest)

				return nil
			},
		}

		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		size = 10
		So(lifecycle.RemoveMigratedRepoBlob("global/blob", "repo/blob"), ShouldBeNil)
		So(linked, ShouldResemble, []string{"global/blob->repo/blob"})

		Convey("a placeholder, or a copy already gone, is left as it is", func() {
			linked = nil

			size = 0
			So(lifecycle.RemoveMigratedRepoBlob("global/blob", "repo/blob"), ShouldBeNil)

			statErr = driver.PathNotFoundError{Path: "repo/blob"}
			So(lifecycle.RemoveMigratedRepoBlob("global/blob", "repo/blob"), ShouldBeNil)

			statErr = errclass.MarkMissing(driver.PathNotFoundError{Path: "repo/blob"})
			So(lifecycle.RemoveMigratedRepoBlob("global/blob", "repo/blob"), ShouldBeNil)

			So(linked, ShouldBeEmpty)
		})

		Convey("other errors are returned", func() {
			statErr = errInjectedReferenceCheck
			So(lifecycle.RemoveMigratedRepoBlob("global/blob", "repo/blob"), ShouldEqual, errInjectedReferenceCheck)
		})
	})
}

func TestRemoteBlobLifecyclePromoteStreamsContent(t *testing.T) {
	Convey("Remote PromoteCandidate streams reader content into the writer and commits", t, func() {
		content := []byte("remote-lifecycle-stream")
		readerCalls := 0
		writerCalls := 0
		commitCalls := 0
		cancelCalls := 0
		closeCalls := 0

		var written bytes.Buffer

		driverStub := &lifecycleStubDriver{
			nameFn: func() string { return constants.S3StorageDriverName },
			readerFn: func(path string, offset int64) (io.ReadCloser, error) {
				readerCalls++

				return io.NopCloser(bytes.NewReader(content)), nil
			},
			writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
				writerCalls++

				return &lifecycleWriterStub{
					writeFn: func(p []byte) (int, error) {
						_, _ = written.Write(p)

						return len(p), nil
					},
					commitFn: func() error {
						commitCalls++

						return nil
					},
					cancelFn: func() error {
						cancelCalls++

						return nil
					},
					closeFn: func() error {
						closeCalls++

						return nil
					},
				}, nil
			},
		}

		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		So(lifecycle.PromoteCandidate(godigest.FromBytes(content), int64(len(content)), "src/blob",
			"staging/blob", "dst/blob"), ShouldBeNil)
		So(readerCalls, ShouldEqual, 1)
		So(writerCalls, ShouldEqual, 1)
		So(commitCalls, ShouldEqual, 1)
		So(cancelCalls, ShouldEqual, 0)
		So(closeCalls, ShouldEqual, 1)
		So(written.Bytes(), ShouldResemble, content)
	})
}

// Upgrade passes of two instances can choose the same repo copy, and the first to finish
// replaces it with a placeholder: the second must then never publish it over the payload.
func TestRemoteBlobLifecyclePromoteVerifiesBeforePublishing(t *testing.T) {
	Convey("Remote PromoteCandidate publishes only a verified copy, never over a published payload", t, func() {
		content := []byte("remote-lifecycle-verify")
		digest := godigest.FromBytes(content)
		size := int64(len(content))

		var (
			source       []byte
			dstSize      int64 = -1
			written      []string
			moved        [][2]string
			deleted      []string
			statDstCalls int
		)

		driverStub := &lifecycleStubDriver{
			nameFn: func() string { return constants.S3StorageDriverName },
			statFn: func(path string) (driver.FileInfo, error) {
				statDstCalls++

				if dstSize < 0 {
					return nil, driver.PathNotFoundError{Path: path}
				}

				return driver.FileInfoInternal{FileInfoFields: driver.FileInfoFields{Path: path, Size: dstSize}}, nil
			},
			readerFn: func(path string, offset int64) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(source)), nil
			},
			writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
				written = append(written, path)

				return &lifecycleWriterStub{}, nil
			},
			moveFn: func(src, dst string) error {
				moved = append(moved, [2]string{src, dst})

				return nil
			},
			deleteFn: func(path string) error {
				deleted = append(deleted, path)

				return nil
			},
		}

		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		Convey("a matching copy is staged, then moved onto the payload", func() {
			source = content

			So(lifecycle.PromoteCandidate(digest, size, "src", "staging", "dst"), ShouldBeNil)
			So(written, ShouldResemble, []string{"staging"})
			So(moved, ShouldResemble, [][2]string{{"staging", "dst"}})
			So(deleted, ShouldBeEmpty)
		})

		Convey("a payload already published is kept, without reading the source", func() {
			dstSize = size

			So(lifecycle.PromoteCandidate(digest, size, "src", "staging", "dst"), ShouldBeNil)
			So(written, ShouldBeEmpty)
			So(moved, ShouldBeEmpty)
		})

		Convey("a source emptied since it was chosen is dropped, and the published payload kept", func() {
			source = []byte{}

			// published by the other pass after this one first looked
			driverStub.writerFn = func(path string, isAppend bool) (driver.FileWriter, error) {
				written = append(written, path)
				dstSize = size

				return &lifecycleWriterStub{}, nil
			}

			So(lifecycle.PromoteCandidate(digest, size, "src", "staging", "dst"), ShouldBeNil)
			So(moved, ShouldBeEmpty)
			So(deleted, ShouldResemble, []string{"staging"})
			So(statDstCalls, ShouldEqual, 2)
		})

		Convey("a copy that does not match, with no payload published, fails", func() {
			Convey("for its size", func() {
				source = []byte{}
			})

			Convey("for its digest", func() {
				source = bytes.Repeat([]byte("x"), len(content))
			})

			So(errors.Is(lifecycle.PromoteCandidate(digest, size, "src", "staging", "dst"), zerr.ErrBadBlob),
				ShouldBeTrue)
			So(moved, ShouldBeEmpty)
			So(deleted, ShouldResemble, []string{"staging"})
		})

		Convey("a payload whose size cannot be checked fails before anything is copied", func() {
			driverStub.statFn = func(path string) (driver.FileInfo, error) {
				return nil, errInjectedPromote
			}

			So(errors.Is(lifecycle.PromoteCandidate(digest, size, "src", "staging", "dst"), errInjectedPromote),
				ShouldBeTrue)
			So(written, ShouldBeEmpty)
		})

		Convey("a digest without content is published as found", func() {
			source = []byte{}

			So(lifecycle.PromoteCandidate(digest, 0, "src", "staging", "dst"), ShouldBeNil)
			So(moved, ShouldResemble, [][2]string{{"staging", "dst"}})
		})
	})
}

var (
	errInjectedPromote = errors.New("injected promote failure")
	errInjectedCleanup = errors.New("injected cleanup failure")

	// the error paths fail before anything is verified, so any digest will do
	promoteErrDigest = godigest.FromString("content")
)

// errCloseReader wraps a reader with an injectable Close error - io.NopCloser (used
// by the success-path test above) always returns nil from Close, so it can't exercise
// PromoteCandidate's reader.Close() error branch.
type errCloseReader struct {
	io.Reader

	closeErr   error
	closeCalls *int
}

func (r errCloseReader) Close() error {
	if r.closeCalls != nil {
		*r.closeCalls++
	}

	return r.closeErr
}

// TestRemoteBlobLifecyclePromoteErrorPaths exercises every error branch in
// PromoteCandidate: it must close whatever it opened so far (reader and/or writer,
// cancelling the writer when content was partially streamed) before propagating the
// error, on every failure path.
func TestRemoteBlobLifecyclePromoteErrorPaths(t *testing.T) {
	Convey("PromoteCandidate error paths clean up whatever was opened", t, func() {
		Convey("reader error: no writer is opened", func() {
			writerCalls := 0

			driverStub := &lifecycleStubDriver{
				readerFn: func(path string, offset int64) (io.ReadCloser, error) {
					return nil, errInjectedPromote
				},
				writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
					writerCalls++

					return &lifecycleWriterStub{}, nil
				},
			}

			lifecycle := newBlobLifecycle(blobLifecycleDeps{
				storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
			})

			err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
			So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			So(writerCalls, ShouldEqual, 0)
		})

		Convey("writer error: reader is closed", func() {
			closeCalls := 0

			driverStub := &lifecycleStubDriver{
				readerFn: func(path string, offset int64) (io.ReadCloser, error) {
					return errCloseReader{Reader: bytes.NewReader(nil), closeCalls: &closeCalls}, nil
				},
				writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errInjectedPromote
				},
			}

			lifecycle := newBlobLifecycle(blobLifecycleDeps{
				storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
			})

			err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
			So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			So(closeCalls, ShouldEqual, 1)
		})

		Convey("copy error: writer is cancelled and both are closed", func() {
			cancelCalls, closeCalls := 0, 0

			driverStub := &lifecycleStubDriver{
				readerFn: func(path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader([]byte("content"))), nil
				},
				writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
					return &lifecycleWriterStub{
						writeFn: func(p []byte) (int, error) { return 0, errInjectedPromote },
						cancelFn: func() error {
							cancelCalls++

							return nil
						},
						closeFn: func() error {
							closeCalls++

							return nil
						},
					}, nil
				},
			}

			lifecycle := newBlobLifecycle(blobLifecycleDeps{
				storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
			})

			err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
			So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			So(cancelCalls, ShouldEqual, 1)
			So(closeCalls, ShouldEqual, 1)
		})

		Convey("commit error: writer is cancelled and both are closed", func() {
			cancelCalls, closeCalls := 0, 0

			driverStub := &lifecycleStubDriver{
				readerFn: func(path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(nil)), nil
				},
				writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
					return &lifecycleWriterStub{
						commitFn: func() error { return errInjectedPromote },
						cancelFn: func() error {
							cancelCalls++

							return nil
						},
						closeFn: func() error {
							closeCalls++

							return nil
						},
					}, nil
				},
			}

			lifecycle := newBlobLifecycle(blobLifecycleDeps{
				storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
			})

			err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
			So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			So(cancelCalls, ShouldEqual, 1)
			So(closeCalls, ShouldEqual, 1)
		})

		Convey("reader close error: writer is still closed", func() {
			closeCalls := 0

			driverStub := &lifecycleStubDriver{
				readerFn: func(path string, offset int64) (io.ReadCloser, error) {
					return errCloseReader{Reader: bytes.NewReader(nil), closeErr: errInjectedPromote}, nil
				},
				writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
					return &lifecycleWriterStub{
						closeFn: func() error {
							closeCalls++

							return nil
						},
					}, nil
				},
			}

			lifecycle := newBlobLifecycle(blobLifecycleDeps{
				storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
			})

			err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
			So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			So(closeCalls, ShouldEqual, 1)
		})

		// Cleanup is best effort: a failing cleanup step is only logged, and the error that
		// stopped the copy is the one returned.
		Convey("cleanup failures are logged and the original error is returned", func() {
			failingReader := func(path string, offset int64) (io.ReadCloser, error) {
				return errCloseReader{Reader: bytes.NewReader([]byte("content")), closeErr: errInjectedCleanup}, nil
			}

			Convey("writer error, then reader close error", func() {
				driverStub := &lifecycleStubDriver{
					readerFn: failingReader,
					writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
						return nil, errInjectedPromote
					},
				}

				lifecycle := newBlobLifecycle(blobLifecycleDeps{
					storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
				})

				err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
				So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			})

			Convey("copy error, then cancel and both close errors", func() {
				driverStub := &lifecycleStubDriver{
					readerFn: failingReader,
					writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
						return &lifecycleWriterStub{
							writeFn:  func(p []byte) (int, error) { return 0, errInjectedPromote },
							cancelFn: func() error { return errInjectedCleanup },
							closeFn:  func() error { return errInjectedCleanup },
						}, nil
					},
				}

				lifecycle := newBlobLifecycle(blobLifecycleDeps{
					storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
				})

				err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
				So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			})

			Convey("reader close error, then writer close error", func() {
				driverStub := &lifecycleStubDriver{
					readerFn: func(path string, offset int64) (io.ReadCloser, error) {
						return errCloseReader{Reader: bytes.NewReader(nil), closeErr: errInjectedPromote}, nil
					},
					writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
						return &lifecycleWriterStub{closeFn: func() error { return errInjectedCleanup }}, nil
					},
				}

				lifecycle := newBlobLifecycle(blobLifecycleDeps{
					storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
				})

				err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
				So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
			})
		})

		Convey("writer close error propagates", func() {
			driverStub := &lifecycleStubDriver{
				readerFn: func(path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(nil)), nil
				},
				writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
					return &lifecycleWriterStub{
						closeFn: func() error { return errInjectedPromote },
					}, nil
				},
			}

			lifecycle := newBlobLifecycle(blobLifecycleDeps{
				storeDriver: driverStub, rootDir: "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
			})

			err := lifecycle.PromoteCandidate(promoteErrDigest, 7, "src", "staging", "dst")
			So(errors.Is(err, errInjectedPromote), ShouldBeTrue)
		})
	})
}

func TestBlobLifecycleShouldDeleteGlobalBlobLocal(t *testing.T) {
	Convey("Local ShouldDeleteGlobalBlob", t, func() {
		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: &lifecycleStubDriver{nameFn: func() string { return constants.LocalStorageDriverName }},
			rootDir:     "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		Convey("missing path is not deleted", func() {
			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(
				filepath.Join(t.TempDir(), "missing"),
				godigest.FromString("missing"),
				nil,
			)
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeFalse)
		})

		Convey("single hardlink can be deleted", func() {
			digest := godigest.FromString("single-hardlink")
			globalBlobPath := filepath.Join(t.TempDir(), "global-blob")

			if err := os.WriteFile(globalBlobPath, []byte("content"), 0o600); err != nil {
				t.Fatalf("create global blob file: %v", err)
			}

			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(globalBlobPath, digest, nil)
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeTrue)
		})

		Convey("multiple hardlinks should not be deleted", func() {
			digest := godigest.FromString("multiple-hardlinks")
			tempDir := t.TempDir()
			globalBlobPath := filepath.Join(tempDir, "global-blob")
			repoBlobPath := filepath.Join(tempDir, "repo-blob")

			if err := os.WriteFile(globalBlobPath, []byte("content"), 0o600); err != nil {
				t.Fatalf("create global blob file: %v", err)
			}

			if err := os.Link(globalBlobPath, repoBlobPath); err != nil {
				t.Fatalf("create hardlink: %v", err)
			}

			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(globalBlobPath, digest, nil)
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeFalse)
		})

		// The cases above all Stat a real file, so Sys() always exposes a real
		// *syscall.Stat_t with Nlink - there's no way to reach the nlink-unavailable
		// fallback that way. Use a fake statFn to exercise that branch instead.
		fakeStatFn := func(name string) (os.FileInfo, error) {
			return fileInfoWithSys{sys: struct{ Size int64 }{Size: 1}}, nil
		}

		Convey("nlink unavailable, digest not referenced elsewhere: deletable", func() {
			lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("unreferenced"),
				func(godigest.Digest) (bool, error) { return false, nil })
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeTrue)
		})

		Convey("nlink unavailable, digest still referenced elsewhere: not deletable", func() {
			lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("referenced"),
				func(godigest.Digest) (bool, error) { return true, nil })
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeFalse)
		})

		Convey("nlink unavailable, isDigestReferenced error propagates", func() {
			lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

			_, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("errors"),
				func(godigest.Digest) (bool, error) { return false, errInjectedReferenceCheck })
			So(errors.Is(err, errInjectedReferenceCheck), ShouldBeTrue)
		})

		Convey("stat errors other than a missing path propagate", func() {
			lifecycle := &localHardlinkBlobLifecycle{statFn: func(name string) (os.FileInfo, error) {
				return nil, os.ErrPermission
			}}

			_, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("stat-error"), nil)
			So(errors.Is(err, os.ErrPermission), ShouldBeTrue)
		})

		Convey("nlink unavailable, isDigestReferenced nil: not deletable", func() {
			lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("no-callback"), nil)
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeFalse)
		})
	})
}

func TestBlobLifecycleShouldDeleteGlobalBlobRemote(t *testing.T) {
	Convey("Remote ShouldDeleteGlobalBlob never deletes inline: the reclaim sweep does, under a claim", t, func() {
		lifecycle := newBlobLifecycle(blobLifecycleDeps{
			storeDriver: &lifecycleStubDriver{nameFn: func() string { return constants.S3StorageDriverName }},
			rootDir:     "/root", metrics: monitoring.NewNopMetricServer(), log: zlog.NewTestLogger(),
		})

		for _, referenced := range []bool{false, true} {
			deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("ignored/path", godigest.FromString("digest"),
				func(godigest.Digest) (bool, error) { return referenced, nil })
			So(err, ShouldBeNil)
			So(deleteDecision, ShouldBeFalse)
		}
	})
}

func TestHardLinkCount(t *testing.T) {
	Convey("hardLinkCount", t, func() {
		Convey("returns count when Nlink is present", func() {
			count, ok := hardLinkCount(fileInfoWithSys{sys: struct{ Nlink uint64 }{Nlink: 3}})
			So(ok, ShouldBeTrue)
			So(count, ShouldEqual, 3)
		})

		Convey("returns false when syscall payload has no Nlink", func() {
			_, ok := hardLinkCount(fileInfoWithSys{sys: struct{ Size int64 }{Size: 1}})
			So(ok, ShouldBeFalse)
		})

		Convey("returns false when syscall payload is nil", func() {
			_, ok := hardLinkCount(fileInfoWithSys{sys: nil})
			So(ok, ShouldBeFalse)
		})
	})
}

type fileInfoWithSys struct {
	sys any
}

func (f fileInfoWithSys) Name() string       { return "" }
func (f fileInfoWithSys) Size() int64        { return 0 }
func (f fileInfoWithSys) Mode() os.FileMode  { return 0 }
func (f fileInfoWithSys) ModTime() time.Time { return time.Time{} }
func (f fileInfoWithSys) IsDir() bool        { return false }
func (f fileInfoWithSys) Sys() any           { return f.sys }

// stallingDeleteDriver is a remote driver whose deletes do not return until their context ends.
type stallingDeleteDriver struct {
	lifecycleStubDriver
}

func (s *stallingDeleteDriver) DeleteContext(ctx context.Context, _ string) error {
	<-ctx.Done()

	return ctx.Err()
}

func TestDeleteClaimedPayloadDeadline(t *testing.T) {
	Convey("A claimed payload delete is bounded by the claim's deadline", t, func() {
		lifecycle := &remoteSharedBlobLifecycle{storeDriver: &stallingDeleteDriver{}}

		Convey("a delete still running at the deadline is cancelled, not left to land later", func() {
			start := time.Now()

			err := lifecycle.deleteClaimedPayload("/root/_blobstore/blobs/sha256/x", start.Add(100*time.Millisecond))
			So(errors.Is(err, context.DeadlineExceeded), ShouldBeTrue)
			So(time.Since(start), ShouldBeLessThan, 5*time.Second)
		})

		Convey("a deadline already passed deletes nothing", func() {
			err := lifecycle.deleteClaimedPayload("/root/_blobstore/blobs/sha256/x", time.Now().Add(-time.Second))
			So(errors.Is(err, zerr.ErrReclaimClaimLost), ShouldBeTrue)
		})
	})
}
