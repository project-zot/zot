//nolint:testpackage // Tests exercise unexported lifecycle seam directly.
package imagestore

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

	"zotregistry.dev/zot/v2/pkg/storage/constants"
)

var errInjectedReferenceCheck = errors.New("injected reference-check failure")

type lifecycleStubDriver struct {
	nameFn     func() string
	statFn     func(path string) (driver.FileInfo, error)
	readerFn   func(path string, offset int64) (io.ReadCloser, error)
	writerFn   func(path string, isAppend bool) (driver.FileWriter, error)
	linkFn     func(src, dst string) error
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
func (s *lifecycleStubDriver) Delete(path string) error             { return nil }

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
	localDriver := &lifecycleStubDriver{nameFn: func() string { return constants.LocalStorageDriverName }}
	localLifecycle := newBlobLifecycle(localDriver)

	if localLifecycle.ShouldGateDeleteUntilRebuild() {
		t.Fatal("local lifecycle should not gate delete until rebuild")
	}

	if localLifecycle.IncludeRepoInMountCandidates(constants.GlobalBlobsRepo) {
		t.Fatal("local lifecycle should exclude _blobstore from mount candidates")
	}

	if !localLifecycle.IncludeRepoInMountCandidates("repo") {
		t.Fatal("local lifecycle should include regular repos in mount candidates")
	}

	remoteDriver := &lifecycleStubDriver{nameFn: func() string { return constants.S3StorageDriverName }}
	remoteLifecycle := newBlobLifecycle(remoteDriver)

	if !remoteLifecycle.ShouldGateDeleteUntilRebuild() {
		t.Fatal("remote lifecycle should gate delete until rebuild")
	}

	if remoteLifecycle.IncludeRepoInMountCandidates(constants.GlobalBlobsRepo) {
		t.Fatal("remote lifecycle should exclude _blobstore from mount candidates")
	}

	if !remoteLifecycle.IncludeRepoInMountCandidates("repo") {
		t.Fatal("remote lifecycle should include regular repos in mount candidates")
	}
}

func TestLocalBlobLifecycleDelegatesToLink(t *testing.T) {
	linkCalls := 0

	driverStub := &lifecycleStubDriver{
		nameFn: func() string { return constants.LocalStorageDriverName },
		linkFn: func(src, dst string) error {
			linkCalls++
			if src == "" || dst == "" {
				t.Fatal("link should receive non-empty paths")
			}

			return nil
		},
	}

	lifecycle := newBlobLifecycle(driverStub)

	if err := lifecycle.PromoteCandidate("src/blob", "dst/blob"); err != nil {
		t.Fatalf("promote candidate: %v", err)
	}

	if err := lifecycle.LinkBlob("dst/blob", "dst/blob2"); err != nil {
		t.Fatalf("link blob: %v", err)
	}

	if linkCalls != 2 {
		t.Fatalf("expected 2 link calls, got %d", linkCalls)
	}
}

// TestLocalBlobLifecycleConvertMigratedRepoBlobToMarkerIsNoOp covers the local
// hardlink lifecycle's ConvertMigratedRepoBlobToMarker: unlike the remote/marker
// lifecycle, local storage keeps hardlinks in each repo, so no marker conversion is
// needed - it must always return nil without touching the driver.
func TestLocalBlobLifecycleConvertMigratedRepoBlobToMarkerIsNoOp(t *testing.T) {
	driverStub := &lifecycleStubDriver{
		nameFn: func() string { return constants.LocalStorageDriverName },
		linkFn: func(src, dst string) error {
			t.Fatal("ConvertMigratedRepoBlobToMarker must not touch the driver on local storage")

			return nil
		},
	}

	lifecycle := newBlobLifecycle(driverStub)

	if err := lifecycle.ConvertMigratedRepoBlobToMarker("global/blob", "repo/blob"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRemoteBlobLifecyclePromoteStreamsContent(t *testing.T) {
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

	lifecycle := newBlobLifecycle(driverStub)

	if err := lifecycle.PromoteCandidate("src/blob", "dst/blob"); err != nil {
		t.Fatalf("promote remote candidate: %v", err)
	}

	if readerCalls != 1 {
		t.Fatalf("expected one reader call, got %d", readerCalls)
	}

	if writerCalls != 1 {
		t.Fatalf("expected one writer call, got %d", writerCalls)
	}

	if commitCalls != 1 {
		t.Fatalf("expected one commit call, got %d", commitCalls)
	}

	if cancelCalls != 0 {
		t.Fatalf("expected zero cancel calls, got %d", cancelCalls)
	}

	if closeCalls != 1 {
		t.Fatalf("expected one close call, got %d", closeCalls)
	}

	if !bytes.Equal(written.Bytes(), content) {
		t.Fatal("streamed content does not match source content")
	}
}

var errInjectedPromote = errors.New("injected promote failure")

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
	t.Run("reader error: no writer is opened", func(t *testing.T) {
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

		lifecycle := newBlobLifecycle(driverStub)

		if err := lifecycle.PromoteCandidate("src", "dst"); !errors.Is(err, errInjectedPromote) {
			t.Fatalf("expected injected error, got %v", err)
		}

		if writerCalls != 0 {
			t.Fatalf("expected no writer call, got %d", writerCalls)
		}
	})

	t.Run("writer error: reader is closed", func(t *testing.T) {
		closeCalls := 0

		driverStub := &lifecycleStubDriver{
			readerFn: func(path string, offset int64) (io.ReadCloser, error) {
				return errCloseReader{Reader: bytes.NewReader(nil), closeCalls: &closeCalls}, nil
			},
			writerFn: func(path string, isAppend bool) (driver.FileWriter, error) {
				return nil, errInjectedPromote
			},
		}

		lifecycle := newBlobLifecycle(driverStub)

		if err := lifecycle.PromoteCandidate("src", "dst"); !errors.Is(err, errInjectedPromote) {
			t.Fatalf("expected injected error, got %v", err)
		}

		if closeCalls != 1 {
			t.Fatalf("expected one reader close call, got %d", closeCalls)
		}
	})

	t.Run("copy error: writer is cancelled and both are closed", func(t *testing.T) {
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

		lifecycle := newBlobLifecycle(driverStub)

		if err := lifecycle.PromoteCandidate("src", "dst"); !errors.Is(err, errInjectedPromote) {
			t.Fatalf("expected injected error, got %v", err)
		}

		if cancelCalls != 1 {
			t.Fatalf("expected one cancel call, got %d", cancelCalls)
		}

		if closeCalls != 1 {
			t.Fatalf("expected one close call, got %d", closeCalls)
		}
	})

	t.Run("commit error: writer is cancelled and both are closed", func(t *testing.T) {
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

		lifecycle := newBlobLifecycle(driverStub)

		if err := lifecycle.PromoteCandidate("src", "dst"); !errors.Is(err, errInjectedPromote) {
			t.Fatalf("expected injected error, got %v", err)
		}

		if cancelCalls != 1 {
			t.Fatalf("expected one cancel call, got %d", cancelCalls)
		}

		if closeCalls != 1 {
			t.Fatalf("expected one close call, got %d", closeCalls)
		}
	})

	t.Run("reader close error: writer is still closed", func(t *testing.T) {
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

		lifecycle := newBlobLifecycle(driverStub)

		if err := lifecycle.PromoteCandidate("src", "dst"); !errors.Is(err, errInjectedPromote) {
			t.Fatalf("expected injected error, got %v", err)
		}

		if closeCalls != 1 {
			t.Fatalf("expected one close call, got %d", closeCalls)
		}
	})

	t.Run("writer close error propagates", func(t *testing.T) {
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

		lifecycle := newBlobLifecycle(driverStub)

		if err := lifecycle.PromoteCandidate("src", "dst"); !errors.Is(err, errInjectedPromote) {
			t.Fatalf("expected injected error, got %v", err)
		}
	})
}

func TestRemoteBlobLifecycleLinkCreatesMarker(t *testing.T) {
	called := false

	var writtenPath string

	var marker []byte

	driverStub := &lifecycleStubDriver{
		nameFn: func() string { return constants.S3StorageDriverName },
		putContent: func(path string, content []byte) {
			called = true
			writtenPath = path

			marker = append([]byte(nil), content...)
		},
	}

	lifecycle := newBlobLifecycle(driverStub)

	if err := lifecycle.LinkBlob("src/blob", "dst/blob"); err != nil {
		t.Fatalf("remote link: %v", err)
	}

	if !called {
		t.Fatal("expected remote link to delegate to underlying driver")
	}

	if writtenPath != "dst/blob" {
		t.Fatalf("unexpected destination path: %s", writtenPath)
	}

	if len(marker) != 0 {
		t.Fatal("remote link should create an empty marker content")
	}
}

func TestBlobLifecycleResolveReadPath(t *testing.T) {
	nonEmptyDigest := godigest.FromString("non-empty")
	emptyDigest := nonEmptyDigest.Algorithm().FromBytes(nil)
	newLocalLifecycle := func() blobLifecycle {
		return newBlobLifecycle(&lifecycleStubDriver{
			nameFn: func() string { return constants.LocalStorageDriverName },
		})
	}
	newRemoteLifecycle := func() blobLifecycle {
		return newBlobLifecycle(&lifecycleStubDriver{
			nameFn: func() string { return constants.S3StorageDriverName },
		})
	}

	testCases := []struct {
		name          string
		lifecycle     blobLifecycle
		digest        godigest.Digest
		blobSize      int64
		globalPath    string
		wantPath      string
		wantErr       bool
		wantCacheCall bool
	}{
		{
			name:          "local non-zero blob keeps path",
			lifecycle:     newLocalLifecycle(),
			digest:        nonEmptyDigest,
			blobSize:      42,
			globalPath:    "_blobstore/blobs/sha256/content",
			wantPath:      "repo/blob",
			wantErr:       false,
			wantCacheCall: false,
		},
		{
			name: "remote uses global path when available",
			lifecycle: newBlobLifecycle(&lifecycleStubDriver{
				nameFn: func() string { return constants.S3StorageDriverName },
				statFn: func(path string) (driver.FileInfo, error) {
					if path == "_blobstore/blobs/sha256/content" {
						return lifecycleFileInfoStub{path: path, size: 42}, nil
					}

					return nil, driver.PathNotFoundError{Path: path}
				},
			}),
			digest:        nonEmptyDigest,
			blobSize:      0,
			globalPath:    "_blobstore/blobs/sha256/content",
			wantPath:      "_blobstore/blobs/sha256/content",
			wantErr:       false,
			wantCacheCall: false,
		},
		{
			name:          "remote empty digest keeps zero-size path",
			lifecycle:     newRemoteLifecycle(),
			digest:        emptyDigest,
			blobSize:      0,
			globalPath:    "_blobstore/blobs/sha256/content",
			wantPath:      "repo/blob",
			wantErr:       false,
			wantCacheCall: false,
		},
		{
			name:          "remote zero-size non-empty digest without global returns not found",
			lifecycle:     newRemoteLifecycle(),
			digest:        nonEmptyDigest,
			blobSize:      0,
			globalPath:    "_blobstore/blobs/sha256/content",
			wantPath:      "",
			wantErr:       true,
			wantCacheCall: false,
		},
		{
			name:          "remote non-zero blob falls back to repo path when global missing",
			lifecycle:     newRemoteLifecycle(),
			digest:        nonEmptyDigest,
			blobSize:      42,
			globalPath:    "_blobstore/blobs/sha256/content",
			wantPath:      "repo/blob",
			wantErr:       false,
			wantCacheCall: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cacheCalled := false

			gotPath, err := testCase.lifecycle.ResolveReadPath(
				"repo/blob",
				testCase.globalPath,
				testCase.digest,
				testCase.blobSize,
				func(digest godigest.Digest) (string, error) {
					cacheCalled = true
					if digest != testCase.digest {
						t.Fatalf("unexpected digest passed to cache resolver: got %s want %s", digest, testCase.digest)
					}

					return "_blobstore/blobs/sha256/content", nil
				})
			if testCase.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}

			if !testCase.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotPath != testCase.wantPath {
				t.Fatalf("unexpected resolved path: got %s want %s", gotPath, testCase.wantPath)
			}

			if cacheCalled != testCase.wantCacheCall {
				t.Fatalf("unexpected cache resolver usage: got %t want %t", cacheCalled, testCase.wantCacheCall)
			}
		})
	}
}

func TestBlobLifecycleShouldDeleteGlobalBlobLocal(t *testing.T) {
	lifecycle := newBlobLifecycle(&lifecycleStubDriver{
		nameFn: func() string { return constants.LocalStorageDriverName },
	})

	t.Run("missing path is not deleted", func(t *testing.T) {
		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(
			filepath.Join(t.TempDir(), "missing"),
			godigest.FromString("missing"),
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deleteDecision {
			t.Fatal("expected missing global blob path to not be deleted")
		}
	})

	t.Run("single hardlink can be deleted", func(t *testing.T) {
		digest := godigest.FromString("single-hardlink")
		globalBlobPath := filepath.Join(t.TempDir(), "global-blob")

		if err := os.WriteFile(globalBlobPath, []byte("content"), 0o600); err != nil {
			t.Fatalf("create global blob file: %v", err)
		}

		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(globalBlobPath, digest, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !deleteDecision {
			t.Fatal("expected single hardlink file to be deletable")
		}
	})

	t.Run("multiple hardlinks should not be deleted", func(t *testing.T) {
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deleteDecision {
			t.Fatal("expected multi-hardlink file to be retained")
		}
	})

	// The three cases above all Stat a real file on the test's local filesystem, so
	// Sys() always exposes a real *syscall.Stat_t with Nlink - there is no way to
	// drive ShouldDeleteGlobalBlob into the nlink-unavailable fallback that way. Use
	// a fake statFn instead to exercise that branch (and its isDigestReferenced
	// wiring) end-to-end, the way a filesystem that doesn't expose hardlink counts
	// actually would.
	fakeStatFn := func(name string) (os.FileInfo, error) {
		return fileInfoWithSys{sys: struct{ Size int64 }{Size: 1}}, nil
	}

	t.Run("nlink unavailable, digest not referenced elsewhere: deletable", func(t *testing.T) {
		lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("unreferenced"),
			func(godigest.Digest) (bool, error) { return false, nil })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !deleteDecision {
			t.Fatal("expected blob to be deletable when isDigestReferenced reports no other references")
		}
	})

	t.Run("nlink unavailable, digest still referenced elsewhere: not deletable", func(t *testing.T) {
		lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("referenced"),
			func(godigest.Digest) (bool, error) { return true, nil })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deleteDecision {
			t.Fatal("expected blob to be retained when isDigestReferenced reports another reference")
		}
	})

	t.Run("nlink unavailable, isDigestReferenced error propagates", func(t *testing.T) {
		lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

		_, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("errors"),
			func(godigest.Digest) (bool, error) { return false, errInjectedReferenceCheck })
		if !errors.Is(err, errInjectedReferenceCheck) {
			t.Fatalf("expected injected error to propagate, got %v", err)
		}
	})

	t.Run("nlink unavailable, isDigestReferenced nil: not deletable", func(t *testing.T) {
		lifecycle := &localHardlinkBlobLifecycle{statFn: fakeStatFn}

		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob("irrelevant", godigest.FromString("no-callback"), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deleteDecision {
			t.Fatal("expected blob to be retained when there is no way to check other references")
		}
	})
}

func TestBlobLifecycleShouldDeleteGlobalBlobRemote(t *testing.T) {
	lifecycle := newBlobLifecycle(&lifecycleStubDriver{
		nameFn: func() string { return constants.S3StorageDriverName },
	})

	t.Run("delete when digest is unreferenced", func(t *testing.T) {
		callbackCalled := false
		digest := godigest.FromString("unreferenced")

		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(
			"ignored/path",
			digest,
			func(callbackDigest godigest.Digest) (bool, error) {
				callbackCalled = true
				if callbackDigest != digest {
					t.Fatalf("unexpected digest in callback: got %s want %s", callbackDigest, digest)
				}

				return false, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !callbackCalled {
			t.Fatal("expected reference callback to be invoked")
		}

		if !deleteDecision {
			t.Fatal("expected unreferenced digest to be deletable")
		}
	})

	t.Run("retain when digest is still referenced", func(t *testing.T) {
		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(
			"ignored/path",
			godigest.FromString("referenced"),
			func(godigest.Digest) (bool, error) {
				return true, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deleteDecision {
			t.Fatal("expected referenced digest to be retained")
		}
	})

	t.Run("callback errors are propagated", func(t *testing.T) {
		callbackErr := io.EOF

		deleteDecision, err := lifecycle.ShouldDeleteGlobalBlob(
			"ignored/path",
			godigest.FromString("error-case"),
			func(godigest.Digest) (bool, error) {
				return false, callbackErr
			},
		)
		if !errors.Is(err, callbackErr) {
			t.Fatalf("expected callback error to propagate, got %v", err)
		}

		if deleteDecision {
			t.Fatal("expected delete decision to be false on callback error")
		}
	})
}

func TestHardLinkCount(t *testing.T) {
	t.Run("returns count when Nlink is present", func(t *testing.T) {
		count, ok := hardLinkCount(fileInfoWithSys{sys: struct{ Nlink uint64 }{Nlink: 3}})
		if !ok {
			t.Fatal("expected hard link count to be detected")
		}

		if count != 3 {
			t.Fatalf("unexpected hard link count: got %d want %d", count, 3)
		}
	})

	t.Run("returns false when syscall payload has no Nlink", func(t *testing.T) {
		_, ok := hardLinkCount(fileInfoWithSys{sys: struct{ Size int64 }{Size: 1}})
		if ok {
			t.Fatal("expected hard link detection to fail without Nlink field")
		}
	})

	t.Run("returns false when syscall payload is nil", func(t *testing.T) {
		_, ok := hardLinkCount(fileInfoWithSys{sys: nil})
		if ok {
			t.Fatal("expected hard link detection to fail for nil syscall payload")
		}
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

type lifecycleFileInfoStub struct {
	path string
	size int64
}

func (f lifecycleFileInfoStub) Path() string       { return f.path }
func (f lifecycleFileInfoStub) Size() int64        { return f.size }
func (f lifecycleFileInfoStub) ModTime() time.Time { return time.Time{} }
func (f lifecycleFileInfoStub) IsDir() bool        { return false }
