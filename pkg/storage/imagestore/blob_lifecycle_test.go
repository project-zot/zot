//nolint:testpackage // Tests exercise unexported lifecycle seam directly.
package imagestore

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/storage/constants"
)

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

type lifecycleFileInfoStub struct {
	path string
	size int64
}

func (f lifecycleFileInfoStub) Path() string       { return f.path }
func (f lifecycleFileInfoStub) Size() int64        { return f.size }
func (f lifecycleFileInfoStub) ModTime() time.Time { return time.Time{} }
func (f lifecycleFileInfoStub) IsDir() bool        { return false }
