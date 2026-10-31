package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type uploadHashGateDriver struct {
	storageTypes.Driver

	path        string
	hashEOF     chan struct{}
	releaseHash chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

type leavingMoveDriver struct {
	storageTypes.Driver
}

type idleUploadDeleter interface {
	DeleteBlobUploadIfIdle(repo, uuid string) (bool, error)
}

func (d *leavingMoveDriver) Move(sourcePath, destPath string) error {
	content, err := d.Driver.ReadFile(sourcePath)
	if err != nil {
		return err
	}

	_, err = d.Driver.WriteFile(destPath, content)

	return err
}

func (d *uploadHashGateDriver) Reader(readPath string, offset int64) (io.ReadCloser, error) {
	reader, err := d.Driver.Reader(readPath, offset)
	if err != nil || readPath != d.path {
		return reader, err
	}

	return &uploadHashGateReader{
		ReadCloser: reader,
		eof:        d.hashEOF,
		release:    d.releaseHash,
		once:       &d.once,
	}, nil
}

func (d *uploadHashGateDriver) unblockHash() {
	d.releaseOnce.Do(func() { close(d.releaseHash) })
}

type uploadHashGateReader struct {
	io.ReadCloser

	eof     chan struct{}
	release chan struct{}
	once    *sync.Once
}

func (r *uploadHashGateReader) Read(buf []byte) (int, error) {
	n, err := r.ReadCloser.Read(buf)
	if err == io.EOF {
		r.once.Do(func() { close(r.eof) })
		<-r.release
	}

	return n, err
}

type blockedUploadBody struct {
	data        []byte
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (b *blockedUploadBody) Read(buf []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	if len(b.data) == 0 {
		return 0, io.EOF
	}

	n := copy(buf, b.data)
	b.data = b.data[n:]

	return n, nil
}

func (b *blockedUploadBody) unblock() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func newUploadHashGateStore(t *testing.T) (storageTypes.ImageStore, *uploadHashGateDriver, string) {
	t.Helper()

	root := t.TempDir()
	driver := &uploadHashGateDriver{
		Driver:      local.New(true),
		hashEOF:     make(chan struct{}),
		releaseHash: make(chan struct{}),
	}
	store := imagestore.NewImageStore(root, "", false, true, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, driver, nil, nil, nil)
	if store == nil {
		t.Fatal("NewImageStore returned nil")
	}

	return store, driver, root
}

func TestFinalizeSealsUploadBeforeDigest(t *testing.T) {
	store, driver, root := newUploadHashGateStore(t)
	ctx := context.Background()
	repo := "sealed-before-digest"
	verified := []byte("verified-content")
	digest := godigest.FromBytes(verified)

	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBlobChunkStreamed(ctx, repo, uuid, bytes.NewReader(verified)); err != nil {
		t.Fatal(err)
	}
	driver.path = path.Join(root, repo, storageConstants.BlobUploadDir, uuid)

	finishErr := make(chan error, 1)
	go func() {
		finishErr <- store.FinishBlobUpload(repo, uuid, bytes.NewReader(nil), digest)
	}()

	select {
	case <-driver.hashEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("finalize did not reach the digest read")
	}
	defer driver.unblockHash()

	lateBody := &blockedUploadBody{
		data:    []byte("late-content"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer lateBody.unblock()

	writerErr := make(chan error, 1)

	go func() {
		_, err := store.PutBlobChunkStreamed(ctx, repo, uuid, lateBody)
		writerErr <- err
	}()

	select {
	case err := <-writerErr:
		if !errors.Is(err, zerr.ErrUploadNotFound) {
			t.Fatalf("late writer error = %v, want ErrUploadNotFound", err)
		}
	case <-lateBody.started:
		t.Fatal("late writer consumed its request body after the session was sealed")
	case <-time.After(2 * time.Second):
		t.Fatal("late writer was not rejected")
	}

	driver.unblockHash()
	if err := <-finishErr; err != nil {
		t.Fatal(err)
	}

	actual, err := os.ReadFile(store.BlobPath(repo, digest))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, verified) {
		t.Fatalf("target content = %q, want %q", actual, verified)
	}
}

func TestFinalizeWaitsForActiveUploadWriter(t *testing.T) {
	store, driver, root := newUploadHashGateStore(t)
	ctx := context.Background()
	repo := "active-writer"
	verified := []byte("verified-content")
	appended := []byte("active-content")
	digest := godigest.FromBytes(verified)

	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBlobChunkStreamed(ctx, repo, uuid, bytes.NewReader(verified)); err != nil {
		t.Fatal(err)
	}
	driver.path = path.Join(root, repo, storageConstants.BlobUploadDir, uuid)

	body := &blockedUploadBody{
		data:    appended,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer body.unblock()

	writerErr := make(chan error, 1)

	go func() {
		_, err := store.PutBlobChunkStreamed(ctx, repo, uuid, body)
		writerErr <- err
	}()
	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("active writer did not start")
	}

	finishErr := make(chan error, 1)
	go func() {
		finishErr <- store.FinishBlobUpload(repo, uuid, bytes.NewReader(nil), digest)
	}()

	select {
	case <-driver.hashEOF:
		t.Fatal("finalize hashed before the active writer completed")
	case err := <-finishErr:
		t.Fatalf("finalize returned before the active writer completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	body.unblock()
	if err := <-writerErr; err != nil {
		t.Fatal(err)
	}

	select {
	case <-driver.hashEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("finalize did not hash after the active writer completed")
	}
	driver.unblockHash()

	if err := <-finishErr; !errors.Is(err, zerr.ErrBadBlobDigest) {
		t.Fatalf("finalize error = %v, want ErrBadBlobDigest", err)
	}

	actual, err := os.ReadFile(store.BlobUploadPath(repo, uuid))
	if err != nil {
		t.Fatal(err)
	}

	expected := append(append([]byte(nil), verified...), appended...)
	if !bytes.Equal(actual, expected) {
		t.Fatalf("upload content = %q, want %q", actual, expected)
	}
	if got := godigest.FromBytes(actual); got == digest {
		t.Fatalf("upload unexpectedly still has verified digest %s", got)
	}
}

func TestFinalizeKeepsSealedSessionWhenSourceRemains(t *testing.T) {
	root := t.TempDir()
	driver := &leavingMoveDriver{Driver: local.New(true)}
	store := imagestore.NewImageStore(root, "", false, true, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, driver, nil, nil, nil)
	if store == nil {
		t.Fatal("NewImageStore returned nil")
	}

	ctx := context.Background()
	repo := "source-remains"
	content := []byte("sealed-content")
	digest := godigest.FromBytes(content)
	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBlobChunkStreamed(ctx, repo, uuid, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}

	if err := store.FinishBlobUpload(repo, uuid, bytes.NewReader(nil), digest); err != nil {
		t.Fatal(err)
	}

	lateErr := make(chan error, 1)

	go func() {
		_, err := store.PutBlobChunkStreamed(ctx, repo, uuid, bytes.NewReader([]byte("late")))
		lateErr <- err
	}()
	if err := <-lateErr; !errors.Is(err, zerr.ErrUploadNotFound) {
		t.Fatalf("late writer error = %v, want ErrUploadNotFound", err)
	}

	if err := store.DeleteBlobUpload(repo, uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.BlobUploadPath(repo, uuid)); !os.IsNotExist(err) {
		t.Fatalf("source upload still exists after cleanup, stat error = %v", err)
	}
}

func TestDeleteBlobUploadIfIdleCleansSealedSource(t *testing.T) {
	root := t.TempDir()
	driver := &leavingMoveDriver{Driver: local.New(true)}
	store := imagestore.NewImageStore(root, "", false, true, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, driver, nil, nil, nil)
	if store == nil {
		t.Fatal("NewImageStore returned nil")
	}

	ctx := context.Background()
	repo := "idle-sealed-source"
	content := []byte("sealed-content")
	digest := godigest.FromBytes(content)
	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBlobChunkStreamed(ctx, repo, uuid, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBlobUpload(repo, uuid, bytes.NewReader(nil), digest); err != nil {
		t.Fatal(err)
	}

	deleter, ok := store.(idleUploadDeleter)
	if !ok {
		t.Fatal("image store does not expose idle upload deletion")
	}
	deleted, err := deleter.DeleteBlobUploadIfIdle(repo, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("sealed upload was not deleted")
	}
	if _, err := os.Stat(store.BlobUploadPath(repo, uuid)); !os.IsNotExist(err) {
		t.Fatalf("source upload still exists after idle cleanup, stat error = %v", err)
	}
}

func TestDeleteBlobUploadIfIdleDoesNotWaitForActiveWriter(t *testing.T) {
	store, _, _ := newUploadHashGateStore(t)
	deleter, ok := store.(idleUploadDeleter)
	if !ok {
		t.Fatal("image store does not expose idle upload deletion")
	}

	ctx := context.Background()
	repo := "gc-busy-upload"
	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	body := &blockedUploadBody{
		data:    []byte("active-content"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer body.unblock()

	writerErr := make(chan error, 1)

	go func() {
		_, err := store.PutBlobChunkStreamed(ctx, repo, uuid, body)
		writerErr <- err
	}()

	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("active writer did not start")
	}

	deleteResult := make(chan struct {
		deleted bool
		err     error
	}, 1)
	go func() {
		var deleted bool
		err := store.WithRepoCleanupLock(repo, func() error {
			var err error
			deleted, err = deleter.DeleteBlobUploadIfIdle(repo, uuid)

			return err
		})
		deleteResult <- struct {
			deleted bool
			err     error
		}{deleted: deleted, err: err}
	}()

	select {
	case result := <-deleteResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.deleted {
			t.Fatal("busy upload was reported as deleted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle upload deletion waited for the active writer")
	}

	body.unblock()
	if err := <-writerErr; err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteBlobUpload(repo, uuid); err != nil {
		t.Fatal(err)
	}
}

// An unlisted upload (S3 multipart is not an object until commit) must still
// keep the repo while the body is being copied. Once that copy finishes, an
// idle session must not pin the repo.
func TestRemoveIdleRepositoryKeepsRepoDuringUnlistedUpload(t *testing.T) {
	root := t.TempDir()
	store := imagestore.NewImageStore(root, "", false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
	ctx := context.Background()
	repo := "unlisted-upload"

	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	body := &blockedUploadBody{
		data:    []byte("partial"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writerErr := make(chan error, 1)

	go func() {
		_, err := store.PutBlobChunk(ctx, repo, uuid, 0, int64(len(body.data)), body)
		writerErr <- err
	}()

	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("blob chunk did not start reading")
	}

	uploadPath := path.Join(root, repo, storageConstants.BlobUploadDir, uuid)
	if err := os.Remove(uploadPath); err != nil {
		t.Fatal(err)
	}

	var removed bool

	err = store.WithRepoLock(repo, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(repo, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("repo was removed while a blob upload was being written")
	}
	if _, statErr := os.Stat(path.Join(root, repo)); statErr != nil {
		t.Fatal(statErr)
	}

	body.unblock()
	if err := <-writerErr; err != nil {
		t.Fatal(err)
	}

	// The copy finished and the upload object is still gone, so the session is
	// idle and the listing is empty. The repo can be removed.
	err = store.WithRepoLock(repo, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(repo, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("idle upload session kept the repo after the write finished")
	}
}

func TestRemoveIdleRepositoryKeepsRepoDuringUnlistedFullUpload(t *testing.T) {
	root := t.TempDir()
	store := imagestore.NewImageStore(root, "", false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
	ctx := context.Background()
	repo := "unlisted-full"
	data := []byte("monolithic")
	digest := godigest.FromBytes(data)

	if err := store.InitRepo(ctx, repo); err != nil {
		t.Fatal(err)
	}

	body := &blockedUploadBody{
		data:    data,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writerErr := make(chan error, 1)

	go func() {
		_, _, err := store.FullBlobUpload(ctx, repo, body, digest)
		writerErr <- err
	}()

	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("full blob upload did not start reading")
	}

	uploads := path.Join(root, repo, storageConstants.BlobUploadDir)
	entries, err := os.ReadDir(uploads)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("upload entries = %d, want 1", len(entries))
	}
	if err := os.Remove(path.Join(uploads, entries[0].Name())); err != nil {
		t.Fatal(err)
	}

	var removed bool

	err = store.WithRepoLock(repo, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(repo, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("repo was removed while a monolithic upload was being written")
	}

	body.unblock()
	// The staging name was removed while the body was open, so the move cannot
	// find it. The repository itself stayed.
	if err := <-writerErr; err == nil {
		t.Fatal("full upload succeeded after its staging file was removed")
	}
	if _, statErr := os.Stat(path.Join(root, repo)); statErr != nil {
		t.Fatal(statErr)
	}
}

// lateUploadListDriver reports no uploads on the first list of an upload
// directory and one upload on the next. The idle-repo delete lists twice, and
// the second list is the one that must keep the repository. onSecond runs
// while that delete has already refused new writers.
type lateUploadListDriver struct {
	storageTypes.Driver

	uploadsPath string
	lists       int
	onSecond    func()
	failSecond  error
}

func (d *lateUploadListDriver) List(fullPath string) ([]string, error) {
	if fullPath != d.uploadsPath {
		return d.Driver.List(fullPath)
	}

	d.lists++
	if d.lists == 2 && d.onSecond != nil {
		d.onSecond()
	}

	if d.lists < 2 {
		return []string{}, nil
	}

	if d.failSecond != nil {
		return nil, d.failSecond
	}

	return []string{path.Join(fullPath, "late")}, nil
}

func TestRemoveIdleRepositoryKeepsRepoWhenUploadAppearsBeforeDelete(t *testing.T) {
	root := t.TempDir()
	repo := "late-upload"
	driver := &lateUploadListDriver{Driver: local.New(true)}
	store := imagestore.NewImageStore(root, "", false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, driver, nil, nil, nil)
	driver.uploadsPath = path.Join(root, repo, storageConstants.BlobUploadDir)

	if err := store.InitRepo(context.Background(), repo); err != nil {
		t.Fatal(err)
	}

	driver.lists = 0

	ctx := context.Background()
	uuid := "upload-1"
	digest := godigest.FromBytes([]byte("a"))
	driver.onSecond = func() {
		body := bytes.NewReader([]byte("a"))
		if _, err := store.PutBlobChunkStreamed(ctx, repo, uuid, body); !errors.Is(err, zerr.ErrUploadNotFound) {
			t.Errorf("streamed chunk error = %v, want ErrUploadNotFound", err)
		}

		body.Reset([]byte("a"))
		if _, err := store.PutBlobChunk(ctx, repo, uuid, 0, 1, body); !errors.Is(err, zerr.ErrUploadNotFound) {
			t.Errorf("chunk error = %v, want ErrUploadNotFound", err)
		}

		if err := store.FinishBlobUpload(repo, uuid, bytes.NewReader(nil), digest); !errors.Is(err, zerr.ErrUploadNotFound) {
			t.Errorf("finish error = %v, want ErrUploadNotFound", err)
		}

		body.Reset([]byte("a"))
		if _, _, err := store.FullBlobUpload(ctx, repo, body, digest); !errors.Is(err, zerr.ErrUploadNotFound) {
			t.Errorf("full upload error = %v, want ErrUploadNotFound", err)
		}
	}

	var removed bool

	err := store.WithRepoLock(repo, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(repo, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("repo was removed after an upload appeared")
	}
	if driver.lists < 2 {
		t.Fatalf("upload lists = %d, want at least 2", driver.lists)
	}
	if _, statErr := os.Stat(path.Join(root, repo)); statErr != nil {
		t.Fatal(statErr)
	}
}

// blockingCommitDriver lists the upload directory as empty, so a staging
// file does not keep the repository. Commit on that directory waits until
// release. That is the window where FinishBlobUpload's in-progress mark must
// keep the repository, and after release the commit must still succeed.
type blockingCommitDriver struct {
	storageTypes.Driver

	uploadsPath string
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (d *blockingCommitDriver) List(fullPath string) ([]string, error) {
	if fullPath == d.uploadsPath {
		return []string{}, nil
	}

	return d.Driver.List(fullPath)
}

func (d *blockingCommitDriver) Writer(filepath string, isAppend bool) (driver.FileWriter, error) {
	writer, err := d.Driver.Writer(filepath, isAppend)
	if err != nil || d.uploadsPath == "" || !strings.HasPrefix(filepath, d.uploadsPath+"/") {
		return writer, err
	}

	return &blockingCommitWriter{FileWriter: writer, gate: d}, nil
}

func (d *blockingCommitDriver) unblock() {
	d.releaseOnce.Do(func() { close(d.release) })
}

type blockingCommitWriter struct {
	driver.FileWriter

	gate *blockingCommitDriver
}

func (w *blockingCommitWriter) Commit(ctx context.Context) error {
	w.gate.once.Do(func() { close(w.gate.started) })
	<-w.gate.release

	return w.FileWriter.Commit(ctx)
}

func TestRemoveIdleRepositoryKeepsRepoDuringUnlistedFinish(t *testing.T) {
	root := t.TempDir()
	repo := "unlisted-finish"
	driver := &blockingCommitDriver{
		Driver:  local.New(true),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	store := imagestore.NewImageStore(root, "", false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, driver, nil, nil, nil)
	driver.uploadsPath = path.Join(root, repo, storageConstants.BlobUploadDir)

	ctx := context.Background()
	data := []byte("committed")
	digest := godigest.FromBytes(data)

	uuid, err := store.NewBlobUpload(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBlobChunk(ctx, repo, uuid, 0, int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	finishErr := make(chan error, 1)
	go func() {
		finishErr <- store.FinishBlobUpload(repo, uuid, bytes.NewReader(nil), digest)
	}()

	select {
	case <-driver.started:
	case <-time.After(2 * time.Second):
		t.Fatal("finish did not reach commit")
	}
	defer driver.unblock()

	var removed bool

	err = store.WithRepoLock(repo, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(repo, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("repo was removed while a blob upload was being committed")
	}
	if _, statErr := os.Stat(path.Join(root, repo)); statErr != nil {
		t.Fatal(statErr)
	}

	driver.unblock()
	if err := <-finishErr; err != nil {
		t.Fatal(err)
	}

	found, _, _, err := store.StatBlob(repo, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("committed blob is missing after the idle-repo check")
	}
}

func TestRemoveIdleRepositoryKeepsParentWhileChildUploadIsUnlisted(t *testing.T) {
	root := t.TempDir()
	store := imagestore.NewImageStore(root, "", false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
	ctx := context.Background()
	parent := "nested"
	child := "nested/child"

	if err := store.InitRepo(ctx, parent); err != nil {
		t.Fatal(err)
	}

	uuid, err := store.NewBlobUpload(ctx, child)
	if err != nil {
		t.Fatal(err)
	}

	body := &blockedUploadBody{
		data:    []byte("child"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writerErr := make(chan error, 1)

	go func() {
		_, err := store.PutBlobChunk(ctx, child, uuid, 0, int64(len(body.data)), body)
		writerErr <- err
	}()

	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("child blob chunk did not start reading")
	}

	uploadPath := path.Join(root, child, storageConstants.BlobUploadDir, uuid)
	if err := os.Remove(uploadPath); err != nil {
		t.Fatal(err)
	}

	var removed bool

	err = store.WithRepoLock(parent, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(parent, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("parent was removed while a child blob upload was being written")
	}
	if _, statErr := os.Stat(path.Join(root, child)); statErr != nil {
		t.Fatal(statErr)
	}

	body.unblock()
	if err := <-writerErr; err != nil {
		t.Fatal(err)
	}

	err = store.WithRepoLock(parent, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(parent, 0)

		return lockErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("idle child upload kept the parent after the write finished")
	}
}

func TestRemoveIdleRepositoryKeepsRepoWhenUploadRecheckFails(t *testing.T) {
	root := t.TempDir()
	repo := "recheck-fail"
	listErr := errors.New("upload list failed") //nolint:err113 // test sentinel
	driver := &lateUploadListDriver{Driver: local.New(true), failSecond: listErr}
	store := imagestore.NewImageStore(root, "", false, false, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, driver, nil, nil, nil)
	driver.uploadsPath = path.Join(root, repo, storageConstants.BlobUploadDir)

	if err := store.InitRepo(context.Background(), repo); err != nil {
		t.Fatal(err)
	}

	driver.lists = 0

	var removed bool

	err := store.WithRepoLock(repo, func() error {
		var lockErr error

		removed, lockErr = store.RemoveIdleRepository(repo, 0)

		return lockErr
	})
	if !errors.Is(err, listErr) {
		t.Fatalf("recheck error = %v, want upload list failed", err)
	}
	if removed {
		t.Fatal("repo was removed when the upload recheck failed")
	}
	if _, statErr := os.Stat(path.Join(root, repo)); statErr != nil {
		t.Fatal(statErr)
	}
}
