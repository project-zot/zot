package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"testing"
	"time"

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
		t.Fatalf("source upload still exists after cleanup, stat error = %v", err)
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
