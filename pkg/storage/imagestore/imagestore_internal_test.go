package imagestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type streamTestDriver struct {
	reader    io.ReadCloser
	writer    driver.FileWriter
	ensureErr error
	writeErr  error
	ensureFn  func(string) error
}

func (d *streamTestDriver) Name() string { return "remote" }
func (d *streamTestDriver) EnsureDir(dir string) error {
	if d.ensureFn != nil {
		return d.ensureFn(dir)
	}

	return d.ensureErr
}
func (d *streamTestDriver) DirExists(string) bool                       { return true }
func (d *streamTestDriver) Reader(string, int64) (io.ReadCloser, error) { return d.reader, nil }
func (d *streamTestDriver) ReadFile(string) ([]byte, error)             { return nil, nil }
func (d *streamTestDriver) Delete(string) error                         { return nil }
func (d *streamTestDriver) Stat(string) (driver.FileInfo, error)        { return nil, nil }
func (d *streamTestDriver) Writer(string, bool) (driver.FileWriter, error) { return d.writer, nil }

func (d *streamTestDriver) WriteFile(string, []byte) (int, error)             { return 0, d.writeErr }
func (d *streamTestDriver) Walk(string, driver.WalkFn) error                  { return nil }
func (d *streamTestDriver) List(string) ([]string, error)                     { return nil, nil }
func (d *streamTestDriver) Move(string, string) error                         { return nil }
func (d *streamTestDriver) SameFile(string, string) bool                      { return false }
func (d *streamTestDriver) Link(string, string) error                         { return nil }
func (d *streamTestDriver) RedirectURL(*http.Request, string) (string, error) { return "", nil }

func TestStreamBlobCandidate(t *testing.T) {
	Convey("Streams and verifies a remote blob", t, func() {
		content := []byte("streamed blob content")
		digest := godigest.FromBytes(content)
		var copied bytes.Buffer
		committed := false

		testDriver := &streamTestDriver{
			reader: io.NopCloser(bytes.NewReader(content)),
			writer: &mocks.FileWriterMock{
				WriteFn: copied.Write,
				CommitFn: func() error {
					committed = true

					return nil
				},
			},
		}
		imageStore := &ImageStore{storeDriver: testDriver}

		err := imageStore.streamBlobCandidate(blobCandidate{blobPath: "source", size: int64(len(content))},
			digest, "destination")
		So(err, ShouldBeNil)
		So(copied.Bytes(), ShouldResemble, content)
		So(committed, ShouldBeTrue)
	})

	Convey("Rejects a blob whose streamed content does not match its digest", t, func() {
		content := []byte("corrupted")
		cancelled := false

		testDriver := &streamTestDriver{
			reader: io.NopCloser(bytes.NewReader(content)),
			writer: &mocks.FileWriterMock{
				WriteFn: func(p []byte) (int, error) { return len(p), nil },
				CancelFn: func() error {
					cancelled = true

					return nil
				},
			},
		}
		imageStore := &ImageStore{storeDriver: testDriver}

		err := imageStore.streamBlobCandidate(blobCandidate{blobPath: "source", size: int64(len(content))},
			godigest.FromString("expected"), "destination")
		So(err, ShouldEqual, zerr.ErrBadBlobDigest)
		So(cancelled, ShouldBeTrue)
	})
}

func TestGetAllDedupeReposCandidatesExcludesBlobstore(t *testing.T) {
	Convey("The internal blobstore is not an authorization candidate", t, func() {
		digest := godigest.FromString("blob")
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		imageStore := &ImageStore{
			rootDir: "/root",
			cache: mocks.CacheMock{
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return []string{
						"/root/" + storageConstants.GlobalBlobsRepo + "/blobs/sha256/blob",
						"/root/repo/blobs/sha256/blob",
					}, nil
				},
			},
			lock:    new(sync.RWMutex),
			metrics: metrics,
		}

		repos, err := imageStore.GetAllDedupeReposCandidates(digest)
		So(err, ShouldBeNil)
		So(repos, ShouldResemble, []string{"repo"})
	})
}

func TestInitRepoRejectsInvalidInternalRepoNames(t *testing.T) {
	Convey("initRepo rejects invalid non-internal repository names", t, func() {
		ensureCalls := 0
		testDriver := &streamTestDriver{
			ensureFn: func(string) error {
				ensureCalls++

				return nil
			},
		}
		imageStore := &ImageStore{storeDriver: testDriver, log: zlog.NewTestLogger()}

		err := imageStore.initRepo(context.Background(), "../escape")
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)
		So(ensureCalls, ShouldEqual, 0)
	})

	Convey("initRepo still allows the internal global blobstore name", t, func() {
		ensureCalls := 0
		testDriver := &streamTestDriver{
			ensureFn: func(string) error {
				ensureCalls++

				return nil
			},
		}
		imageStore := &ImageStore{storeDriver: testDriver, log: zlog.NewTestLogger()}

		err := imageStore.initRepo(context.Background(), storageConstants.GlobalBlobsRepo)
		So(err, ShouldBeNil)
		So(ensureCalls, ShouldEqual, 2)
	})
}

func TestWriteBlobstoreMigrationMarkerErrors(t *testing.T) {
	Convey("Migration marker directory errors are propagated", t, func() {
		testDriver := &streamTestDriver{ensureErr: zerr.ErrBadBlobDigest}
		imageStore := &ImageStore{storeDriver: testDriver}

		err := imageStore.writeBlobstoreMigrationMarker("_blobstore/.migrated")
		So(err, ShouldEqual, zerr.ErrBadBlobDigest)
	})

	Convey("Migration marker write errors are propagated", t, func() {
		testDriver := &streamTestDriver{writeErr: zerr.ErrBadBlobDigest}
		imageStore := &ImageStore{storeDriver: testDriver}

		err := imageStore.writeBlobstoreMigrationMarker("_blobstore/.migrated")
		So(err, ShouldEqual, zerr.ErrBadBlobDigest)
	})
}
