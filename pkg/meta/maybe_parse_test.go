package meta_test

import (
	"errors"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestMaybeParseStorageGate(t *testing.T) {
	logger := log.NewTestLogger()
	emptyStore := storage.StoreController{DefaultStore: mocks.MockedImageStore{
		GetRepositoriesFn: func() ([]string, error) { return nil, nil },
	}}

	Convey("fastRestart=false always runs the full parse and stamps", t, func() {
		var stamped string

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn: func() ([]string, error) { return nil, nil },
			GetFastRestartStampFn: func() (string, error) {
				t.Fatal("GetFastRestartStamp must not be called when fastRestart=false")

				return "", nil
			},
			SetFastRestartStampFn: func(v string) error {
				stamped = v

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, false, "v1", logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true with matching stamp skips the parse", t, func() {
		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn: func() ([]string, error) {
				t.Fatal("full parse must not run when stamp matches")

				return nil, nil
			},
			GetFastRestartStampFn: func() (string, error) { return "v1", nil },
			SetFastRestartStampFn: func(v string) error {
				t.Fatal("must not re-stamp when stamp already matches")

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "v1", logger)
		So(err, ShouldBeNil)
	})

	Convey("fastRestart=true with mismatched stamp runs full parse and re-stamps", t, func() {
		var (
			parsed  bool
			stamped string
		)

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn: func() ([]string, error) {
				parsed = true

				return nil, nil
			},
			GetFastRestartStampFn: func() (string, error) { return "v1", nil },
			SetFastRestartStampFn: func(v string) error {
				stamped = v

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "v2", logger)
		So(err, ShouldBeNil)
		So(parsed, ShouldBeTrue)
		So(stamped, ShouldEqual, "v2")
	})

	Convey("fastRestart=true with empty stamp runs full parse and stamps", t, func() {
		var stamped string

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn:     func() ([]string, error) { return nil, nil },
			GetFastRestartStampFn: func() (string, error) { return "", nil },
			SetFastRestartStampFn: func(v string) error {
				stamped = v

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "v1", logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true falls back to full parse when GetFastRestartStamp errors", t, func() {
		var stamped string

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn:     func() ([]string, error) { return nil, nil },
			GetFastRestartStampFn: func() (string, error) { return "", errors.New("redis down") }, //nolint: err113
			SetFastRestartStampFn: func(v string) error {
				stamped = v

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "v1", logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true with empty binary identity always parses and never stamps", t, func() {
		var (
			parsed       bool
			stampInvoked bool
		)

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn: func() ([]string, error) {
				parsed = true

				return nil, nil
			},
			GetFastRestartStampFn: func() (string, error) { return "", nil },
			SetFastRestartStampFn: func(v string) error {
				stampInvoked = true

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "", logger)
		So(err, ShouldBeNil)
		So(parsed, ShouldBeTrue)
		So(stampInvoked, ShouldBeFalse)
	})

	Convey("a repo that fails to parse is not stamped", t, func() {
		// StatIndex fails for the only repo, so it is skipped (failedRepos > 0).
		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return []string{repo}, nil },
			StatIndexFn: func(string) (bool, int64, time.Time, error) {
				return false, 0, time.Time{}, errMetaTestInjected
			},
		}}

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn: func() ([]string, error) { return nil, nil },
			SetFastRestartStampFn: func(string) error {
				t.Fatal("must not stamp when a repo failed to parse")

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, store, false, "v1", logger)
		So(err, ShouldBeNil)
	})

	Convey("a repo with a missing manifest blob is not stamped", t, func() {
		// The repo parses, but its only manifest blob is missing, so the repo is
		// only partially parsed (partialRepos > 0).
		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return []string{repo}, nil },
			GetIndexContentFn: func(string) ([]byte, error) {
				return getIndexBlob(ispec.Index{
					Manifests: []ispec.Descriptor{{
						MediaType:   ispec.MediaTypeImageManifest,
						Digest:      godigest.FromString("missing"),
						Annotations: map[string]string{ispec.AnnotationRefName: "tag1"},
					}},
				}), nil
			},
			GetBlobContentFn: func(string, godigest.Digest) ([]byte, error) {
				return nil, zerr.ErrBlobNotFound
			},
		}}

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn: func() ([]string, error) { return nil, nil },
			SetFastRestartStampFn: func(string) error {
				t.Fatal("must not stamp when a repo was only partially parsed")

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, store, false, "v1", logger)
		So(err, ShouldBeNil)
	})
}
