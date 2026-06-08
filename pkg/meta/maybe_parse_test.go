package meta_test

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

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
			GetWriterVersionFn: func() (string, error) {
				t.Fatal("GetWriterVersion must not be called when fastRestart=false")

				return "", nil
			},
			SetWriterVersionFn: func(v string) error {
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
			GetWriterVersionFn: func() (string, error) { return "v1", nil },
			SetWriterVersionFn: func(v string) error {
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
			GetWriterVersionFn: func() (string, error) { return "v1", nil },
			SetWriterVersionFn: func(v string) error {
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
			GetAllRepoNamesFn:  func() ([]string, error) { return nil, nil },
			GetWriterVersionFn: func() (string, error) { return "", nil },
			SetWriterVersionFn: func(v string) error {
				stamped = v

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "v1", logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true falls back to full parse when GetWriterVersion errors", t, func() {
		var stamped string

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn:  func() ([]string, error) { return nil, nil },
			GetWriterVersionFn: func() (string, error) { return "", errors.New("redis down") }, //nolint: err113
			SetWriterVersionFn: func(v string) error {
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
			GetWriterVersionFn: func() (string, error) { return "", nil },
			SetWriterVersionFn: func(v string) error {
				stampInvoked = true

				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, "", logger)
		So(err, ShouldBeNil)
		So(parsed, ShouldBeTrue)
		So(stampInvoked, ShouldBeFalse)
	})
}
