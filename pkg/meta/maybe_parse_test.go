package meta_test

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/version"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// withReleaseTag temporarily overrides config.ReleaseTag/Commit so the
// tests can deterministically observe CurrentWriterVersion behavior even
// under `go test` (where both globals are normally empty).
func withReleaseTag(t *testing.T, tag, commit string) func() {
	t.Helper()

	prevTag := config.ReleaseTag
	prevCommit := config.Commit
	config.ReleaseTag = tag
	config.Commit = commit

	return func() {
		config.ReleaseTag = prevTag
		config.Commit = prevCommit
	}
}

func TestCurrentWriterVersion(t *testing.T) {
	Convey("CurrentWriterVersion prefers ReleaseTag", t, func() {
		defer withReleaseTag(t, "v2.3.4", "abc123")()
		So(version.CurrentWriterVersion(), ShouldEqual, "v2.3.4")
	})

	Convey("CurrentWriterVersion falls back to dev-<Commit>", t, func() {
		defer withReleaseTag(t, "", "abc123")()
		So(version.CurrentWriterVersion(), ShouldEqual, "dev-abc123")
	})

	Convey("CurrentWriterVersion returns empty when neither is set", t, func() {
		defer withReleaseTag(t, "", "")()
		So(version.CurrentWriterVersion(), ShouldEqual, "")
	})
}

func TestMaybeParseStorageGate(t *testing.T) {
	logger := log.NewTestLogger()
	emptyStore := storage.StoreController{DefaultStore: mocks.MockedImageStore{
		GetRepositoriesFn: func() ([]string, error) { return nil, nil },
	}}

	Convey("fastRestart=false always runs the full parse and stamps", t, func() {
		defer withReleaseTag(t, "v1", "")()

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

		err := meta.MaybeParseStorage(mock, emptyStore, false, logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true with matching stamp skips the parse", t, func() {
		defer withReleaseTag(t, "v1", "")()

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

		err := meta.MaybeParseStorage(mock, emptyStore, true, logger)
		So(err, ShouldBeNil)
	})

	Convey("fastRestart=true with mismatched stamp runs full parse and re-stamps", t, func() {
		defer withReleaseTag(t, "v2", "")()

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

		err := meta.MaybeParseStorage(mock, emptyStore, true, logger)
		So(err, ShouldBeNil)
		So(parsed, ShouldBeTrue)
		So(stamped, ShouldEqual, "v2")
	})

	Convey("fastRestart=true with empty stamp runs full parse and stamps", t, func() {
		defer withReleaseTag(t, "v1", "")()

		var stamped string

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn:  func() ([]string, error) { return nil, nil },
			GetWriterVersionFn: func() (string, error) { return "", nil },
			SetWriterVersionFn: func(v string) error {
				stamped = v
				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true falls back to full parse when GetWriterVersion errors", t, func() {
		defer withReleaseTag(t, "v1", "")()

		var stamped string

		mock := mocks.MetaDBMock{
			GetAllRepoNamesFn:  func() ([]string, error) { return nil, nil },
			GetWriterVersionFn: func() (string, error) { return "", errors.New("redis down") },
			SetWriterVersionFn: func(v string) error {
				stamped = v
				return nil
			},
		}

		err := meta.MaybeParseStorage(mock, emptyStore, true, logger)
		So(err, ShouldBeNil)
		So(stamped, ShouldEqual, "v1")
	})

	Convey("fastRestart=true with empty binary identity always parses and never stamps", t, func() {
		defer withReleaseTag(t, "", "")()

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

		err := meta.MaybeParseStorage(mock, emptyStore, true, logger)
		So(err, ShouldBeNil)
		So(parsed, ShouldBeTrue)
		So(stampInvoked, ShouldBeFalse)
	})
}
