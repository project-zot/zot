//go:build sync && scrub && metrics && search && ui_base
// +build sync,scrub,metrics,search,ui_base

package test_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/test"
)

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := test.CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir := t.TempDir()

		err := test.CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}

		err = test.CopyFiles(dir, "/etc/passwd")
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir does not have read permissions", t, func() {
		dir := t.TempDir()

		err := os.Chmod(dir, 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a subfolder that does not have read permissions", t, func() {
		dir := t.TempDir()

		sdir := "subdir"
		err := os.Mkdir(path.Join(dir, sdir), 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a file that does not have read permissions", t, func() {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := ioutil.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(filePath, 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
}

func TestGetOciLayoutDigests(t *testing.T) {
	dir := t.TempDir()

	Convey("image path is wrong", t, func() {
		So(func() { _, _, _ = test.GetOciLayoutDigests("inexistent-image") }, ShouldPanic)
	})

	Convey("no permissions when getting index", t, func() {
		err := test.CopyFiles("../../test/data/zot-test", path.Join(dir, "test-index"))
		if err != nil {
			panic(err)
		}

		err = os.Chmod(path.Join(dir, "test-index", "index.json"), 0o000)
		if err != nil {
			panic(err)
		}

		So(func() { _, _, _ = test.GetOciLayoutDigests(path.Join(dir, "test-index")) }, ShouldPanic)

		err = os.Chmod(path.Join(dir, "test-index", "index.json"), 0o755)
		if err != nil {
			panic(err)
		}
	})

	Convey("can't access manifest digest", t, func() {
		err := test.CopyFiles("../../test/data/zot-test", path.Join(dir, "test-manifest"))
		if err != nil {
			panic(err)
		}

		buf, err := ioutil.ReadFile(path.Join(dir, "test-manifest", "index.json"))
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		if err := json.Unmarshal(buf, &index); err != nil {
			panic(err)
		}

		err = os.Chmod(path.Join(dir, "test-manifest", "blobs/sha256", index.Manifests[0].Digest.Encoded()), 0o000)
		if err != nil {
			panic(err)
		}

		So(func() { _, _, _ = test.GetOciLayoutDigests(path.Join(dir, "test-manifest")) }, ShouldPanic)

		err = os.Chmod(path.Join(dir, "test-manifest", "blobs/sha256", index.Manifests[0].Digest.Encoded()), 0o755)
		if err != nil {
			panic(err)
		}
	})
}
