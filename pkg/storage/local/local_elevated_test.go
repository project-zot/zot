//go:build needprivileges
// +build needprivileges

package local_test

import (
	"bytes"
	_ "crypto/sha256"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
)

func TestElevatedPrivilegesInvalidDedupe(t *testing.T) {
	Convey("Invalid dedupe scenarios", t, func() {
		dir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := local.NewImageStore(dir, true, storConstants.DefaultGCDelay, true, true, log, metrics, nil)

		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := strings.Split(digest.String(), ":")[1]
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// Create a file at the same place where FinishBlobUpload will create
		err = imgStore.InitRepo("dedupe2")
		So(err, ShouldBeNil)

		err = os.MkdirAll(path.Join(dir, "dedupe2", "blobs/sha256"), 0o755)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1), content, 0o755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)
		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		cmd := exec.Command("chattr", "+i", path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1)) // nolint: gosec
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest.String())
		So(err, ShouldNotBeNil)
		So(blob, ShouldEqual, buflen)

		cmd = exec.Command("chattr", "-i", path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1)) // nolint: gosec
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
	})
}
