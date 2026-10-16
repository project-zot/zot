package imagestore_test

// The restore walk refills dedupe placeholders, which only exist on remote storage. These
// tests run it over a real filesystem by giving the local driver a remote name, which is
// all newBlobLifecycle selects on.

import (
	"context"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// remoteNamedDriver is the local driver under a name that is not the local one, so the
// image store picks the remote lifecycle (zero-byte copies are placeholders) for it. Link
// writes an empty placeholder, as the remote drivers do, rather than a hardlink.
type remoteNamedDriver struct {
	storageTypes.Driver
}

func (d *remoteNamedDriver) Name() string { return "remote-test" }

func (d *remoteNamedDriver) Link(src, dest string) error {
	if src == dest {
		return nil
	}

	_, err := d.Driver.WriteFile(dest, []byte{})

	return err
}

func TestRestoreDedupedBlobsRemoteLifecycle(t *testing.T) {
	Convey("The restore walk refills placeholders from a surviving content copy", t, func() {
		newStore := func(dir string) storageTypes.ImageStore {
			log := zlog.NewTestLogger()
			cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)
			So(err, ShouldBeNil)

			return imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
				&remoteNamedDriver{Driver: local.New(true)}, cacheDriver, nil, nil)
		}

		content := []byte("blob-content-for-dedupe")
		digest := godigest.FromBytes(content)

		writeBlob := func(dir, repo string, body []byte) string {
			blobPath := path.Join(dir, repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)

			return blobPath
		}

		Convey("placeholder survives with no content source", func() {
			dir := t.TempDir()
			imgStore := newStore(dir)

			original := writeBlob(dir, "repo-original", content)
			placeholder := writeBlob(dir, "repo-placeholder", []byte{})
			So(os.Remove(original), ShouldBeNil)

			// the placeholder is still there and nothing holds the content, so this must
			// fail rather than leave it zero-size
			err := imgStore.RunDedupeForDigest(context.Background(), digest, false,
				[]string{original, placeholder})
			So(err, ShouldNotBeNil)
		})

		Convey("a deleted path does not stop the restore", func() {
			dir := t.TempDir()
			imgStore := newStore(dir)

			original := writeBlob(dir, "repo-original", content)
			placeholder := writeBlob(dir, "repo-placeholder", []byte{})
			deleted := writeBlob(dir, "repo-gone", content)
			So(os.Remove(deleted), ShouldBeNil)

			err := imgStore.RunDedupeForDigest(context.Background(), digest, false,
				[]string{deleted, original, placeholder})
			So(err, ShouldBeNil)

			// the surviving copy was still found as the content source, so the
			// placeholder got restored
			restored, err := os.ReadFile(placeholder)
			So(err, ShouldBeNil)
			So(restored, ShouldResemble, content)
		})
	})
}
