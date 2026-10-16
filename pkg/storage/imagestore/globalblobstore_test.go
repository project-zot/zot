package imagestore_test

import (
	"os"
	"path"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// The global blobstore lives next to the repositories under the store root, but it is never
// one: no walk may list it as a repository or return its blobs as a repository's.
func TestWalksSkipGlobalBlobstore(t *testing.T) {
	Convey("Repository and digest walks never treat the global blobstore as a repository", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		imgStore := imagestore.NewImageStore(dir, dir, false, true, log, monitoring.NewNopMetricServer(), nil,
			local.New(true), nil, nil, nil)

		img := image.CreateRandomImage()
		So(image.WriteImageToFileSystem(img, "repo", "tag", storage.StoreController{DefaultStore: imgStore}),
			ShouldBeNil)

		digest := godigest.FromBytes(img.Layers[0])

		// make the blobstore look as much like a repository as possible
		blobstore := path.Join(dir, storageConstants.GlobalBlobsRepo)
		blobPath := path.Join(blobstore, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
		So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(blobPath, img.Layers[0], storageConstants.DefaultFilePerms), ShouldBeNil)

		for _, name := range []string{ispec.ImageLayoutFile, ispec.ImageIndexFile} {
			content, err := os.ReadFile(path.Join(dir, "repo", name))
			So(err, ShouldBeNil)
			//nolint:gosec // test path is tempdir-scoped
			So(os.WriteFile(path.Join(blobstore, name), content, storageConstants.DefaultFilePerms), ShouldBeNil)
		}

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldResemble, []string{"repo"})

		page, _, err := imgStore.GetNextRepositories("", 100, func(string) (bool, error) { return true, nil })
		So(err, ShouldBeNil)
		So(page, ShouldResemble, []string{"repo"})

		processed := map[string]struct{}{}

		for {
			repo, err := imgStore.GetNextRepository(processed)
			So(err, ShouldBeNil)

			if repo == "" {
				break
			}

			So(repo, ShouldNotEqual, storageConstants.GlobalBlobsRepo)

			processed[repo] = struct{}{}
		}

		So(processed, ShouldContainKey, "repo")

		var lastDigests []godigest.Digest

		for {
			next, blobPaths, err := imgStore.GetNextDigestWithBlobPaths(repos, lastDigests)
			So(err, ShouldBeNil)

			if next == "" {
				break
			}

			for _, blobPath := range blobPaths {
				So(strings.Contains(blobPath, storageConstants.GlobalBlobsRepo), ShouldBeFalse)
			}

			lastDigests = append(lastDigests, next)
		}

		So(lastDigests, ShouldContain, digest)
	})
}
