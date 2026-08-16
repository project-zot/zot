package image_test

import (
	"context"
	"errors"
	"io"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var ErrTestError = errors.New("ErrTestError")

func TestWriteImageToFileSystem(t *testing.T) {
	Convey("WriteImageToFileSystem errors", t, func() {
		err := WriteImageToFileSystem(Image{}, "repo", "dig", storage.StoreController{
			DefaultStore: mocks.MockedImageStore{
				InitRepoFn: func(ctx context.Context, name string) error {
					return ErrTestError
				},
			},
		})
		So(err, ShouldNotBeNil)

		err = WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(ctx context.Context, repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		count := 0
		err = WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(ctx context.Context, repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						if count == 0 {
							count++

							return "", 0, nil
						}

						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		err = WriteImageToFileSystem(
			Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
						body []byte, extraTags []string,
					) (godigest.Digest, godigest.Digest, error) {
						return "", "", ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)
	})

	Convey("WriteImageToFileSystem waits for manifest visibility", t, func() {
		manifestReads := 0
		store := mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				manifestReads++
				if manifestReads == 1 {
					return nil, "", "", zerr.ErrManifestNotFound
				}

				return nil, "", "", nil
			},
		}

		err := WriteImageToFileSystem(Image{}, "repo", "tag", storage.StoreController{DefaultStore: store})
		So(err, ShouldBeNil)
		So(manifestReads, ShouldEqual, 2)
	})

	Convey("WriteImageToFileSystem returns non-transient manifest errors", t, func() {
		manifestReads := 0
		store := mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				manifestReads++

				return nil, "", "", ErrTestError
			},
		}

		err := WriteImageToFileSystem(Image{}, "repo", "tag", storage.StoreController{DefaultStore: store})
		So(err, ShouldEqual, ErrTestError)
		So(manifestReads, ShouldEqual, 1)
	})
}
