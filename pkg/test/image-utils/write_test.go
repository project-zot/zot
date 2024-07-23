package image_test

import (
	"errors"
	"io"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/storage"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("ErrTestError")

func TestWriteImageToFileSystem(t *testing.T) {
	Convey("WriteImageToFileSystem errors", t, func() {
		err := WriteImageToFileSystem(Image{}, "repo", "dig", storage.StoreController{
			DefaultStore: mocks.MockedImageStore{
				InitRepoFn: func(name string) error {
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
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
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
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
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
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte,
					) (godigest.Digest, godigest.Digest, error) {
						return "", "", ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)
	})
}
