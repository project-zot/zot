//go:build extended
// +build extended

package api_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

var ErrUnexpectedError = errors.New("error: unexpected error")

type MockedImageStore struct {
	dirExistsFn            func(d string) bool
	rootDirFn              func() string
	initRepoFn             func(name string) error
	validateRepoFn         func(name string) (bool, error)
	getRepositoriesFn      func() ([]string, error)
	getImageTagsFn         func(repo string) ([]string, error)
	getImageManifestFn     func(repo string, reference string) ([]byte, string, string, error)
	putImageManifestFn     func(repo string, reference string, mediaType string, body []byte) (string, error)
	deleteImageManifestFn  func(repo string, reference string) error
	blobUploadPathFn       func(repo string, uuid string) string
	newBlobUploadFn        func(repo string) (string, error)
	getBlobUploadFn        func(repo string, uuid string) (int64, error)
	blobUploadInfoFn       func(repo string, uuid string) (int64, error)
	putBlobChunkStreamedFn func(repo string, uuid string, body io.Reader) (int64, error)
	putBlobChunkFn         func(repo string, uuid string, from int64, to int64, body io.Reader) (int64, error)
	finishBlobUploadFn     func(repo string, uuid string, body io.Reader, digest string) error
	fullBlobUploadFn       func(repo string, body io.Reader, digest string) (string, int64, error)
	dedupeBlobFn           func(src string, dstDigest digest.Digest, dst string) error
	deleteBlobUploadFn     func(repo string, uuid string) error
	blobPathFn             func(repo string, digest digest.Digest) string
	checkBlobFn            func(repo string, digest string) (bool, int64, error)
	getBlobFn              func(repo string, digest string, mediaType string) (io.Reader, int64, error)
	deleteBlobFn           func(repo string, digest string) error
	getIndexContentFn      func(repo string) ([]byte, error)
	getBlobContentFn       func(repo, digest string) ([]byte, error)
	getReferrersFn         func(repo, digest string, mediaType string) ([]artifactspec.Descriptor, error)
	urlForPathFn           func(path string) (string, error)
	runGCRepoFn            func(repo string)
}

func (is *MockedImageStore) Lock(t *time.Time) {
}

func (is *MockedImageStore) Unlock(t *time.Time) {
}

func (is *MockedImageStore) RUnlock(t *time.Time) {
}

func (is *MockedImageStore) RLock(t *time.Time) {
}

func (is *MockedImageStore) DirExists(d string) bool {
	if is != nil && is.dirExistsFn != nil {
		return is.dirExistsFn(d)
	}

	return true
}

func (is *MockedImageStore) RootDir() string {
	if is != nil && is.rootDirFn != nil {
		return is.rootDirFn()
	}

	return ""
}

func (is *MockedImageStore) InitRepo(name string) error {
	if is != nil && is.initRepoFn != nil {
		return is.initRepoFn(name)
	}

	return nil
}

func (is *MockedImageStore) ValidateRepo(name string) (bool, error) {
	if is != nil && is.validateRepoFn != nil {
		return is.validateRepoFn(name)
	}

	return true, nil
}

func (is *MockedImageStore) GetRepositories() ([]string, error) {
	if is != nil && is.getRepositoriesFn != nil {
		return is.getRepositoriesFn()
	}

	return []string{}, nil
}

func (is *MockedImageStore) GetImageManifest(repo string, reference string) ([]byte, string, string, error) {
	if is != nil && is.getImageManifestFn != nil {
		return is.getImageManifestFn(repo, reference)
	}

	return []byte{}, "", "", nil
}

func (is *MockedImageStore) PutImageManifest(
	repo string,
	reference string,
	mediaType string,
	body []byte,
) (string, error) {
	if is != nil && is.putImageManifestFn != nil {
		return is.putImageManifestFn(repo, reference, mediaType, body)
	}

	return "", nil
}

func (is *MockedImageStore) GetImageTags(name string) ([]string, error) {
	if is != nil && is.getImageTagsFn != nil {
		return is.getImageTagsFn(name)
	}

	return []string{}, nil
}

func (is *MockedImageStore) DeleteImageManifest(name string, reference string) error {
	if is != nil && is.deleteImageManifestFn != nil {
		return is.deleteImageManifestFn(name, reference)
	}

	return nil
}

func (is *MockedImageStore) NewBlobUpload(repo string) (string, error) {
	if is != nil && is.newBlobUploadFn != nil {
		return is.newBlobUploadFn(repo)
	}

	return "", nil
}

func (is *MockedImageStore) GetBlobUpload(repo string, uuid string) (int64, error) {
	if is != nil && is.getBlobUploadFn != nil {
		return is.getBlobUploadFn(repo, uuid)
	}

	return 0, nil
}

func (is *MockedImageStore) BlobUploadInfo(repo string, uuid string) (int64, error) {
	if is != nil && is.blobUploadInfoFn != nil {
		return is.blobUploadInfoFn(repo, uuid)
	}

	return 0, nil
}

func (is *MockedImageStore) BlobUploadPath(repo string, uuid string) string {
	if is != nil && is.blobUploadPathFn != nil {
		return is.blobUploadPathFn(repo, uuid)
	}

	return ""
}

func (is *MockedImageStore) PutBlobChunkStreamed(repo string, uuid string, body io.Reader) (int64, error) {
	if is != nil && is.putBlobChunkStreamedFn != nil {
		return is.putBlobChunkStreamedFn(repo, uuid, body)
	}

	return 0, nil
}

func (is *MockedImageStore) PutBlobChunk(
	repo string,
	uuid string,
	from int64,
	to int64,
	body io.Reader,
) (int64, error) {
	if is != nil && is.putBlobChunkFn != nil {
		return is.putBlobChunkFn(repo, uuid, from, to, body)
	}

	return 0, nil
}

func (is *MockedImageStore) FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error {
	if is != nil && is.finishBlobUploadFn != nil {
		return is.finishBlobUploadFn(repo, uuid, body, digest)
	}

	return nil
}

func (is *MockedImageStore) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
	if is != nil && is.fullBlobUploadFn != nil {
		return is.fullBlobUploadFn(repo, body, digest)
	}

	return "", 0, nil
}

func (is *MockedImageStore) DedupeBlob(src string, dstDigest digest.Digest, dst string) error {
	if is != nil && is.dedupeBlobFn != nil {
		return is.dedupeBlobFn(src, dstDigest, dst)
	}

	return nil
}

func (is *MockedImageStore) DeleteBlob(repo string, digest string) error {
	if is != nil && is.deleteBlobFn != nil {
		return is.deleteBlobFn(repo, digest)
	}

	return nil
}

func (is *MockedImageStore) BlobPath(repo string, digest digest.Digest) string {
	if is != nil && is.blobPathFn != nil {
		return is.blobPathFn(repo, digest)
	}

	return ""
}

func (is *MockedImageStore) CheckBlob(repo string, digest string) (bool, int64, error) {
	if is != nil && is.checkBlobFn != nil {
		return is.checkBlobFn(repo, digest)
	}

	return true, 0, nil
}

func (is *MockedImageStore) GetBlob(repo string, digest string, mediaType string) (io.Reader, int64, error) {
	if is != nil && is.getBlobFn != nil {
		return is.getBlobFn(repo, digest, mediaType)
	}

	return &io.LimitedReader{}, 0, nil
}

func (is *MockedImageStore) DeleteBlobUpload(repo string, digest string) error {
	if is != nil && is.deleteBlobUploadFn != nil {
		return is.deleteBlobUploadFn(repo, digest)
	}

	return nil
}

func (is *MockedImageStore) GetIndexContent(repo string) ([]byte, error) {
	if is != nil && is.getIndexContentFn != nil {
		return is.getIndexContentFn(repo)
	}

	return []byte{}, nil
}

func (is *MockedImageStore) GetBlobContent(repo string, digest string) ([]byte, error) {
	if is != nil && is.getBlobContentFn != nil {
		return is.getBlobContentFn(repo, digest)
	}

	return []byte{}, nil
}

func (is *MockedImageStore) GetReferrers(
	repo string,
	digest string,
	mediaType string,
) ([]artifactspec.Descriptor, error) {
	if is != nil && is.getReferrersFn != nil {
		return is.getReferrersFn(repo, digest, mediaType)
	}

	return []artifactspec.Descriptor{}, nil
}

func (is *MockedImageStore) URLForPath(path string) (string, error) {
	if is != nil && is.urlForPathFn != nil {
		return is.urlForPathFn(path)
	}

	return "", nil
}

func (is *MockedImageStore) RunGCRepo(repo string) {
	if is != nil && is.runGCRepoFn != nil {
		is.runGCRepoFn(repo)
	}
}

func TestRoutes(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.Commit = true

		err := test.CopyFiles("../../test/data", ctlr.Config.Storage.RootDirectory)
		if err != nil {
			panic(err)
		}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		rthdlr := api.NewRouteHandler(ctlr)

		// NOTE: the url or method itself doesn't matter below since we are calling the handlers directly,
		// so path routing is bypassed

		Convey("Get manifest", func() {
			// overwrite controller storage
			ctlr.StoreController.DefaultStore = &MockedImageStore{
				getImageManifestFn: func(repo string, reference string) ([]byte, string, string, error) {
					return []byte{}, "", "", zerr.ErrRepoBadVersion
				},
			}

			request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{
				"name":      "test",
				"reference": "b8b1231908844a55c251211c7a67ae3c809fb86a081a8eeb4a715e6d7d65625c",
			})
			response := httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp := response.Result()

			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("UpdateManifest ", func() {
			testUpdateManifest := func(urlVars map[string]string, ism *MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				str := []byte("test")
				request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewBuffer(str))
				request = mux.SetURLVars(request, urlVars)
				request.Header.Add("Content-Type", ispec.MediaTypeImageManifest)
				response := httptest.NewRecorder()

				rthdlr.UpdateManifest(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}
			// repo not found
			statusCode := testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&MockedImageStore{
					putImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
			// ErrManifestNotFound
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},

				&MockedImageStore{
					putImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", zerr.ErrManifestNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
			// ErrBadManifest
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&MockedImageStore{
					putImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", zerr.ErrBadManifest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)
			// ErrBlobNotFound
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&MockedImageStore{
					putImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", zerr.ErrBlobNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrRepoBadVersion
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&MockedImageStore{
					putImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", zerr.ErrRepoBadVersion
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteManifest", func() {
			testDeleteManifest := func(headers map[string]string, urlVars map[string]string, ism *MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.Background(), "DELETE", baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				for k, v := range headers {
					request.Header.Add(k, v)
				}
				response := httptest.NewRecorder()

				rthdlr.DeleteManifest(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrRepoNotFound
			statusCode := testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrManifestNotFound",
					"reference": "reference",
				},
				&MockedImageStore{
					deleteImageManifestFn: func(repo, reference string) error {
						return zerr.ErrRepoNotFound
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrManifestNotFound
			statusCode = testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrManifestNotFound",
					"reference": "reference",
				},
				&MockedImageStore{
					deleteImageManifestFn: func(repo, reference string) error {
						return zerr.ErrManifestNotFound
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUnexpectedError
			statusCode = testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrUnexpectedError",
					"reference": "reference",
				},
				&MockedImageStore{
					deleteImageManifestFn: func(repo, reference string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// ErrBadManifest
			statusCode = testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrBadManifest",
					"reference": "reference",
				},
				&MockedImageStore{
					deleteImageManifestFn: func(repo, reference string) error {
						return zerr.ErrBadManifest
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("DeleteBlob", func() {
			testDeleteBlob := func(urlVars map[string]string, ism *MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				response := httptest.NewRecorder()

				rthdlr.DeleteBlob(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrUnexpectedError
			statusCode := testDeleteBlob(
				map[string]string{
					"name":   "ErrUnexpectedError",
					"digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&MockedImageStore{
					deleteBlobFn: func(repo, digest string) error {
						return ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			statusCode = testDeleteBlob(
				map[string]string{
					"name":   "ErrBadBlobDigest",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&MockedImageStore{
					deleteBlobFn: func(repo, digest string) error {
						return zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrBlobNotFound
			statusCode = testDeleteBlob(
				map[string]string{
					"name":   "ErrBlobNotFound",
					"digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&MockedImageStore{
					deleteBlobFn: func(repo, digest string) error {
						return zerr.ErrBlobNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrRepoNotFound
			statusCode = testDeleteBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&MockedImageStore{
					deleteBlobFn: func(repo, digest string) error {
						return zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
		})

		// Check Blob
		Convey("CheckBlob", func() {
			testCheckBlob := func(urlVars map[string]string, ism *MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				response := httptest.NewRecorder()

				rthdlr.CheckBlob(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrBadBlobDigest
			statusCode := testCheckBlob(
				map[string]string{
					"name":   "ErrBadBlobDigest",
					"digest": "1234",
				},
				&MockedImageStore{
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrRepoNotFound
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "1234",
				},
				&MockedImageStore{
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrBlobNotFound
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "ErrBlobNotFound",
					"digest": "1234",
				},
				&MockedImageStore{
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, zerr.ErrBlobNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUnexpectedError
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "ErrUnexpectedError",
					"digest": "1234",
				},
				&MockedImageStore{
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// Error Check Blob is not ok
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "Check Blob Not Ok",
					"digest": "1234",
				},
				&MockedImageStore{
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return false, 0, nil
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("GetBlob", func() {
			testGetBlob := func(urlVars map[string]string, ism *MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				response := httptest.NewRecorder()

				rthdlr.GetBlob(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}
			// ErrRepoNotFound
			statusCode := testGetBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&MockedImageStore{
					getBlobFn: func(repo, digest, mediaType string) (io.Reader, int64, error) {
						return bytes.NewBuffer([]byte("")), 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrRepoNotFound
			statusCode = testGetBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&MockedImageStore{
					getBlobFn: func(repo, digest, mediaType string) (io.Reader, int64, error) {
						return bytes.NewBuffer([]byte("")), 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("CreateBlobUpload", func() {
			testCreateBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "POST", baseURL, nil)
				request = mux.SetURLVars(request,
					map[string]string{
						"name":  "test",
						"mount": "1234",
					})

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.CreateBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrRepoNotFound
			statusCode := testCreateBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				&MockedImageStore{
					newBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// a full blob upload if multiple digests are present
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
					{"digest", "5234"},
				},
				map[string]string{},
				&MockedImageStore{
					newBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// a full blob upload if content type is wrong
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
				},
				map[string]string{
					"Content-Type": "badContentType",
				},
				&MockedImageStore{
					newBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
					checkBlobFn: func(repo, digest string) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusUnsupportedMediaType)

			// digest prezent imgStore err
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
				},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&MockedImageStore{
					fullBlobUploadFn: func(repo string, body io.Reader, digest string) (string, int64, error) {
						return "session", 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// digest prezent bad length
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
				},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&MockedImageStore{
					fullBlobUploadFn: func(repo string, body io.Reader, digest string) (string, int64, error) {
						return "session", 20, nil
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// newBlobUpload not found
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&MockedImageStore{
					newBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// newBlobUpload unexpected error
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&MockedImageStore{
					newBlobUploadFn: func(repo string) (string, error) {
						return "", ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("GetBlobUpload", func() {
			testGetBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.GetBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrBadUploadRange
			statusCode := testGetBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&MockedImageStore{
					getBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrBadUploadRange
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrBadBlobDigest
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&MockedImageStore{
					getBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrRepoNotFound
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&MockedImageStore{
					getBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUploadNotFound
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&MockedImageStore{
					getBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrUploadNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUploadNotFound
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&MockedImageStore{
					getBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("PatchBlobUpload", func() {
			testPatchBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "PATCH", baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.PatchBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "abc",
					"Content-Range":  "abc",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-50",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 100, zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 100, zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 100, ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("UpdateBlobUpload", func() {
			testUpdateBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "PATCH", baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.UpdateBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "badRange",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, zerr.ErrBadUploadRange
					},
				},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					putBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrBadBlobDigest
					},
				},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrBadUploadRange
					},
				},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteBlobUpload", func() {
			testDeleteBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "PATCH", baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.DeleteBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testDeleteBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					deleteBlobUploadFn: func(repo, uuid string) error {
						return zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testDeleteBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					deleteBlobUploadFn: func(repo, uuid string) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testDeleteBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					deleteBlobUploadFn: func(repo, uuid string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("ListRepositories", func() {
			testListRepositoriesWithSubstores := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				ctlr.StoreController.SubStore = map[string]storage.ImageStore{
					"test": &MockedImageStore{
						getRepositoriesFn: func() ([]string, error) {
							return []string{}, ErrUnexpectedError
						},
					},
				}
				request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.ListRepositories(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			testListRepositories := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				ctlr.StoreController.SubStore = map[string]storage.ImageStore{}
				request, _ := http.NewRequestWithContext(context.TODO(), "PATCH", baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.ListRepositories(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}
			// with substores
			status := testListRepositoriesWithSubstores(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					getRepositoriesFn: func() ([]string, error) {
						return []string{}, ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)

			status = testListRepositories(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					getRepositoriesFn: func() ([]string, error) {
						return []string{}, ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("ListRepositories with Authz", func() {
			ctlr.StoreController.DefaultStore = &MockedImageStore{
				getRepositoriesFn: func() ([]string, error) {
					return []string{"repo"}, nil
				},
			}
			ctlr.StoreController.SubStore = map[string]storage.ImageStore{
				"test1": &MockedImageStore{
					getRepositoriesFn: func() ([]string, error) {
						return []string{"repo1"}, nil
					},
				},
				"test2": &MockedImageStore{
					getRepositoriesFn: func() ([]string, error) {
						return []string{"repo2"}, nil
					},
				},
			}

			// make the user an admin
			// acCtx := api.NewAccessControlContext(map[string]bool{}, true)
			// ctx := context.WithValue(context.Background(), "ctx", acCtx)
			ctx := context.Background()
			request, _ := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{
				"name":       "repo",
				"session_id": "test",
			})
			response := httptest.NewRecorder()

			rthdlr.ListRepositories(response, request)

			resp := response.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})

		Convey("Helper functions", func() {
			testUpdateBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), "PATCH", baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.UpdateBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "a-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "20-a",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "20-1",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&MockedImageStore{
					finishBlobUploadFn: func(repo, uuid string, body io.Reader, digest string) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)
		})
	})
}
