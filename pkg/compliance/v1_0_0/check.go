//nolint:dupl
package v1_0_0 //nolint:stylecheck,golint,revive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	//nolint:golint,stylecheck,revive
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/compliance"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func CheckWorkflows(t *testing.T, config *compliance.Config) {
	t.Helper()

	if config == nil || config.Address == "" || config.Port == "" {
		t.Fatal("insufficient config")
	}

	if config.OutputJSON {
		outputJSONEnter()

		defer outputJSONExit()
	}

	baseURL := "http://" + net.JoinHostPort(config.Address, config.Port)

	storageInfo := config.StorageInfo

	fmt.Println("------------------------------")
	fmt.Println("Checking for v1.0.0 compliance")
	fmt.Println("------------------------------")

	Convey("Make API calls to the controller", t, func(c C) {
		Convey("Check version", func() {
			_, _ = Print("\nCheck version")
			resp, err := resty.R().Get(baseURL + constants.RoutePrefix + "/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Get repository catalog", func() {
			_, _ = Print("\nGet repository catalog")
			resp, err := resty.R().Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, constants.DefaultMediaType)

			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/z/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/a/b/c/d/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			resp, err = resty.R().SetResult(&api.RepositoryList{}).Get(baseURL +
				constants.RoutePrefix + constants.ExtCatalogPrefix)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.String(), ShouldNotBeEmpty)
			result, ok := resp.Result().(*api.RepositoryList)
			So(ok, ShouldBeTrue)

			if !config.Compliance {
				// stricter check for zot ci/cd
				So(len(result.Repositories), ShouldBeGreaterThan, 0)
				So(result.Repositories[0], ShouldEqual, "a/b/c/d")
				So(result.Repositories[1], ShouldEqual, "z")
			}
		})

		Convey("Get images in a repository", func() {
			_, _ = Print("\nGet images in a repository")
			// non-existent repository should fail
			resp, err := resty.R().Get(baseURL + "/v2/repo1/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.String(), ShouldNotBeEmpty)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/repo1/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			resp, err = resty.R().Get(baseURL + "/v2/repo1/tags/list")
			So(err, ShouldBeNil)

			if !config.Compliance {
				// stricter check for zot ci/cd
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.String(), ShouldNotBeEmpty)
			}
		})

		Convey("Monolithic blob upload", func() {
			_, _ = Print("\nMonolithic blob upload")
			resp, err := resty.R().Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

			resp, err = resty.R().Get(baseURL + "/v2/repo2/tags/list")
			So(err, ShouldBeNil)

			if !config.Compliance {
				// stricter check for zot ci/cd
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.String(), ShouldNotBeEmpty)
			}

			// without a "?digest=<>" should fail
			content := []byte("this is a blob1")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			resp, err = resty.R().Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Monolithic blob upload with body", func() {
			_, _ = Print("\nMonolithic blob upload")
			// create content
			content := []byte("this is a blob2")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// setting invalid URL params should fail
			resp, err := resty.R().
				SetQueryParam("digest", digest.String()).
				SetQueryParam("from", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetBody(content).
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
			// setting a "?digest=<>" but without body should fail
			resp, err = resty.R().
				SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// set a "?digest=<>"
			resp, err = resty.R().
				SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetBody(content).
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)
			// blob reference should be accessible
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Empty blob upload", func() {
			_, _ = Print("\nEmpty blob upload")
			// empty blob digest (sha256 of empty string)
			emptyDigest := godigest.Canonical.FromBytes([]byte{})
			So(emptyDigest, ShouldNotBeNil)

			// Test POST with digest and Content-Length: 0 (empty body)
			resp, err := resty.R().
				SetQueryParam("digest", emptyDigest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Length", "0").
				SetBody([]byte{}).
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldEqual, emptyDigest.String())

			// Verify empty blob can be retrieved via GET
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(len(resp.Body()), ShouldEqual, 0)

			// Verify empty blob can be checked via HEAD
			resp, err = resty.R().Head(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldEqual, emptyDigest.String())

			// Test PUT with digest and Content-Length: 0 (empty body) via POST+PUT flow
			resp, err = resty.R().Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// PUT with empty body
			resp, err = resty.R().
				SetQueryParam("digest", emptyDigest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Length", "0").
				SetBody([]byte{}).
				Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc2 := test.Location(baseURL, resp)
			So(blobLoc2, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldEqual, emptyDigest.String())

			// Verify the blob uploaded via PUT can be retrieved
			resp, err = resty.R().Get(blobLoc2)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(len(resp.Body()), ShouldEqual, 0)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			_, _ = Print("\nMonolithic blob upload with multiple name components")
			resp, err := resty.R().Post(baseURL + "/v2/repo10/repo20/repo30/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

			resp, err = resty.R().Get(baseURL + "/v2/repo10/repo20/repo30/tags/list")
			So(err, ShouldBeNil)

			if !config.Compliance {
				// stricter check for zot ci/cd
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.String(), ShouldNotBeEmpty)
			}

			// without a "?digest=<>" should fail
			content := []byte("this is a blob3")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			resp, err = resty.R().Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Chunked blob upload", func() {
			_, _ = Print("\nChunked blob upload")
			resp, err := resty.R().Post(baseURL + "/v2/repo3/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer

			chunk1 := []byte("this is the first chunk1")
			nbytes, err := buf.Write(chunk1)
			So(nbytes, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// check progress
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk1")
			nbytes, err = buf.Write(chunk2)
			So(nbytes, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes())-1)
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)

			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			_, _ = Print("\nChunked blob upload with multiple name components")
			resp, err := resty.R().Post(baseURL + "/v2/repo40/repo50/repo60/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer

			chunk1 := []byte("this is the first chunk2")
			nbytes, err := buf.Write(chunk1)
			So(nbytes, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// check progress
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk2")
			nbytes, err = buf.Write(chunk2)
			So(nbytes, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes())-1)
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)

			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Create and delete uploads", func() {
			_, _ = Print("\nCreate and delete uploads")
			// create a upload
			resp, err := resty.R().Post(baseURL + "/v2/repo4/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			resp, err = resty.R().Delete(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
		})

		Convey("Create and delete blobs", func() {
			_, _ = Print("\nCreate and delete blobs")
			// create a upload
			resp, err := resty.R().Post(baseURL + "/v2/repo5/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob4")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			resp, err = resty.R().Delete(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Mount blobs", func() {
			_, _ = Print("\nMount blobs from another repository")
			// create a upload
			resp, err := resty.R().Post(baseURL + "/v2/repo6/blobs/uploads/?digest=\"abc\"&&from=\"xyz\"")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldBeIn, []int{http.StatusCreated, http.StatusAccepted, http.StatusMethodNotAllowed})
		})

		Convey("Blob delete after mount", func() {
			_, _ = Print("\nBlob delete after mount")
			content := []byte("this is a blob for mount test")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			// Upload blob to repo2
			resp, err := resty.R().Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLocRepo2 := test.Location(baseURL, resp)
			So(blobLocRepo2, ShouldNotBeEmpty)

			// Verify blob exists in repo2
			resp, err = resty.R().Head(blobLocRepo2)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// Mount blob from repo2 to repo1
			resp, err = resty.R().SetQueryParam("mount", digest.String()).
				SetQueryParam("from", "repo2").
				Post(baseURL + "/v2/repo1/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLocRepo1 := test.Location(baseURL, resp)
			So(blobLocRepo1, ShouldNotBeEmpty)

			// Verify blob exists in repo1
			resp, err = resty.R().Head(blobLocRepo1)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// Delete blob from repo2
			resp, err = resty.R().Delete(blobLocRepo2)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// Verify blob no longer exists in repo2 (should return 404)
			resp, err = resty.R().Head(blobLocRepo2)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			// Verify blob still exists in repo1 (should return 200)
			resp, err = resty.R().Head(blobLocRepo1)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Bad digest POST only", func() {
			_, _ = Print("\nBad digest POST only")
			content := []byte("this is a blob with bad digest")
			badDigest := "sha256:invalid_digest_format"

			// POST with invalid digest should return 400 Bad Request
			resp, err := resty.R().
				SetQueryParam("digest", badDigest).
				SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Length", strconv.Itoa(len(content))).
				SetBody(content).
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			// POST with mismatched digest should return 400 Bad Request
			correctDigest := godigest.FromBytes(content)
			So(correctDigest, ShouldNotBeNil)
			// Use a different digest that doesn't match the content
			wrongDigest := godigest.Canonical.FromBytes([]byte("different content"))
			So(wrongDigest, ShouldNotBeNil)

			resp, err = resty.R().
				SetQueryParam("digest", wrongDigest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Length", strconv.Itoa(len(content))).
				SetBody(content).
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("Chunked blob upload PUT without Content-Length", func() {
			_, _ = Print("\nChunked blob upload PUT without Content-Length")
			// Start chunked upload
			resp, err := resty.R().Post(baseURL + "/v2/repo3/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			chunk2 := []byte("this is the second chunk")
			buf.Write(chunk1)
			buf.Write(chunk2)
			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// Upload first chunk via PATCH
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// Upload second chunk via PATCH
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes())-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk2).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// Finish upload with PUT - all chunks already uploaded, so Content-Length can be missing
			// This tests Chunked upload PUT with missing Content-Length
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				// Note: Not setting Content-Length header - this should work per spec
				Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := test.Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldEqual, digest.String())

			// Verify blob can be retrieved
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldResemble, buf.Bytes())
		})

		Convey("Manifests", func() {
			_, _ = Print("\nManifests")
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + "/v2/repo7/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// since we are not specifying any prefix i.e provided in config while starting server,
			// so it should store repo7 to global root dir
			_, err = os.Stat(path.Join(storageInfo[0], "repo7"))
			So(err, ShouldBeNil)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

			content := []byte("this is a blob5")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

			// check a non-existent manifest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			img := image.CreateDefaultImage()
			digest = img.ManifestDescriptor.Digest

			repoName := "repo7"
			err = image.UploadImage(img, baseURL, repoName, "test:1.0")
			So(err, ShouldBeNil)

			err = image.UploadImage(img, baseURL, repoName, "test:1.0.1")
			So(err, ShouldBeNil)

			err = image.UploadImage(img, baseURL, repoName, "test:2.0")
			So(err, ShouldBeNil)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest by tag should pass
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			// delete manifest by digest (1.0 deleted but 1.0.1 has same reference)
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			// delete again should fail
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
		})

		// pagination
		Convey("Pagination", func() {
			_, _ = Print("\nPagination")

			img := image.CreateDefaultImage()

			for index := 0; index <= 4; index++ {
				repoName := "page0"
				err := image.UploadImage(
					img, baseURL, repoName, fmt.Sprintf("test:%d.0", index))
				So(err, ShouldBeNil)
			}

			resp, err := resty.R().Get(baseURL + "/v2/page0/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n= ")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=a")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=0&last=100")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=0&last=test:0.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=3")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			next := resp.Header().Get("Link")
			So(next, ShouldNotBeEmpty)

			nextURL := strings.Split(next, ";")[0]
			if strings.HasPrefix(nextURL, "<") || strings.HasPrefix(nextURL, "\"") {
				nextURL = nextURL[1:]
			}

			if strings.HasSuffix(nextURL, ">") || strings.HasSuffix(nextURL, "\"") {
				nextURL = nextURL[:len(nextURL)-1]
			}

			nextURL = baseURL + nextURL

			resp, err = resty.R().Get(nextURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			next = resp.Header().Get("Link")
			So(next, ShouldBeEmpty)
		})

		// this is an additional test for repository names (alphanumeric)
		Convey("Repository names", func() {
			_, _ = Print("\nRepository names")
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + "/v2/repotest/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			resp, err = resty.R().Post(baseURL + "/v2/repotest123/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		})

		Convey("Multiple Storage", func() {
			// test APIS on subpath routes, default storage already tested above
			// subpath route firsttest
			resp, err := resty.R().Post(baseURL + "/v2/firsttest/first/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			firstloc := test.Location(baseURL, resp)
			So(firstloc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(firstloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

			// if firsttest route is used as prefix in url that means repo should be stored in subpaths["firsttest"] rootdir
			_, err = os.Stat(path.Join(storageInfo[1], "firsttest/first"))
			So(err, ShouldBeNil)

			// subpath route secondtest
			resp, err = resty.R().Post(baseURL + "/v2/secondtest/second/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			secondloc := test.Location(baseURL, resp)
			So(secondloc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(secondloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

			// if secondtest route is used as prefix in url that means repo should be stored in subpaths["secondtest"] rootdir
			_, err = os.Stat(path.Join(storageInfo[2], "secondtest/second"))
			So(err, ShouldBeNil)

			content := []byte("this is a blob5")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			// first test
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(firstloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			firstblobLoc := resp.Header().Get("Location")
			So(firstblobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

			// second test
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(secondloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			secondblobLoc := resp.Header().Get("Location")
			So(secondblobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

			// check a non-existent manifest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/firsttest/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/secondtest/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			img := image.CreateDefaultImage()
			digest = img.ManifestDescriptor.Digest

			// subpath firsttest
			err = image.UploadImage(img, baseURL, "firsttest/first", "test:1.0")
			So(err, ShouldBeNil)

			// subpath secondtest
			err = image.UploadImage(img, baseURL, "secondtest/second", "test:1.0")
			So(err, ShouldBeNil)

			// subpath firsttest
			err = image.UploadImage(img, baseURL, "firsttest/first", "test:2.0")
			So(err, ShouldBeNil)

			// subpath secondtest
			err = image.UploadImage(img, baseURL, "secondtest/second", "test:2.0")
			So(err, ShouldBeNil)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)

			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			resp, err = resty.R().Delete(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().Delete(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			// delete again should fail
			resp, err = resty.R().Delete(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().Delete(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)

			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
		})
	})
}

//nolint:gochecknoglobals
var (
	old  *os.File
	r    *os.File
	w    *os.File
	outC chan string
)

func outputJSONEnter() {
	// this env var instructs goconvey to output results to JSON (stdout)
	os.Setenv("GOCONVEY_REPORTER", "json")

	// stdout capture copied from: https://stackoverflow.com/a/29339052
	old = os.Stdout
	// keep backup of the real stdout
	r, w, _ = os.Pipe()
	outC = make(chan string)
	os.Stdout = w

	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer

		_, err := io.Copy(&buf, r)
		if err != nil {
			panic(err)
		}

		outC <- buf.String()
	}()
}

func outputJSONExit() {
	// back to normal state
	w.Close()

	os.Stdout = old // restoring the real stdout

	out := <-outC

	// The output of JSON is combined with regular output, so we look for the
	// first occurrence of the "{" character and take everything after that
	rawJSON := "[{" + strings.Join(strings.Split(out, "{")[1:], "{")
	rawJSON = strings.Replace(rawJSON, reporting.OpenJson, "", 1)
	rawJSON = strings.Replace(rawJSON, reporting.CloseJson, "", 1)
	tmp := strings.Split(rawJSON, ",")
	rawJSON = strings.Join(tmp[0:len(tmp)-1], ",") + "]"

	rawJSONMinified := validateMinifyRawJSON(rawJSON)
	fmt.Println(rawJSONMinified)
}

func validateMinifyRawJSON(rawJSON string) string {
	var jsonData any

	err := json.Unmarshal([]byte(rawJSON), &jsonData)
	if err != nil {
		panic(err)
	}

	rawJSONBytesMinified, err := json.Marshal(jsonData)
	if err != nil {
		panic(err)
	}

	return string(rawJSONBytesMinified)
}
