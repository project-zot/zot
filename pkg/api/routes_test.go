// nolint (dupl)
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	DefaultContentType = "application/json; charset=utf-8"
	BaseURL            = "http://127.0.0.1:8080"
)

func TestAPI(t *testing.T) {
	Convey("Make API calls to the controller", t, func(c C) {
		Convey("check version", func() {
			resp, err := resty.R().Get(BaseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			resp, err := resty.R().Get(BaseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, DefaultContentType)
			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			resp, err = resty.R().Post(BaseURL + "/v2/z/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			resp, err = resty.R().Post(BaseURL + "/v2/a/b/c/d/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().SetResult(&api.RepositoryList{}).Get(BaseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			r := resp.Result().(*api.RepositoryList)
			So(r.Repositories[0], ShouldEqual, "a/b/c/d")
			So(r.Repositories[1], ShouldEqual, "z")
		})

		Convey("Get images in a repository", func() {
			// non-existent repository should fail
			resp, err := resty.R().Get(BaseURL + "/v2/repo/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			// after newly created upload should succeed
			resp, err = resty.R().Post(BaseURL + "/v2/repo/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().Get(BaseURL + "/v2/repo/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
		})

		Convey("Monolithic blob upload", func() {
			resp, err := resty.R().Post(BaseURL + "/v2/repo/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(BaseURL + "/v2/repo/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(BaseURL + blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			resp, err := resty.R().Post(BaseURL + "/v2/repo1/repo2/repo3/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(BaseURL + "/v2/repo1/repo2/repo3/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)

			// without a "?digest=<>" should fail
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(BaseURL + blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			resp, err := resty.R().Post(BaseURL + "/v2/repo/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes()))
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(BaseURL + blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			resp, err := resty.R().Post(BaseURL + "/v2/repo4/repo5/repo6/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1))
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes()))
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(BaseURL + blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			// create a upload
			resp, err := resty.R().Post(BaseURL + "/v2/repo/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			resp, err = resty.R().Delete(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete blobs", func() {
			// create a upload
			resp, err := resty.R().Post(BaseURL + "/v2/repo/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			resp, err = resty.R().Delete(BaseURL + blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Manifests", func() {
			// create a blob/layer
			resp, err := resty.R().Post(BaseURL + "/v2/repo/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := resp.Header().Get("Location")
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(BaseURL + loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// create a manifest
			m := ispec.Manifest{Layers: []ispec.Descriptor{{Digest: digest}}}
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(BaseURL + "/v2/repo/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = resty.R().Head(BaseURL + "/v2/repo/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(BaseURL + "/v2/repo/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(BaseURL + "/v2/repo/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(BaseURL + "/v2/repo/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest
			resp, err = resty.R().Delete(BaseURL + "/v2/repo/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			// delete again should fail
			resp, err = resty.R().Delete(BaseURL + "/v2/repo/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			resp, err = resty.R().Head(BaseURL + "/v2/repo/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(BaseURL + "/v2/repo/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(BaseURL + "/v2/repo/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(BaseURL + "/v2/repo/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
		})
	})
}

func TestMain(m *testing.M) {
	config := api.NewConfig()
	c := api.NewController(config)
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}
	//defer os.RemoveAll(dir)
	c.Config.Storage.RootDirectory = dir
	go func() {
		// this blocks
		if err := c.Run(); err != nil {
			return
		}
	}()
	for {
		// poll until ready
		resp, _ := resty.R().Get(BaseURL)
		if resp.StatusCode() == 404 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	status := m.Run()
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
	os.Exit(status)
}
