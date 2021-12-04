// nolint: dupl
package v1_0_0 // nolint:stylecheck,golint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey" // nolint:golint,stylecheck
	"github.com/smartystreets/goconvey/convey/reporting"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/compliance"
	. "zotregistry.io/zot/test" // nolint:golint,stylecheck
)

func CheckWorkflows(t *testing.T, config *compliance.Config) {
	if config == nil || config.Address == "" || config.Port == "" {
		panic("insufficient config")
	}

	if config.OutputJSON {
		outputJSONEnter()

		defer outputJSONExit()
	}

	baseURL := fmt.Sprintf("http://%s:%s", config.Address, config.Port)

	storageInfo := config.StorageInfo

	fmt.Println("------------------------------")
	fmt.Println("Checking for v1.0.0 compliance")
	fmt.Println("------------------------------")

	Convey("Make API calls to the controller", t, func(c C) {
		Convey("Check version", func() {
			Print("\nCheck version")
			resp, err := resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Get repository catalog", func() {
			Print("\nGet repository catalog")
			resp, err := resty.R().Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldEqual, api.DefaultMediaType)
			var repoList api.RepositoryList
			err = json.Unmarshal(resp.Body(), &repoList)
			So(err, ShouldBeNil)
			So(len(repoList.Repositories), ShouldEqual, 0)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/z/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/a/b/c/d/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().SetResult(&api.RepositoryList{}).Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.String(), ShouldNotBeEmpty)
			r := resp.Result().(*api.RepositoryList)
			if !config.Compliance {
				// stricter check for zot ci/cd
				So(len(r.Repositories), ShouldBeGreaterThan, 0)
				So(r.Repositories[0], ShouldEqual, "a/b/c/d")
				So(r.Repositories[1], ShouldEqual, "z")
			}
		})

		Convey("Get images in a repository", func() {
			Print("\nGet images in a repository")
			// non-existent repository should fail
			resp, err := resty.R().Get(baseURL + "/v2/repo1/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.String(), ShouldNotBeEmpty)

			// after newly created upload should succeed
			resp, err = resty.R().Post(baseURL + "/v2/repo1/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().Get(baseURL + "/v2/repo1/tags/list")
			So(err, ShouldBeNil)
			if !config.Compliance {
				// stricter check for zot ci/cd
				So(resp.StatusCode(), ShouldEqual, 200)
				So(resp.String(), ShouldNotBeEmpty)
			}
		})

		Convey("Monolithic blob upload", func() {
			Print("\nMonolithic blob upload")
			resp, err := resty.R().Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(baseURL + "/v2/repo2/tags/list")
			So(err, ShouldBeNil)
			if !config.Compliance {
				// stricter check for zot ci/cd
				So(resp.StatusCode(), ShouldEqual, 200)
				So(resp.String(), ShouldNotBeEmpty)
			}

			// without a "?digest=<>" should fail
			content := []byte("this is a blob1")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with body", func() {
			Print("\nMonolithic blob upload")
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
			So(resp.StatusCode(), ShouldEqual, 405)
			// setting a "?digest=<>" but without body should fail
			resp, err = resty.R().
				SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// set a "?digest=<>"
			resp, err = resty.R().
				SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetBody(content).
				Post(baseURL + "/v2/repo2/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)
			// blob reference should be accessible
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Monolithic blob upload with multiple name components", func() {
			Print("\nMonolithic blob upload with multiple name components")
			resp, err := resty.R().Post(baseURL + "/v2/repo10/repo20/repo30/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			resp, err = resty.R().Get(baseURL + "/v2/repo10/repo20/repo30/tags/list")
			So(err, ShouldBeNil)
			if !config.Compliance {
				// stricter check for zot ci/cd
				So(resp.StatusCode(), ShouldEqual, 200)
				So(resp.String(), ShouldNotBeEmpty)
			}

			// without a "?digest=<>" should fail
			content := []byte("this is a blob3")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without the Content-Length should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// without any data to send, should fail
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload", func() {
			Print("\nChunked blob upload")
			resp, err := resty.R().Post(baseURL + "/v2/repo3/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk1")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 416)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk1")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes())-1)
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := Location(baseURL, resp)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Chunked blob upload with multiple name components", func() {
			Print("\nChunked blob upload with multiple name components")
			resp, err := resty.R().Post(baseURL + "/v2/repo40/repo50/repo60/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			var buf bytes.Buffer
			chunk1 := []byte("this is the first chunk2")
			n, err := buf.Write(chunk1)
			So(n, ShouldEqual, len(chunk1))
			So(err, ShouldBeNil)

			// write first chunk
			contentRange := fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// check progress
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			r := resp.Header().Get("Range")
			So(r, ShouldNotBeEmpty)
			So(r, ShouldEqual, "bytes="+contentRange)

			// write same chunk should fail
			contentRange = fmt.Sprintf("%d-%d", 0, len(chunk1)-1)
			resp, err = resty.R().SetHeader("Content-Type", "application/octet-stream").
				SetHeader("Content-Range", contentRange).SetBody(chunk1).Patch(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 416)
			So(resp.String(), ShouldNotBeEmpty)

			chunk2 := []byte("this is the second chunk2")
			n, err = buf.Write(chunk2)
			So(n, ShouldEqual, len(chunk2))
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(buf.Bytes())
			So(digest, ShouldNotBeNil)

			// write final chunk
			contentRange = fmt.Sprintf("%d-%d", len(chunk1), len(buf.Bytes())-1)
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Range", contentRange).
				SetHeader("Content-Type", "application/octet-stream").SetBody(chunk2).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := Location(baseURL, resp)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)
			// upload reference should now be removed
			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// blob reference should be accessible
			resp, err = resty.R().Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Create and delete uploads", func() {
			Print("\nCreate and delete uploads")
			// create a upload
			resp, err := resty.R().Post(baseURL + "/v2/repo4/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// delete this upload
			resp, err = resty.R().Delete(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
		})

		Convey("Create and delete blobs", func() {
			Print("\nCreate and delete blobs")
			// create a upload
			resp, err := resty.R().Post(baseURL + "/v2/repo5/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			content := []byte("this is a blob4")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := Location(baseURL, resp)
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// delete this blob
			resp, err = resty.R().Delete(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		})

		Convey("Mount blobs", func() {
			Print("\nMount blobs from another repository")
			// create a upload
			resp, err := resty.R().Post(baseURL + "/v2/repo6/blobs/uploads/?digest=\"abc\"&&from=\"xyz\"")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldBeIn, []int{201, 202, 405})
		})

		Convey("Manifests", func() {
			Print("\nManifests")
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + "/v2/repo7/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			loc := Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// since we are not specifying any prefix i.e provided in config while starting server,
			// so it should store repo7 to global root dir
			_, err = os.Stat(path.Join(storageInfo[0], "repo7"))
			So(err, ShouldBeNil)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)
			content := []byte("this is a blob5")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// check a non-existent manifest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// create a manifest
			m := ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: digest,
					Size:   int64(len(content)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}
			m.SchemaVersion = 2
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repo7/manifests/test:1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d = resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			content = []byte("this is a blob5")
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// create a manifest with same blob but a different tag
			m = ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: digest,
					Size:   int64(len(content)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}
			m.SchemaVersion = 2
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d = resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest by tag should pass
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			// delete manifest by digest (1.0 deleted but 1.0.1 has same reference)
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			// delete again should fail
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
		})

		// pagination
		Convey("Pagination", func() {
			Print("\nPagination")

			for i := 0; i <= 4; i++ {
				// create a blob/layer
				resp, err := resty.R().Post(baseURL + "/v2/page0/blobs/uploads/")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 202)
				loc := Location(baseURL, resp)
				So(loc, ShouldNotBeEmpty)

				resp, err = resty.R().Get(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 204)
				content := []byte("this is a blob7")
				digest := godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				// monolithic blob upload: success
				resp, err = resty.R().SetQueryParam("digest", digest.String()).
					SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 201)
				blobLoc := resp.Header().Get("Location")
				So(blobLoc, ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
				So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

				// create a manifest
				m := ispec.Manifest{
					Config: ispec.Descriptor{
						Digest: digest,
						Size:   int64(len(content)),
					},
					Layers: []ispec.Descriptor{
						{
							MediaType: "application/vnd.oci.image.layer.v1.tar",
							Digest:    digest,
							Size:      int64(len(content)),
						},
					},
				}
				m.SchemaVersion = 2
				content, err = json.Marshal(m)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
					SetBody(content).Put(baseURL + fmt.Sprintf("/v2/page0/manifests/test:%d.0", i))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 201)
				d := resp.Header().Get(api.DistContentDigestKey)
				So(d, ShouldNotBeEmpty)
				So(d, ShouldEqual, digest.String())
			}

			resp, err := resty.R().Get(baseURL + "/v2/page0/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			resp, err = resty.R().Get(baseURL + "/v2/page0/tags/list?n=3")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			next := resp.Header().Get("Link")
			So(next, ShouldNotBeEmpty)

			u := baseURL + strings.Split(next, ";")[0]
			resp, err = resty.R().Get(u)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			next = resp.Header().Get("Link")
			So(next, ShouldBeEmpty)
		})

		// this is an additional test for repository names (alphanumeric)
		Convey("Repository names", func() {
			Print("\nRepository names")
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + "/v2/repotest/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			resp, err = resty.R().Post(baseURL + "/v2/repotest123/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
		})

		Convey("Multiple Storage", func() {
			// test APIS on subpath routes, default storage already tested above
			// subpath route firsttest
			resp, err := resty.R().Post(baseURL + "/v2/firsttest/first/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			firstloc := Location(baseURL, resp)
			So(firstloc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(firstloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

			// if firsttest route is used as prefix in url that means repo should be stored in subpaths["firsttest"] rootdir
			_, err = os.Stat(path.Join(storageInfo[1], "firsttest/first"))
			So(err, ShouldBeNil)

			// subpath route secondtest
			resp, err = resty.R().Post(baseURL + "/v2/secondtest/second/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)
			secondloc := Location(baseURL, resp)
			So(secondloc, ShouldNotBeEmpty)

			resp, err = resty.R().Get(secondloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 204)

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
			So(resp.StatusCode(), ShouldEqual, 201)
			firstblobLoc := resp.Header().Get("Location")
			So(firstblobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// second test
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(secondloc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			secondblobLoc := resp.Header().Get("Location")
			So(secondblobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

			// check a non-existent manifest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/firsttest/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/secondtest/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// create a manifest
			m := ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: digest,
					Size:   int64(len(content)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}
			m.SchemaVersion = 2
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// subpath firsttest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d := resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// subpath secondtest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d = resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			content = []byte("this is a blob5")
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// create a manifest with same blob but a different tag
			m = ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: digest,
					Size:   int64(len(content)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}
			m.SchemaVersion = 2
			content, err = json.Marshal(m)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			// subpath firsttest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/firsttest/first/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d = resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// subpath secondtest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/secondtest/second/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 201)
			d = resp.Header().Get(api.DistContentDigestKey)
			So(d, ShouldNotBeEmpty)
			So(d, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)
			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			resp, err = resty.R().Delete(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 202)

			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().Delete(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// delete again should fail
			resp, err = resty.R().Delete(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().Delete(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)

			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/firsttest/first/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)

			resp, err = resty.R().Head(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			resp, err = resty.R().Get(baseURL + "/v2/secondtest/second/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
			So(resp.Body(), ShouldNotBeEmpty)
		})
	})
}

// nolint: gochecknoglobals
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
	var j interface{}

	err := json.Unmarshal([]byte(rawJSON), &j)
	if err != nil {
		panic(err)
	}

	rawJSONBytesMinified, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}

	return string(rawJSONBytesMinified)
}
