package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"

	tcommon "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/inject"
)

var (
	ErrPostBlob               = errors.New("can't post blob")
	ErrPutBlob                = errors.New("can't put blob")
	ErrPutIndex               = errors.New("can't put index")
	ErrInvalidRefForExtraTags = errors.New("ref must be empty or a valid digest when using extra tags")
)

// UploadOption configures an upload request.
type UploadOption func(*uploadConfig)

type uploadConfig struct {
	user      string
	password  string
	extraTags []string
}

func (c *uploadConfig) withAuth(req *resty.Request) *resty.Request {
	if c.user != "" {
		return req.SetBasicAuth(c.user, c.password)
	}

	return req
}

func (c *uploadConfig) withTagParams(req *resty.Request) *resty.Request {
	tagParams := make(url.Values)

	for _, t := range c.extraTags {
		tagParams.Add("tag", t)
	}

	return req.SetMultiValueQueryParams(tagParams)
}

// WithBasicAuth sets HTTP basic authentication credentials for the upload.
func WithBasicAuth(user, password string) UploadOption {
	return func(c *uploadConfig) {
		c.user = user
		c.password = password
	}
}

// WithExtraTags attaches additional tags to the manifest via the digest-push
// API (PUT /v2/{repo}/manifests/{digest}?tag=...).
func WithExtraTags(tags ...string) UploadOption {
	return func(c *uploadConfig) {
		c.extraTags = append(c.extraTags, tags...)
	}
}

func UploadImage(img Image, baseURL, repo, ref string) error {
	return UploadImageWithOpts(img, baseURL, repo, ref)
}

func UploadImageWithBasicAuth(img Image, baseURL, repo, ref, user, password string) error {
	return UploadImageWithOpts(img, baseURL, repo, ref, WithBasicAuth(user, password))
}

func UploadImageWithOpts(img Image, baseURL, repo, ref string, opts ...UploadOption) error {
	cfg := &uploadConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if ref == "" {
		ref = img.DigestStr()
	} else if len(cfg.extraTags) > 0 {
		if _, err := godigest.Parse(ref); err != nil {
			return ErrInvalidRefForExtraTags
		}
	}

	digestAlgorithm := img.digestAlgorithm

	if digestAlgorithm == "" {
		digestAlgorithm = godigest.Canonical
	}

	for _, blob := range img.Layers {
		resp, err := cfg.withAuth(resty.R()).
			Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusAccepted {
			return ErrPostBlob
		}

		loc := resp.Header().Get("Location")

		digest := digestAlgorithm.FromBytes(blob).String()

		resp, err = cfg.withAuth(resty.R()).
			SetHeader("Content-Length", strconv.Itoa(len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusCreated {
			return ErrPutBlob
		}
	}

	var err error

	cblob := img.ConfigDescriptor.Data

	// we'll remove this check once we make the full transition to the new way of generating test images
	if len(cblob) == 0 {
		cblob, err = json.Marshal(img.Config)
		if err = inject.Error(err); err != nil {
			return err
		}
	}

	cdigest := digestAlgorithm.FromBytes(cblob)

	if img.Manifest.Config.MediaType == ispec.MediaTypeEmptyJSON ||
		img.Manifest.Config.Digest == ispec.DescriptorEmptyJSON.Digest {
		cblob = ispec.DescriptorEmptyJSON.Data
		cdigest = ispec.DescriptorEmptyJSON.Digest
	}

	resp, err := cfg.withAuth(resty.R()).
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	loc := tcommon.Location(baseURL, resp)

	// uploading blob should get 201
	resp, err = cfg.withAuth(resty.R()).
		SetHeader("Content-Length", strconv.Itoa(len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	manifestBlob := img.ManifestDescriptor.Data

	// we'll remove this check once we make the full transition to the new way of generating test images
	if len(manifestBlob) == 0 {
		manifestBlob, err = json.Marshal(img.Manifest)
		if err = inject.Error(err); err != nil {
			return err
		}
	}

	// Use the media type from ManifestDescriptor, or fall back to Manifest.MediaType, or default to OCI
	mediaType := img.ManifestDescriptor.MediaType

	if mediaType == "" {
		mediaType = img.Manifest.MediaType
	}

	if mediaType == "" {
		mediaType = ispec.MediaTypeImageManifest
	}

	resp, err = cfg.withTagParams(cfg.withAuth(resty.R())).
		SetHeader("Content-type", mediaType).
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated {
		return ErrPutBlob
	}

	return err
}

func UploadMultiarchImage(multiImage MultiarchImage, baseURL string, repo, ref string) error {
	return UploadMultiarchImageWithOpts(multiImage, baseURL, repo, ref)
}

func UploadMultiarchImageWithOpts(multiImage MultiarchImage, baseURL string, repo, ref string,
	opts ...UploadOption,
) error {
	cfg := &uploadConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if ref == "" {
		ref = multiImage.DigestStr()
	} else if len(cfg.extraTags) > 0 {
		if _, err := godigest.Parse(ref); err != nil {
			return ErrInvalidRefForExtraTags
		}
	}

	for _, image := range multiImage.Images {
		var perImageOpts []UploadOption
		if cfg.user != "" {
			perImageOpts = append(perImageOpts, WithBasicAuth(cfg.user, cfg.password))
		}

		err := UploadImageWithOpts(image, baseURL, repo, image.DigestStr(), perImageOpts...)
		if err != nil {
			return err
		}
	}

	indexBlob := multiImage.IndexDescriptor.Data

	if len(indexBlob) == 0 {
		var err error

		indexBlob, err = json.Marshal(multiImage.Index)
		if err = inject.Error(err); err != nil {
			return err
		}
	}

	// Use the media type from IndexDescriptor, or fall back to Index.MediaType, or default to OCI
	mediaType := multiImage.IndexDescriptor.MediaType

	if mediaType == "" {
		mediaType = multiImage.Index.MediaType
	}

	if mediaType == "" {
		mediaType = ispec.MediaTypeImageIndex
	}

	resp, err := cfg.withTagParams(cfg.withAuth(resty.R())).
		SetHeader("Content-type", mediaType).
		SetBody(indexBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	if resp.StatusCode() != http.StatusCreated {
		return ErrPutIndex
	}

	return err
}

func DeleteImage(repo, reference, baseURL string) (int, error) {
	resp, err := resty.R().Delete(
		fmt.Sprintf(baseURL+"/v2/%s/manifests/%s", repo, reference),
	)
	if err != nil {
		return -1, err
	}

	return resp.StatusCode(), err
}
