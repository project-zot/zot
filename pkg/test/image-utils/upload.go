package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"

	tcommon "zotregistry.dev/zot/pkg/test/common"
	"zotregistry.dev/zot/pkg/test/inject"
)

var (
	ErrPostBlob = errors.New("can't post blob")
	ErrPutBlob  = errors.New("can't put blob")
	ErrPutIndex = errors.New("can't put index")
)

func UploadImage(img Image, baseURL, repo, ref string) error {
	for _, blob := range img.Layers {
		resp, err := resty.R().Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusAccepted {
			return ErrPostBlob
		}

		loc := resp.Header().Get("Location")

		digest := godigest.FromBytes(blob).String()

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
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

	cdigest := godigest.FromBytes(cblob)

	if img.Manifest.Config.MediaType == ispec.MediaTypeEmptyJSON ||
		img.Manifest.Config.Digest == ispec.DescriptorEmptyJSON.Digest {
		cblob = ispec.DescriptorEmptyJSON.Data
		cdigest = ispec.DescriptorEmptyJSON.Digest
	}

	resp, err := resty.R().
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	loc := tcommon.Location(baseURL, resp)

	// uploading blob should get 201
	resp, err = resty.R().
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
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

	resp, err = resty.R().
		SetHeader("Content-type", ispec.MediaTypeImageManifest).
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated {
		return ErrPutBlob
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated {
		return ErrPutBlob
	}

	return err
}

func UploadImageWithBasicAuth(img Image, baseURL, repo, ref, user, password string) error {
	for _, blob := range img.Layers {
		resp, err := resty.R().
			SetBasicAuth(user, password).
			Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusAccepted {
			return ErrPostBlob
		}

		loc := resp.Header().Get("Location")

		digest := godigest.FromBytes(blob).String()

		resp, err = resty.R().
			SetBasicAuth(user, password).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
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
	// upload config
	cblob, err := json.Marshal(img.Config)
	if err = inject.Error(err); err != nil {
		return err
	}

	cdigest := godigest.FromBytes(cblob)

	if img.Manifest.Config.MediaType == ispec.MediaTypeEmptyJSON {
		cblob = ispec.DescriptorEmptyJSON.Data
		cdigest = ispec.DescriptorEmptyJSON.Digest
	}

	resp, err := resty.R().
		SetBasicAuth(user, password).
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	loc := tcommon.Location(baseURL, resp)

	// uploading blob should get 201
	resp, err = resty.R().
		SetBasicAuth(user, password).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
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

	// put manifest
	manifestBlob, err := json.Marshal(img.Manifest)
	if err = inject.Error(err); err != nil {
		return err
	}

	_, err = resty.R().
		SetBasicAuth(user, password).
		SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	return err
}

func UploadMultiarchImage(multiImage MultiarchImage, baseURL string, repo, ref string) error {
	for _, image := range multiImage.Images {
		err := UploadImage(image, baseURL, repo, image.DigestStr())
		if err != nil {
			return err
		}
	}

	// put manifest
	indexBlob := multiImage.IndexDescriptor.Data

	if len(indexBlob) == 0 {
		var err error

		indexBlob, err = json.Marshal(multiImage.Index)
		if err = inject.Error(err); err != nil {
			return err
		}
	}

	resp, err := resty.R().
		SetHeader("Content-type", ispec.MediaTypeImageIndex).
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
