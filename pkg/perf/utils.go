package perf

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"
)

func PushImage(imagePath string, username string, passphrase string,
	baseURL string, repo string, imageName string) error {
	blobList := make([]string, 0)

	buf, err := ioutil.ReadFile(path.Join(imagePath, "index.json"))

	if err != nil {
		return err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		return err
	}

	for _, m := range index.Manifests {
		digest := m.Digest
		blobList = append(blobList, digest.Encoded())
		p := path.Join(imagePath, "blobs", digest.Algorithm().String(), digest.Encoded())

		buf, err = ioutil.ReadFile(p)

		if err != nil {
			return err
		}

		var manifest ispec.Manifest
		if err := json.Unmarshal(buf, &manifest); err != nil {
			return err
		}

		tag := manifest.Annotations[ispec.AnnotationRefName]
		blobList = append(blobList, manifest.Config.Digest.Encoded())

		for _, layer := range manifest.Layers {
			blobList = append(blobList, layer.Digest.Encoded())
		}

		// push blobs
		for _, blob := range blobList {
			// read blob
			blobPath := path.Join(imagePath, "blobs/sha256", blob)

			blobBuf, err := ioutil.ReadFile(blobPath)
			if err != nil {
				return err
			}

			blobURL := fmt.Sprintf("https://%s=sha256:%s", path.Join(baseURL, repo, imageName, "blobs/uploads/?digest"), blob)
			// post request of blob
			_, err = resty.R().
				SetHeader("Content-type", "application/octet-stream").
				SetHeader("Content-Length", fmt.Sprintf("%d", len(blobBuf))).
				SetBasicAuth(username, passphrase).
				SetBody(buf).Put(blobURL)

			if err != nil {
				return err
			}
		}

		// push manifest
		manifestURL := fmt.Sprintf("https://%s", path.Join(baseURL, repo, imageName, "manifests", tag))
		_, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			SetBody(buf).
			Put(manifestURL)

		if err != nil {
			return err
		}
	}

	// push index
	indexURL := fmt.Sprintf("https://%s", path.Join(baseURL, repo, imageName, "index.json"))
	_, err = resty.R().SetBasicAuth(username, passphrase).
		SetHeader("Content-type", ispec.MediaTypeImageManifest).
		SetBody(buf).
		Put(indexURL)

	if err != nil {
		return err
	}

	return nil
}
