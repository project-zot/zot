package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/google/uuid"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/test"
)

func deleteTestRepo(repos []string, url string, client *resty.Client) error {
	for _, repo := range repos {
		resp, err := client.R().Delete((fmt.Sprintf("%s/v2/%s/", url, repo)))
		if err != nil {
			return err
		}

		// request specific check
		statusCode := resp.StatusCode()
		if statusCode != http.StatusAccepted {
			return errors.ErrUnknownCode
		}
	}

	return nil
}

func pullAndCollect(url string, repos []string, manifestItem manifestStruct,
	config testConfig, client *resty.Client, statsCh chan statsRecord) []string {
	manifestHash := manifestItem.manifestHash
	manifestBySizeHash := manifestItem.manifestBySizeHash

	func() {
		start := time.Now()

		var isConnFail, isErr bool

		var statusCode int

		var latency time.Duration

		defer func() {
			// send a stats record
			statsCh <- statsRecord{
				latency:    latency,
				statusCode: statusCode,
				isConnFail: isConnFail,
				isErr:      isErr,
			}
		}()

		if config.mixedSize {
			smallSizeIdx := 0
			mediumSizeIdx := 1
			largeSizeIdx := 2

			idx := flipFunc(config.probabilityRange)

			switch idx {
			case smallSizeIdx:
				statusRequests["1MB"]++
			case mediumSizeIdx:
				statusRequests["10MB"]++
			case largeSizeIdx:
				statusRequests["100MB"]++
			}

			manifestHash = manifestBySizeHash[idx]
		}

		for repo, manifestTag := range manifestHash {
			manifestLoc := fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, manifestTag)

			// check manifest
			resp, err := client.R().
				SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				Head(manifestLoc)

			latency = time.Since(start)

			if err != nil {
				isConnFail = true

				return
			}

			// request specific check
			statusCode = resp.StatusCode()
			if statusCode != http.StatusOK {
				isErr = true

				return
			}

			// send request and get the manifest
			resp, err = client.R().
				SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				Get(manifestLoc)

			latency = time.Since(start)

			if err != nil {
				isConnFail = true

				return
			}

			// request specific check
			statusCode = resp.StatusCode()
			if statusCode != http.StatusOK {
				isErr = true

				return
			}

			manifestBody := resp.Body()

			// file copy simulation
			_, err = io.Copy(ioutil.Discard, bytes.NewReader(manifestBody))

			latency = time.Since(start)

			if err != nil {
				log.Fatal(err)
			}

			var pulledManifest ispec.Manifest

			err = json.Unmarshal(manifestBody, &pulledManifest)
			if err != nil {
				log.Fatal(err)
			}

			// check config
			configDigest := pulledManifest.Config.Digest
			configLoc := fmt.Sprintf("%s/v2/%s/blobs/%s", url, repo, configDigest)
			resp, err = client.R().Head(configLoc)

			latency = time.Since(start)

			if err != nil {
				isConnFail = true

				return
			}

			// request specific check
			statusCode = resp.StatusCode()
			if statusCode != http.StatusOK {
				isErr = true

				return
			}

			// send request and get the config
			resp, err = client.R().Get(configLoc)

			latency = time.Since(start)

			if err != nil {
				isConnFail = true

				return
			}

			// request specific check
			statusCode = resp.StatusCode()
			if statusCode != http.StatusOK {
				isErr = true

				return
			}

			configBody := resp.Body()

			// file copy simulation
			_, err = io.Copy(ioutil.Discard, bytes.NewReader(configBody))

			latency = time.Since(start)

			if err != nil {
				log.Fatal(err)
			}

			// download blobs
			for _, layer := range pulledManifest.Layers {
				blobDigest := layer.Digest
				blobLoc := fmt.Sprintf("%s/v2/%s/blobs/%s", url, repo, blobDigest)

				// check blob
				resp, err := client.R().Head(blobLoc)

				latency = time.Since(start)

				if err != nil {
					isConnFail = true

					return
				}

				// request specific check
				statusCode = resp.StatusCode()
				if statusCode != http.StatusOK {
					isErr = true

					return
				}

				// send request and get response the blob
				resp, err = client.R().Get(blobLoc)

				latency = time.Since(start)

				if err != nil {
					isConnFail = true

					return
				}

				// request specific check
				statusCode = resp.StatusCode()
				if statusCode != http.StatusOK {
					isErr = true

					return
				}

				blobBody := resp.Body()

				// file copy simulation
				_, err = io.Copy(ioutil.Discard, bytes.NewReader(blobBody))
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}()

	return repos
}

func pushMonolithImage(workdir, url, trepo string, repos []string, size int,
	client *resty.Client) (map[string]string, []string, error) {
	var statusCode int

	// key: repository name. value: manifest name
	manifestHash := make(map[string]string)

	ruid, err := uuid.NewUUID()
	if err != nil {
		return nil, repos, err
	}

	var repo string

	if trepo != "" {
		repo = trepo + "/" + ruid.String()
	} else {
		repo = ruid.String()
	}

	repos = append(repos, repo)

	// upload blob
	resp, err := client.R().Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repo))
	if err != nil {
		return nil, repos, err
	}

	// request specific check
	statusCode = resp.StatusCode()
	if statusCode != http.StatusAccepted {
		return nil, repos, errors.ErrUnknownCode
	}

	loc := test.Location(url, resp)
	blob := path.Join(workdir, fmt.Sprintf("%d.blob", size))

	fhandle, err := os.OpenFile(blob, os.O_RDONLY, defaultFilePerms)
	if err != nil {
		return nil, repos, err
	}

	defer fhandle.Close()

	// stream the entire blob
	digest := blobHash[blob]

	resp, err = client.R().
		SetContentLength(true).
		SetQueryParam("digest", digest.String()).
		SetHeader("Content-Length", fmt.Sprintf("%d", size)).
		SetHeader("Content-Type", "application/octet-stream").SetBody(fhandle).Put(loc)

	if err != nil {
		return nil, repos, err
	}

	// request specific check
	statusCode = resp.StatusCode()
	if statusCode != http.StatusCreated {
		return nil, repos, errors.ErrUnknownCode
	}

	// upload image config blob
	resp, err = client.R().
		Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repo))

	if err != nil {
		return nil, repos, err
	}

	// request specific check
	statusCode = resp.StatusCode()
	if statusCode != http.StatusAccepted {
		return nil, repos, errors.ErrUnknownCode
	}

	loc = test.Location(url, resp)
	cblob, cdigest := test.GetRandomImageConfig()
	resp, err = client.R().
		SetContentLength(true).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)

	if err != nil {
		return nil, repos, err
	}

	// request specific check
	statusCode = resp.StatusCode()
	if statusCode != http.StatusCreated {
		return nil, repos, errors.ErrUnknownCode
	}

	// create a manifest
	manifest := ispec.Manifest{
		Versioned: imeta.Versioned{
			SchemaVersion: defaultSchemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cdigest,
			Size:      int64(len(cblob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest,
				Size:      int64(size),
			},
		},
	}

	content, err := json.MarshalIndent(&manifest, "", "\t")
	if err != nil {
		return nil, repos, err
	}

	manifestTag := fmt.Sprintf("tag%d", size)

	// finish upload
	resp, err = client.R().
		SetContentLength(true).
		SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).
		Put(fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, manifestTag))

	if err != nil {
		return nil, repos, err
	}

	// request specific check
	statusCode = resp.StatusCode()
	if statusCode != http.StatusCreated {
		return nil, repos, errors.ErrUnknownCode
	}

	manifestHash[repo] = manifestTag

	return manifestHash, repos, nil
}

func pushMonolithAndCollect(workdir, url, trepo string, count int,
	repos []string, config testConfig, client *resty.Client,
	statsCh chan statsRecord) []string {
	func() {
		start := time.Now()

		var isConnFail, isErr bool

		var statusCode int

		var latency time.Duration

		defer func() {
			// send a stats record
			statsCh <- statsRecord{
				latency:    latency,
				statusCode: statusCode,
				isConnFail: isConnFail,
				isErr:      isErr,
			}
		}()

		ruid, err := uuid.NewUUID()
		if err != nil {
			log.Fatal(err)
		}

		var repo string

		if trepo != "" {
			repo = trepo + "/" + ruid.String()
		} else {
			repo = ruid.String()
		}

		repos = append(repos, repo)

		// create a new upload
		resp, err := client.R().
			Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repo))

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		loc := test.Location(url, resp)

		var size int

		if config.mixedSize {
			idx := flipFunc(config.probabilityRange)
			smallSizeIdx := 0
			mediumSizeIdx := 1
			largeSizeIdx := 2

			switch idx {
			case smallSizeIdx:
				size = smallBlob
				statusRequests["1MB"]++
			case mediumSizeIdx:
				size = mediumBlob
				statusRequests["10MB"]++
			case largeSizeIdx:
				size = largeBlob
				statusRequests["100MB"]++
			default:
				size = config.size
			}
		} else {
			size = config.size
		}

		blob := path.Join(workdir, fmt.Sprintf("%d.blob", size))

		fhandle, err := os.OpenFile(blob, os.O_RDONLY, defaultFilePerms)
		if err != nil {
			isConnFail = true

			return
		}

		defer fhandle.Close()

		// stream the entire blob
		digest := blobHash[blob]

		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", size)).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest.String()).
			SetBody(fhandle).
			Put(loc)

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusCreated {
			isErr = true

			return
		}

		// upload image config blob
		resp, err = client.R().
			Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repo))

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		loc = test.Location(url, resp)
		cblob, cdigest := test.GetRandomImageConfig()
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", cdigest.String()).
			SetBody(cblob).
			Put(loc)

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusCreated {
			isErr = true

			return
		}

		// create a manifest
		manifest := ispec.Manifest{
			Versioned: imeta.Versioned{
				SchemaVersion: defaultSchemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(size),
				},
			},
		}

		content, err := json.MarshalIndent(&manifest, "", "\t")
		if err != nil {
			log.Fatal(err)
		}

		manifestTag := fmt.Sprintf("tag%d", count)

		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).
			Put(fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, manifestTag))

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusCreated {
			isErr = true

			return
		}
	}()

	return repos
}

func pushChunkAndCollect(workdir, url, trepo string, count int,
	repos []string, config testConfig, client *resty.Client,
	statsCh chan statsRecord) []string {
	func() {
		start := time.Now()

		var isConnFail, isErr bool

		var statusCode int

		var latency time.Duration

		defer func() {
			// send a stats record
			statsCh <- statsRecord{
				latency:    latency,
				statusCode: statusCode,
				isConnFail: isConnFail,
				isErr:      isErr,
			}
		}()

		ruid, err := uuid.NewUUID()
		if err != nil {
			log.Fatal(err)
		}

		var repo string

		if trepo != "" {
			repo = trepo + "/" + ruid.String()
		} else {
			repo = ruid.String()
		}

		repos = append(repos, repo)

		// create a new upload
		resp, err := client.R().
			Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repo))

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		loc := test.Location(url, resp)

		var size int

		if config.mixedSize {
			idx := flipFunc(config.probabilityRange)
			smallSizeIdx := 0
			mediumSizeIdx := 1
			largeSizeIdx := 2

			switch idx {
			case smallSizeIdx:
				size = smallBlob
				statusRequests["1MB"]++
			case mediumSizeIdx:
				size = mediumBlob
				statusRequests["10MB"]++
			case largeSizeIdx:
				size = largeBlob
				statusRequests["100MB"]++

			default:
				size = config.size
			}
		} else {
			size = config.size
		}

		blob := path.Join(workdir, fmt.Sprintf("%d.blob", size))

		fhandle, err := os.OpenFile(blob, os.O_RDONLY, defaultFilePerms)
		if err != nil {
			isConnFail = true

			return
		}

		defer fhandle.Close()

		digest := blobHash[blob]

		// upload blob
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Type", "application/octet-stream").
			SetBody(fhandle).
			Patch(loc)

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		loc = test.Location(url, resp)

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		// finish upload
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", size)).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest.String()).
			Put(loc)

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusCreated {
			isErr = true

			return
		}

		// upload image config blob
		resp, err = client.R().
			Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repo))

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		loc = test.Location(url, resp)
		cblob, cdigest := test.GetRandomImageConfig()
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Type", "application/octet-stream").
			SetBody(fhandle).
			Patch(loc)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		// upload blob
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Type", "application/octet-stream").
			SetBody(cblob).
			Patch(loc)

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		loc = test.Location(url, resp)

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		// finish upload
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", cdigest.String()).
			Put(loc)

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusCreated {
			isErr = true

			return
		}

		// create a manifest
		manifest := ispec.Manifest{
			Versioned: imeta.Versioned{
				SchemaVersion: defaultSchemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(size),
				},
			},
		}

		content, err := json.Marshal(manifest)
		if err != nil {
			log.Fatal(err)
		}

		manifestTag := fmt.Sprintf("tag%d", count)

		// finish upload
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).
			Put(fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, manifestTag))

		latency = time.Since(start)

		if err != nil {
			isConnFail = true

			return
		}

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusCreated {
			isErr = true

			return
		}
	}()

	return repos
}
