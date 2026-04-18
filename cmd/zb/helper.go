package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	godigest "github.com/opencontainers/go-digest"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
)

func makeHTTPGetRequest(url string, resultPtr any, client *resty.Client) (http.Header, error) {
	resp, err := client.R().Get(url)
	if err != nil {
		return http.Header{}, err
	}

	header := resp.Header()

	if resp.StatusCode() != http.StatusOK {
		log.Printf("unable to make GET request on %s, response status code: %d", url, resp.StatusCode())

		return header, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusOK,
			resp.StatusCode(), string(resp.Body()))
	}

	err = json.Unmarshal(resp.Body(), resultPtr)
	if err != nil {
		return header, err
	}

	return header, nil
}

func makeHTTPDeleteRequest(url string, client *resty.Client) error {
	resp, err := client.R().Delete(url)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted {
		log.Printf("unable to make DELETE request on %s, response status code: %d", url, resp.StatusCode())

		return fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusAccepted,
			resp.StatusCode(), string(resp.Body()))
	}

	return nil
}

func deleteTestRepo(repos []string, url string, client *resty.Client) error {
	for _, repo := range repos {
		var tags common.ImageTags

		// get tags
		_, err := makeHTTPGetRequest(fmt.Sprintf("%s/v2/%s/tags/list", url, repo), &tags, client)
		if err != nil {
			return err
		}

		for _, tag := range tags.Tags {
			var manifest ispec.Manifest

			// first get tag manifest to get containing blobs
			header, err := makeHTTPGetRequest(fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, tag), &manifest, client)
			if err != nil {
				return err
			}

			manifestDigest := header.Get("Docker-Content-Digest")

			// delete manifest so that we don't trigger BlobInUse error
			err = makeHTTPDeleteRequest(fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, manifestDigest), client)
			if err != nil {
				return err
			}

			// delete blobs
			for _, blob := range manifest.Layers {
				err := makeHTTPDeleteRequest(fmt.Sprintf("%s/v2/%s/blobs/%s", url, repo, blob.Digest.String()), client)
				if err != nil {
					return err
				}
			}

			// delete config blob
			err = makeHTTPDeleteRequest(fmt.Sprintf("%s/v2/%s/blobs/%s", url, repo, manifest.Config.Digest.String()), client)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func pullAndCollect(url string, repos []string, manifestItem manifestStruct,
	config testConfig, client *resty.Client, statsCh chan statsRecord,
) []string {
	manifestHash := manifestItem.manifestHash
	manifestBySizeHash := manifestItem.manifestBySizeHash

	func() {
		start := time.Now()

		var (
			isConnFail, isErr bool
			statusCode        int
			latency           time.Duration
			err               error
		)

		timings := []perTagTiming{}

		defer func() {
			// send a stats record
			statsCh <- statsRecord{
				latency:    latency,
				statusCode: statusCode,
				isConnFail: isConnFail,
				isErr:      isErr,
				err:        err,
				timings:    timings,
			}
		}()

		if config.mixedSize {
			_, idx := getRandomSize(config.probabilityRange)

			manifestHash = manifestBySizeHash[idx]
		}

		for repo, manifestTag := range manifestHash {
			manifestLoc := fmt.Sprintf("%s/v2/%s/manifests/%s", url, repo, manifestTag)

			var resp *resty.Response

			tagTiming := perTagTiming{}

			var manifestHeadFirstByte time.Time
			manifestHeadReqStart := time.Now()

			manifestHeadTrace := &httptrace.ClientTrace{
				GotFirstResponseByte: func() {
					manifestHeadFirstByte = time.Now()
				},
			}

			// check manifest
			resp, err = client.R().
				SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetContext(httptrace.WithClientTrace(context.Background(), manifestHeadTrace)).
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

			if !manifestHeadFirstByte.IsZero() {
				tagTiming.manifestHeadTTFB = manifestHeadFirstByte.Sub(manifestHeadReqStart)
			}

			var manifestGetFirstByte time.Time
			manifestGetReqStart := time.Now()

			manifestTrace := &httptrace.ClientTrace{
				GotFirstResponseByte: func() {
					manifestGetFirstByte = time.Now()
				},
			}

			// send request and get the manifest
			resp, err = client.R().
				SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetContext(httptrace.WithClientTrace(context.Background(), manifestTrace)).
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

			if !manifestGetFirstByte.IsZero() {
				tagTiming.manifestGetTTFB = manifestGetFirstByte.Sub(manifestGetReqStart)
			}

			manifestBody := resp.Body()

			// file copy simulation
			_, err = io.Copy(io.Discard, bytes.NewReader(manifestBody))

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

			var configFirstByte time.Time
			configReqStart := time.Now()

			configTrace := &httptrace.ClientTrace{
				GotFirstResponseByte: func() {
					configFirstByte = time.Now()
				},
			}

			resp, err = client.R().
				SetContext(httptrace.WithClientTrace(context.Background(), configTrace)).
				Get(configLoc)

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

			if !configFirstByte.IsZero() {
				tagTiming.configTTFB = configFirstByte.Sub(configReqStart)
			}

			configBody := resp.Body()

			// file copy simulation
			_, err = io.Copy(io.Discard, bytes.NewReader(configBody))

			latency = time.Since(start)

			if err != nil {
				log.Fatal(err)
			}

			// download blobs
			for _, layer := range pulledManifest.Layers {
				blobDigest := layer.Digest
				blobLoc := fmt.Sprintf("%s/v2/%s/blobs/%s", url, repo, blobDigest)

				// check blob
				resp, err = client.R().Head(blobLoc)

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

				var blobFirstByte time.Time
				blobReqStart := time.Now()

				blobTrace := &httptrace.ClientTrace{
					GotFirstResponseByte: func() {
						blobFirstByte = time.Now()
					},
				}

				// send request and stream the blob directly to discard without buffering
				resp, err = client.R().
					SetDoNotParseResponse(true).
					SetContext(httptrace.WithClientTrace(context.Background(), blobTrace)).
					Get(blobLoc)

				latency = time.Since(start)

				if err != nil {
					isConnFail = true

					return
				}

				// request specific check
				statusCode = resp.StatusCode()
				if statusCode != http.StatusOK {
					isErr = true
					resp.RawBody().Close()

					return
				}

				if !blobFirstByte.IsZero() {
					tagTiming.layersTTFB = append(tagTiming.layersTTFB, blobFirstByte.Sub(blobReqStart))
				}

				// drain response body without buffering in memory
				if _, err = io.Copy(io.Discard, resp.RawBody()); err != nil {
					log.Fatal(err)
				}

				resp.RawBody().Close()
			}

			timings = append(timings, tagTiming)
		}
	}()

	return repos
}

func pushMonolithImage(workdir, url, trepo string, repos []string, config testConfig,
	client *resty.Client,
) (map[string]string, []string, error) {
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
		return nil, repos, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusAccepted,
			resp.StatusCode(), string(resp.Body())) //nolint: err113
	}

	loc := getLocation(url, resp)

	var size int

	if config.size == 0 {
		size, _ = getRandomSize(config.probabilityRange)
	} else {
		size = config.size
	}

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
		SetHeader("Content-Length", strconv.Itoa(size)).
		SetHeader("Content-Type", "application/octet-stream").SetBody(fhandle).Put(loc)
	if err != nil {
		return nil, repos, err
	}

	// request specific check
	statusCode = resp.StatusCode()
	if statusCode != http.StatusCreated {
		return nil, repos, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusCreated,
			resp.StatusCode(), string(resp.Body()))
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
		return nil, repos, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusAccepted,
			resp.StatusCode(), string(resp.Body()))
	}

	loc = getLocation(url, resp)
	cblob, cdigest := getImageConfig()

	resp, err = client.R().
		SetContentLength(true).
		SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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
		return nil, repos, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusCreated,
			resp.StatusCode(), string(resp.Body()))
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
		return nil, repos, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusCreated,
			resp.StatusCode(), string(resp.Body()))
	}

	manifestHash[repo] = manifestTag

	return manifestHash, repos, nil
}

func pushMonolithAndCollect(workdir, url, trepo string, count int,
	repos []string, config testConfig, client *resty.Client,
	statsCh chan statsRecord,
) []string {
	func() {
		start := time.Now()

		var (
			isConnFail, isErr bool
			statusCode        int
			latency           time.Duration
			err               error
		)

		defer func() {
			// send a stats record
			statsCh <- statsRecord{
				latency:    latency,
				statusCode: statusCode,
				isConnFail: isConnFail,
				isErr:      isErr,
				err:        err,
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

		loc := getLocation(url, resp)

		var size int

		if config.mixedSize {
			size, _ = getRandomSize(config.probabilityRange)
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
			SetHeader("Content-Length", strconv.Itoa(size)).
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

		loc = getLocation(url, resp)
		cblob, cdigest := getImageConfig()
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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
	statsCh chan statsRecord,
) []string {
	func() {
		start := time.Now()

		var (
			isConnFail, isErr bool
			statusCode        int
			latency           time.Duration
			err               error
		)

		defer func() {
			// send a stats record
			statsCh <- statsRecord{
				latency:    latency,
				statusCode: statusCode,
				isConnFail: isConnFail,
				isErr:      isErr,
				err:        err,
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

		loc := getLocation(url, resp)

		var size int

		if config.mixedSize {
			size, _ = getRandomSize(config.probabilityRange)
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

		loc = getLocation(url, resp)

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		// finish upload
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", strconv.Itoa(size)).
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

		loc = getLocation(url, resp)
		cblob, cdigest := getImageConfig()

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

		loc = getLocation(url, resp)

		// request specific check
		statusCode = resp.StatusCode()
		if statusCode != http.StatusAccepted {
			isErr = true

			return
		}

		// finish upload
		resp, err = client.R().
			SetContentLength(true).
			SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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

func getRandomSize(probabilityRange []float64) (int, int) {
	var size int

	idx := flipFunc(probabilityRange)
	smallSizeIdx := 0
	mediumSizeIdx := 1
	largeSizeIdx := 2

	switch idx {
	case smallSizeIdx:
		size = smallBlob
		current := loadOrStore(&statusRequests, "1MB", 0)
		statusRequests.Store("1MB", current+1)
	case mediumSizeIdx:
		size = mediumBlob
		current := loadOrStore(&statusRequests, "10MB", 0)
		statusRequests.Store("10MB", current+1)
	case largeSizeIdx:
		size = largeBlob
		current := loadOrStore(&statusRequests, "100MB", 0)
		statusRequests.Store("100MB", current+1)
	default:
		size = 0
	}

	return size, idx
}

//nolint:gosec
func flipFunc(probabilityRange []float64) int {
	seed := time.Now().UTC().UnixNano()
	mrand := rand.New(rand.NewSource(seed))
	toss := mrand.Float64()

	for idx, r := range probabilityRange {
		if toss < r {
			return idx
		}
	}

	return len(probabilityRange) - 1
}

// pbty - probabilities.
func normalizeProbabilityRange(pbty []float64) []float64 {
	dim := len(pbty)

	// npd - normalized probability density
	npd := make([]float64, dim)

	for idx := range pbty {
		npd[idx] = 0.0
	}

	// [0.2, 0.7, 0.1] -> [0.2, 0.9, 1]
	npd[0] = pbty[0]
	for i := 1; i < dim; i++ {
		npd[i] = npd[i-1] + pbty[i]
	}

	return npd
}

func loadOrStore(statusRequests *sync.Map, key string, value int) int { //nolint:unparam
	val, _ := statusRequests.LoadOrStore(key, value)

	intValue, ok := val.(int)
	if !ok {
		log.Fatalf("invalid type: %#v, should be int", val)
	}

	return intValue
}

func getImageConfig() ([]byte, godigest.Digest) {
	createdTime := time.Date(2011, time.Month(1), 1, 1, 1, 1, 0, time.UTC)

	config := ispec.Image{
		Created: &createdTime,
		Author:  "ZotUser",
		Platform: ispec.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
	}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}

func getLocation(baseURL string, resp *resty.Response) string {
	// For some API responses, the Location header is set and is supposed to
	// indicate an opaque value. However, it is not clear if this value is an
	// absolute URL (https://server:port/v2/...) or just a path (/v2/...)
	// zot implements the latter as per the spec, but some registries appear to
	// return the former - this needs to be clarified
	loc := resp.Header().Get("Location")

	uloc, err := url.Parse(loc)
	if err != nil {
		return ""
	}

	path := uloc.Path

	return baseURL + path
}
