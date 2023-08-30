//go:build search
// +build search

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	notreg "github.com/notaryproject/notation-go/registry"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
)

var (
	httpClientsMap = make(map[string]*http.Client) //nolint: gochecknoglobals
	httpClientLock sync.Mutex                      //nolint: gochecknoglobals
)

const (
	httpTimeout        = 5 * time.Minute
	certsPath          = "/etc/containers/certs.d"
	homeCertsDir       = ".config/containers/certs.d"
	clientCertFilename = "client.cert"
	clientKeyFilename  = "client.key"
	caCertFilename     = "ca.crt"
)

func makeGETRequest(ctx context.Context, url, username, password string,
	verifyTLS bool, debug bool, resultsPtr interface{}, configWriter io.Writer,
) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, password)

	return doHTTPRequest(req, verifyTLS, debug, resultsPtr, configWriter)
}

func makeHEADRequest(ctx context.Context, url, username, password string, verifyTLS bool,
	debug bool,
) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, password)

	return doHTTPRequest(req, verifyTLS, debug, nil, io.Discard)
}

func makeGraphQLRequest(ctx context.Context, url, query, username,
	password string, verifyTLS bool, debug bool, resultsPtr interface{}, configWriter io.Writer,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewBufferString(query))
	if err != nil {
		return err
	}

	q := req.URL.Query()
	q.Add("query", query)

	req.URL.RawQuery = q.Encode()

	req.SetBasicAuth(username, password)
	req.Header.Add("Content-Type", "application/json")

	_, err = doHTTPRequest(req, verifyTLS, debug, resultsPtr, configWriter)
	if err != nil {
		return err
	}

	return nil
}

func doHTTPRequest(req *http.Request, verifyTLS bool, debug bool,
	resultsPtr interface{}, configWriter io.Writer,
) (http.Header, error) {
	var httpClient *http.Client

	var err error

	host := req.Host

	httpClientLock.Lock()

	if httpClientsMap[host] == nil {
		httpClient, err = common.CreateHTTPClient(verifyTLS, host, "")
		if err != nil {
			return nil, err
		}

		httpClientsMap[host] = httpClient
	} else {
		httpClient = httpClientsMap[host]
	}

	httpClientLock.Unlock()

	if debug {
		fmt.Fprintln(configWriter, "[debug] ", req.Method, " ", req.URL, "[request header] ", req.Header)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Fprintln(configWriter, "[debug] ", req.Method, req.URL, "[status] ",
			resp.StatusCode, " ", "[response header] ", resp.Header)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, zerr.ErrUnauthorizedAccess
		}

		bodyBytes, _ := io.ReadAll(resp.Body)

		return nil, fmt.Errorf("%w: Expected: %d, Got: %d, Body: '%s'", zerr.ErrBadHTTPStatusCode, http.StatusOK,
			resp.StatusCode, string(bodyBytes))
	}

	if resultsPtr == nil {
		return resp.Header, nil
	}

	if err := json.NewDecoder(resp.Body).Decode(resultsPtr); err != nil {
		return nil, err
	}

	return resp.Header, nil
}

func isURL(str string) bool {
	u, err := url.Parse(str)

	return err == nil && u.Scheme != "" && u.Host != ""
} // from https://stackoverflow.com/a/55551215

type requestsPool struct {
	jobs     chan *httpJob
	done     chan struct{}
	wtgrp    *sync.WaitGroup
	outputCh chan stringResult
}

type httpJob struct {
	url       string
	username  string
	password  string
	imageName string
	tagName   string
	config    searchConfig
}

const rateLimiterBuffer = 5000

func newSmoothRateLimiter(wtgrp *sync.WaitGroup, opch chan stringResult) *requestsPool {
	ch := make(chan *httpJob, rateLimiterBuffer)

	return &requestsPool{
		jobs:     ch,
		done:     make(chan struct{}),
		wtgrp:    wtgrp,
		outputCh: opch,
	}
}

// block every "rateLimit" time duration.
const rateLimit = 100 * time.Millisecond

func (p *requestsPool) startRateLimiter(ctx context.Context) {
	p.wtgrp.Done()

	throttle := time.NewTicker(rateLimit).C

	for {
		select {
		case job := <-p.jobs:
			go p.doJob(ctx, job)
		case <-p.done:
			return
		}
		<-throttle
	}
}

func (p *requestsPool) doJob(ctx context.Context, job *httpJob) {
	defer p.wtgrp.Done()

	// Check manifest media type
	header, err := makeHEADRequest(ctx, job.url, job.username, job.password, *job.config.verifyTLS,
		*job.config.debug)
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		p.outputCh <- stringResult{"", err}
	}

	verbose := *job.config.verbose

	switch header.Get("Content-Type") {
	case ispec.MediaTypeImageManifest:
		image, err := fetchImageManifestStruct(ctx, job)
		if err != nil {
			if isContextDone(ctx) {
				return
			}
			p.outputCh <- stringResult{"", err}

			return
		}
		platformStr := getPlatformStr(image.Manifests[0].Platform)

		str, err := image.string(*job.config.outputFormat, len(job.imageName), len(job.tagName), len(platformStr), verbose)
		if err != nil {
			if isContextDone(ctx) {
				return
			}
			p.outputCh <- stringResult{"", err}

			return
		}

		if isContextDone(ctx) {
			return
		}

		p.outputCh <- stringResult{str, nil}
	case ispec.MediaTypeImageIndex:
		image, err := fetchImageIndexStruct(ctx, job)
		if err != nil {
			if isContextDone(ctx) {
				return
			}
			p.outputCh <- stringResult{"", err}

			return
		}

		platformStr := getPlatformStr(image.Manifests[0].Platform)

		str, err := image.string(*job.config.outputFormat, len(job.imageName), len(job.tagName), len(platformStr), verbose)
		if err != nil {
			if isContextDone(ctx) {
				return
			}
			p.outputCh <- stringResult{"", err}

			return
		}

		if isContextDone(ctx) {
			return
		}

		p.outputCh <- stringResult{str, nil}
	default:
		return
	}
}

func fetchImageIndexStruct(ctx context.Context, job *httpJob) (*imageStruct, error) {
	var indexContent ispec.Index

	header, err := makeGETRequest(ctx, job.url, job.username, job.password,
		*job.config.verifyTLS, *job.config.debug, &indexContent, job.config.resultWriter)
	if err != nil {
		if isContextDone(ctx) {
			return nil, context.Canceled
		}

		return nil, err
	}

	indexDigest := header.Get("docker-content-digest")

	indexSize, err := strconv.ParseInt(header.Get("Content-Length"), 10, 64)
	if err != nil {
		return nil, err
	}

	imageSize := indexSize

	manifestList := make([]common.ManifestSummary, 0, len(indexContent.Manifests))

	for _, manifestDescriptor := range indexContent.Manifests {
		manifest, err := fetchManifestStruct(ctx, job.imageName, manifestDescriptor.Digest.String(),
			job.config, job.username, job.password)
		if err != nil {
			return nil, err
		}

		imageSize += int64(atoiWithDefault(manifest.Size, 0))

		if manifestDescriptor.Platform != nil {
			manifest.Platform = common.Platform{
				Os:      manifestDescriptor.Platform.OS,
				Arch:    manifestDescriptor.Platform.Architecture,
				Variant: manifestDescriptor.Platform.Variant,
			}
		}

		manifestList = append(manifestList, manifest)
	}

	isIndexSigned := isCosignSigned(ctx, job.imageName, indexDigest, job.config, job.username, job.password) ||
		isNotationSigned(ctx, job.imageName, indexDigest, job.config, job.username, job.password)

	return &imageStruct{
		RepoName:  job.imageName,
		Tag:       job.tagName,
		Digest:    indexDigest,
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: manifestList,
		Size:      strconv.FormatInt(imageSize, 10),
		IsSigned:  isIndexSigned,
	}, nil
}

func atoiWithDefault(size string, defaultVal int) int {
	val, err := strconv.Atoi(size)
	if err != nil {
		return defaultVal
	}

	return val
}

func fetchImageManifestStruct(ctx context.Context, job *httpJob) (*imageStruct, error) {
	manifest, err := fetchManifestStruct(ctx, job.imageName, job.tagName, job.config, job.username, job.password)
	if err != nil {
		return nil, err
	}

	return &imageStruct{
		RepoName:  job.imageName,
		Tag:       job.tagName,
		Digest:    manifest.Digest,
		MediaType: ispec.MediaTypeImageManifest,
		Manifests: []common.ManifestSummary{
			manifest,
		},
		Size:     manifest.Size,
		IsSigned: manifest.IsSigned,
	}, nil
}

func fetchManifestStruct(ctx context.Context, repo, manifestReference string, searchConf searchConfig,
	username, password string,
) (common.ManifestSummary, error) {
	manifestResp := ispec.Manifest{}

	URL := fmt.Sprintf("%s/v2/%s/manifests/%s",
		*searchConf.servURL, repo, manifestReference)

	header, err := makeGETRequest(ctx, URL, username, password,
		*searchConf.verifyTLS, *searchConf.debug, &manifestResp, searchConf.resultWriter)
	if err != nil {
		if isContextDone(ctx) {
			return common.ManifestSummary{}, context.Canceled
		}

		return common.ManifestSummary{}, err
	}

	manifestDigest := header.Get("docker-content-digest")
	configDigest := manifestResp.Config.Digest.String()

	configContent, err := fetchConfig(ctx, repo, configDigest, searchConf, username, password)
	if err != nil {
		if isContextDone(ctx) {
			return common.ManifestSummary{}, context.Canceled
		}

		return common.ManifestSummary{}, err
	}

	opSys := ""
	arch := ""
	variant := ""

	if manifestResp.Config.Platform != nil {
		opSys = manifestResp.Config.Platform.OS
		arch = manifestResp.Config.Platform.Architecture
		variant = manifestResp.Config.Platform.Variant
	}

	if opSys == "" {
		opSys = configContent.OS
	}

	if arch == "" {
		arch = configContent.Architecture
	}

	if variant == "" {
		variant = configContent.Variant
	}

	manifestSize, err := strconv.ParseInt(header.Get("Content-Length"), 10, 64)
	if err != nil {
		return common.ManifestSummary{}, err
	}

	var imageSize int64

	imageSize += manifestResp.Config.Size
	imageSize += manifestSize

	layers := []common.LayerSummary{}

	for _, entry := range manifestResp.Layers {
		imageSize += entry.Size

		layers = append(
			layers,
			common.LayerSummary{
				Size:   fmt.Sprintf("%v", entry.Size),
				Digest: entry.Digest.String(),
			},
		)
	}

	isSigned := isCosignSigned(ctx, repo, manifestDigest, searchConf, username, password) ||
		isNotationSigned(ctx, repo, manifestDigest, searchConf, username, password)

	return common.ManifestSummary{
		ConfigDigest: configDigest,
		Digest:       manifestDigest,
		Layers:       layers,
		Platform:     common.Platform{Os: opSys, Arch: arch, Variant: variant},
		Size:         strconv.FormatInt(imageSize, 10),
		IsSigned:     isSigned,
	}, nil
}

func fetchConfig(ctx context.Context, repo, configDigest string, searchConf searchConfig,
	username, password string,
) (ispec.Image, error) {
	configContent := ispec.Image{}

	URL := fmt.Sprintf("%s/v2/%s/blobs/%s",
		*searchConf.servURL, repo, configDigest)

	_, err := makeGETRequest(ctx, URL, username, password,
		*searchConf.verifyTLS, *searchConf.debug, &configContent, searchConf.resultWriter)
	if err != nil {
		if isContextDone(ctx) {
			return ispec.Image{}, context.Canceled
		}

		return ispec.Image{}, err
	}

	return configContent, nil
}

func isNotationSigned(ctx context.Context, repo, digestStr string, searchConf searchConfig,
	username, password string,
) bool {
	var referrers ispec.Index

	URL := fmt.Sprintf("%s/v2/%s/referrers/%s?artifactType=%s",
		*searchConf.servURL, repo, digestStr, notreg.ArtifactTypeNotation)

	_, err := makeGETRequest(ctx, URL, username, password,
		*searchConf.verifyTLS, *searchConf.debug, &referrers, searchConf.resultWriter)
	if err != nil {
		return false
	}

	if len(referrers.Manifests) > 0 {
		return true
	}

	return false
}

func isCosignSigned(ctx context.Context, repo, digestStr string, searchConf searchConfig,
	username, password string,
) bool {
	var result interface{}
	cosignTag := strings.Replace(digestStr, ":", "-", 1) + "." + remote.SignatureTagSuffix

	URL := fmt.Sprintf("%s/v2/%s/manifests/%s", *searchConf.servURL, repo, cosignTag)

	_, err := makeGETRequest(ctx, URL, username, password, *searchConf.verifyTLS,
		*searchConf.debug, &result, searchConf.resultWriter)

	return err == nil
}

func (p *requestsPool) submitJob(job *httpJob) {
	p.jobs <- job
}
