//go:build search
// +build search

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	notreg "github.com/notaryproject/notation-go/registry"
	"github.com/sigstore/cosign/pkg/oci/remote"

	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
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
			resp.StatusCode, " ", "[respoonse header] ", resp.Header)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, zotErrors.ErrUnauthorizedAccess
		}

		bodyBytes, _ := io.ReadAll(resp.Body)

		return nil, errors.New(string(bodyBytes)) //nolint: goerr113
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
	jobs     chan *manifestJob
	done     chan struct{}
	wtgrp    *sync.WaitGroup
	outputCh chan stringResult
}

type manifestJob struct {
	url          string
	username     string
	password     string
	imageName    string
	tagName      string
	config       searchConfig
	manifestResp manifestResponse
}

const rateLimiterBuffer = 5000

func newSmoothRateLimiter(wtgrp *sync.WaitGroup, opch chan stringResult) *requestsPool {
	ch := make(chan *manifestJob, rateLimiterBuffer)

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

func (p *requestsPool) doJob(ctx context.Context, job *manifestJob) {
	defer p.wtgrp.Done()

	header, err := makeGETRequest(ctx, job.url, job.username, job.password,
		*job.config.verifyTLS, *job.config.debug, &job.manifestResp, job.config.resultWriter)
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		p.outputCh <- stringResult{"", err}
	}

	digestStr := header.Get("docker-content-digest")
	configDigest := job.manifestResp.Config.Digest

	var size uint64

	layers := []layer{}

	for _, entry := range job.manifestResp.Layers {
		size += entry.Size

		layers = append(
			layers,
			layer{
				Size:   entry.Size,
				Digest: entry.Digest,
			},
		)
	}

	size += uint64(job.manifestResp.Config.Size)

	manifestSize, err := strconv.Atoi(header.Get("Content-Length"))
	if err != nil {
		p.outputCh <- stringResult{"", err}
	}

	isSigned := false
	cosignTag := strings.Replace(digestStr, ":", "-", 1) + "." + remote.SignatureTagSuffix

	_, err = makeGETRequest(ctx, *job.config.servURL+"/v2/"+job.imageName+
		"/manifests/"+cosignTag, job.username, job.password,
		*job.config.verifyTLS, *job.config.debug, &job.manifestResp, job.config.resultWriter)
	if err == nil {
		isSigned = true
	}

	var referrers api.ReferenceList

	if !isSigned {
		_, err = makeGETRequest(ctx, fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers?artifactType=%s",
			*job.config.servURL, job.imageName, digestStr, notreg.ArtifactTypeNotation), job.username, job.password,
			*job.config.verifyTLS, *job.config.debug, &referrers, job.config.resultWriter)
		if err == nil {
			for _, reference := range referrers.References {
				if reference.ArtifactType == notreg.ArtifactTypeNotation {
					isSigned = true

					break
				}
			}
		}
	}

	size += uint64(manifestSize)

	image := &imageStruct{}
	image.verbose = *job.config.verbose
	image.RepoName = job.imageName
	image.Tag = job.tagName
	image.Digest = digestStr
	image.Size = strconv.Itoa(int(size))
	image.ConfigDigest = configDigest
	image.Layers = layers
	image.IsSigned = isSigned

	str, err := image.string(*job.config.outputFormat, len(job.imageName), len(job.tagName))
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
}

func (p *requestsPool) submitJob(job *manifestJob) {
	p.jobs <- job
}
