package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
)

var httpClient *http.Client //nolint: gochecknoglobals

const httpTimeout = 5 * time.Second

func createHTTPClient(verifyTLS bool) *http.Client {
	var tr = http.DefaultTransport.(*http.Transport).Clone()
	if !verifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec
	}

	return &http.Client{
		Timeout:   httpTimeout,
		Transport: tr,
	}
}

func makeGETRequest(url, username, password string, verifyTLS bool, resultsPtr interface{}) (http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, password)

	if httpClient == nil {
		httpClient = createHTTPClient(verifyTLS)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, zotErrors.ErrUnauthorizedAccess
		}

		bodyBytes, _ := ioutil.ReadAll(resp.Body)

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
	jobs      chan *manifestJob
	done      chan struct{}
	waitGroup *sync.WaitGroup
	outputCh  chan imageListResult
	context   context.Context
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

func newSmoothRateLimiter(ctx context.Context, wg *sync.WaitGroup, op chan imageListResult) *requestsPool {
	ch := make(chan *manifestJob, rateLimiterBuffer)

	return &requestsPool{
		jobs:      ch,
		done:      make(chan struct{}),
		waitGroup: wg,
		outputCh:  op,
		context:   ctx,
	}
}

// block every "rateLimit" time duration.
const rateLimit = 100 * time.Millisecond

func (p *requestsPool) startRateLimiter() {
	p.waitGroup.Done()

	throttle := time.NewTicker(rateLimit).C

	for {
		select {
		case job := <-p.jobs:
			go p.doJob(job)
		case <-p.done:
			return
		}
		<-throttle
	}
}

func (p *requestsPool) doJob(job *manifestJob) {
	defer p.waitGroup.Done()

	header, err := makeGETRequest(job.url, job.username, job.password, *job.config.verifyTLS, &job.manifestResp)
	if err != nil {
		if isContextDone(p.context) {
			return
		}
		p.outputCh <- imageListResult{"", err}
	}

	digest := header.Get("docker-content-digest")
	digest = strings.TrimPrefix(digest, "sha256:")

	var size uint64

	for _, layer := range job.manifestResp.Layers {
		size += layer.Size
	}

	image := &imageStruct{}
	image.Name = job.imageName
	image.Tags = []tags{
		{
			Name:   job.tagName,
			Digest: digest,
			Size:   size,
		},
	}

	str, err := image.string(*job.config.outputFormat)
	if err != nil {
		if isContextDone(p.context) {
			return
		}
		p.outputCh <- imageListResult{"", err}

		return
	}

	if isContextDone(p.context) {
		return
	}

	p.outputCh <- imageListResult{str, nil}
}

func (p *requestsPool) submitJob(job *manifestJob) {
	p.jobs <- job
}
