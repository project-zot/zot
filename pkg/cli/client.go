//go:build search || ui_base
// +build search ui_base

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/storage"
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

func createHTTPClient(verifyTLS bool, host string) *http.Client {
	htr := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	if !verifyTLS {
		htr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec

		return &http.Client{
			Timeout:   httpTimeout,
			Transport: htr,
		}
	}

	// Add a copy of the system cert pool
	caCertPool, _ := x509.SystemCertPool()

	tlsConfig := loadPerHostCerts(caCertPool, host)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12}
	}

	htr = &http.Transport{TLSClientConfig: tlsConfig}

	return &http.Client{
		Timeout:   httpTimeout,
		Transport: htr,
	}
}

func makeGETRequest(ctx context.Context, url, username, password string,
	verifyTLS bool, resultsPtr interface{},
) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, password)

	return doHTTPRequest(req, verifyTLS, resultsPtr)
}

func makeGraphQLRequest(ctx context.Context, url, query, username,
	password string, verifyTLS bool, resultsPtr interface{},
) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, bytes.NewBufferString(query))
	if err != nil {
		return err
	}

	q := req.URL.Query()
	q.Add("query", query)

	req.URL.RawQuery = q.Encode()

	req.SetBasicAuth(username, password)
	req.Header.Add("Content-Type", "application/json")

	_, err = doHTTPRequest(req, verifyTLS, resultsPtr)
	if err != nil {
		return err
	}

	return nil
}

func doHTTPRequest(req *http.Request, verifyTLS bool, resultsPtr interface{}) (http.Header, error) {
	var httpClient *http.Client

	host := req.Host

	httpClientLock.Lock()

	if httpClientsMap[host] == nil {
		httpClient = createHTTPClient(verifyTLS, host)

		httpClientsMap[host] = httpClient
	} else {
		httpClient = httpClientsMap[host]
	}

	httpClientLock.Unlock()

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

func loadPerHostCerts(caCertPool *x509.CertPool, host string) *tls.Config {
	// Check if the /home/user/.config/containers/certs.d/$IP:$PORT dir exists
	home := os.Getenv("HOME")
	clientCertsDir := filepath.Join(home, homeCertsDir, host)

	if storage.DirExists(clientCertsDir) {
		tlsConfig, err := getTLSConfig(clientCertsDir, caCertPool)

		if err == nil {
			return tlsConfig
		}
	}

	// Check if the /etc/containers/certs.d/$IP:$PORT dir exists
	clientCertsDir = filepath.Join(certsPath, host)
	if storage.DirExists(clientCertsDir) {
		tlsConfig, err := getTLSConfig(clientCertsDir, caCertPool)

		if err == nil {
			return tlsConfig
		}
	}

	return nil
}

func getTLSConfig(certsPath string, caCertPool *x509.CertPool) (*tls.Config, error) {
	clientCert := filepath.Join(certsPath, clientCertFilename)
	clientKey := filepath.Join(certsPath, clientKeyFilename)
	caCertFile := filepath.Join(certsPath, caCertFilename)

	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}

	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
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
		*job.config.verifyTLS, &job.manifestResp)
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		p.outputCh <- stringResult{"", err}
	}

	digest := header.Get("docker-content-digest")
	digest = strings.TrimPrefix(digest, "sha256:")

	configDigest := job.manifestResp.Config.Digest
	configDigest = strings.TrimPrefix(configDigest, "sha256:")

	var size uint64

	layers := []layer{}

	for _, entry := range job.manifestResp.Layers {
		size += entry.Size

		layers = append(
			layers,
			layer{
				Size:   entry.Size,
				Digest: strings.TrimPrefix(entry.Digest, "sha256:"),
			},
		)
	}

	image := &imageStruct{}
	image.verbose = *job.config.verbose
	image.Name = job.imageName
	image.Tags = []tags{
		{
			Name:         job.tagName,
			Digest:       digest,
			Size:         size,
			ConfigDigest: configDigest,
			Layers:       layers,
		},
	}

	str, err := image.string(*job.config.outputFormat)
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
