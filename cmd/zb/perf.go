package main

import (
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	urlparser "net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	jsoniter "github.com/json-iterator/go"
	godigest "github.com/opencontainers/go-digest"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api/constants"
)

const (
	KiB                  = 1 * 1024
	MiB                  = 1 * KiB * 1024
	GiB                  = 1 * MiB * 1024
	maxSize              = 1 * GiB // 1GiB
	defaultDirPerms      = 0o700
	defaultFilePerms     = 0o600
	defaultSchemaVersion = 2
	smallBlob            = 1 * MiB
	mediumBlob           = 10 * MiB
	largeBlob            = 100 * MiB
	cicdFmt              = "ci-cd"
	secureProtocol       = "https"
	httpKeepAlive        = 30 * time.Second
	maxSourceIPs         = 1000
	httpTimeout          = 30 * time.Second
	TLSHandshakeTimeout  = 10 * time.Second
)

// nolint:gochecknoglobals
var blobHash map[string]godigest.Digest = map[string]godigest.Digest{}

// nolint:gochecknoglobals // used only in this test
var statusRequests map[string]int

func setup(workingDir string) {
	_ = os.MkdirAll(workingDir, defaultDirPerms)

	const multiplier = 10

	const rndPageSize = 4 * KiB

	for size := 1 * MiB; size < maxSize; size *= multiplier {
		fname := path.Join(workingDir, fmt.Sprintf("%d.blob", size))

		fhandle, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, defaultFilePerms)
		if err != nil {
			log.Fatal(err)
		}

		err = fhandle.Truncate(int64(size))
		if err != nil {
			log.Fatal(err)
		}

		_, err = fhandle.Seek(0, 0)
		if err != nil {
			log.Fatal(err)
		}

		// write a random first page so every test run has different blob content
		rnd := make([]byte, rndPageSize)
		if _, err := crand.Read(rnd); err != nil {
			log.Fatal(err)
		}

		if _, err := fhandle.Write(rnd); err != nil {
			log.Fatal(err)
		}

		if _, err := fhandle.Seek(0, 0); err != nil {
			log.Fatal(err)
		}

		fhandle.Close() // should flush the write

		// pre-compute the SHA256
		fhandle, err = os.OpenFile(fname, os.O_RDONLY, defaultFilePerms)
		if err != nil {
			log.Fatal(err)
		}

		defer fhandle.Close()

		digest, err := godigest.FromReader(fhandle)
		if err != nil {
			log.Fatal(err) // nolint:gocritic // file closed on exit
		}

		blobHash[fname] = digest
	}
}

func teardown(workingDir string) {
	_ = os.RemoveAll(workingDir)
}

// statistics handling.

type Durations []time.Duration

func (a Durations) Len() int           { return len(a) }
func (a Durations) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Durations) Less(i, j int) bool { return a[i] < a[j] }

type statsSummary struct {
	latencies            []time.Duration
	name                 string
	min, max, total      time.Duration
	statusHist           map[string]int
	rps                  float32
	mixedSize, mixedType bool
	errors               int
}

func newStatsSummary(name string) statsSummary {
	summary := statsSummary{
		name:       name,
		min:        -1,
		max:        -1,
		statusHist: make(map[string]int),
		mixedSize:  false,
		mixedType:  false,
	}

	return summary
}

type statsRecord struct {
	latency    time.Duration
	statusCode int
	isConnFail bool
	isErr      bool
}

func updateStats(summary *statsSummary, record statsRecord) {
	if record.isConnFail || record.isErr {
		summary.errors++
	}

	if summary.min < 0 || record.latency < summary.min {
		summary.min = record.latency
	}

	if summary.max < 0 || record.latency > summary.max {
		summary.max = record.latency
	}

	// 2xx
	if record.statusCode >= http.StatusOK &&
		record.statusCode <= http.StatusAccepted {
		summary.statusHist["2xx"]++
	}

	// 3xx
	if record.statusCode >= http.StatusMultipleChoices &&
		record.statusCode <= http.StatusPermanentRedirect {
		summary.statusHist["3xx"]++
	}

	// 4xx
	if record.statusCode >= http.StatusBadRequest &&
		record.statusCode <= http.StatusUnavailableForLegalReasons {
		summary.statusHist["4xx"]++
	}

	// 5xx
	if record.statusCode >= http.StatusInternalServerError &&
		record.statusCode <= http.StatusNetworkAuthenticationRequired {
		summary.statusHist["5xx"]++
	}

	summary.latencies = append(summary.latencies, record.latency)
}

type cicdTestSummary struct {
	Name  string      `json:"name"`
	Unit  string      `json:"unit"`
	Value interface{} `json:"value"`
	Range string      `json:"range,omitempty"`
}

type manifestStruct struct {
	manifestHash       map[string]string
	manifestBySizeHash map[int](map[string]string)
}

// nolint:gochecknoglobals // used only in this test
var cicdSummary = []cicdTestSummary{}

func printStats(requests int, summary *statsSummary, outFmt string) {
	log.Printf("============\n")
	log.Printf("Test name:\t%s", summary.name)
	log.Printf("Time taken for tests:\t%v", summary.total)
	log.Printf("Complete requests:\t%v", requests-summary.errors)
	log.Printf("Failed requests:\t%v", summary.errors)
	log.Printf("Requests per second:\t%v", summary.rps)
	log.Printf("\n")

	if summary.mixedSize {
		log.Printf("1MB:\t%v", statusRequests["1MB"])
		log.Printf("10MB:\t%v", statusRequests["10MB"])
		log.Printf("100MB:\t%v", statusRequests["100MB"])
		log.Printf("\n")
	}

	if summary.mixedType {
		log.Printf("Pull:\t%v", statusRequests["Pull"])
		log.Printf("Push:\t%v", statusRequests["Push"])
		log.Printf("\n")
	}

	for k, v := range summary.statusHist {
		log.Printf("%s responses:\t%v", k, v)
	}

	log.Printf("\n")
	log.Printf("min: %v", summary.min)
	log.Printf("max: %v", summary.max)
	log.Printf("%s:\t%v", "p50", summary.latencies[requests/2])
	log.Printf("%s:\t%v", "p75", summary.latencies[requests*3/4])
	log.Printf("%s:\t%v", "p90", summary.latencies[requests*9/10])
	log.Printf("%s:\t%v", "p99", summary.latencies[requests*99/100])
	log.Printf("\n")

	// ci/cd
	if outFmt == cicdFmt {
		cicdSummary = append(cicdSummary,
			cicdTestSummary{
				Name:  summary.name,
				Unit:  "requests per sec",
				Value: summary.rps,
				Range: "3",
			},
		)
	}
}

// nolint:gosec
func flipFunc(probabilityRange []float64) int {
	mrand.Seed(time.Now().UTC().UnixNano())
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

// test suites/funcs.

type testFunc func(
	workdir, url, repo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
) error

func GetCatalog(
	workdir, url, repo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	for count := 0; count < requests; count++ {
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

			// send request and get response
			resp, err := client.R().Get(url + constants.RoutePrefix + constants.ExtCatalogPrefix)

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
		}()
	}

	return nil
}

func PushMonolithStreamed(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	if config.mixedSize {
		statusRequests = make(map[string]int)
	}

	for count := 0; count < requests; count++ {
		repos = pushMonolithAndCollect(workdir, url, trepo, count,
			repos, config, client, statsCh)
	}

	// clean up
	err := deleteTestRepo(repos, url, client)
	if err != nil {
		return err
	}

	return nil
}

func PushChunkStreamed(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	if config.mixedSize {
		statusRequests = make(map[string]int)
	}

	for count := 0; count < requests; count++ {
		repos = pushChunkAndCollect(workdir, url, trepo, count,
			repos, config, client, statsCh)
	}

	// clean up
	err := deleteTestRepo(repos, url, client)
	if err != nil {
		return err
	}

	return nil
}

func Pull(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	var manifestHash map[string]string

	manifestBySizeHash := make(map[int](map[string]string))

	if config.mixedSize {
		statusRequests = make(map[string]int)
	}

	if config.mixedSize {
		var manifestBySize map[string]string

		smallSizeIdx := 0
		mediumSizeIdx := 1
		largeSizeIdx := 2

		// Push small blob
		manifestBySize, repos, err := pushMonolithImage(workdir, url, trepo, repos, smallBlob, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[smallSizeIdx] = manifestBySize

		// Push medium blob
		manifestBySize, repos, err = pushMonolithImage(workdir, url, trepo, repos, mediumBlob, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[mediumSizeIdx] = manifestBySize

		// Push large blob
		// nolint: ineffassign, staticcheck, wastedassign
		manifestBySize, repos, err = pushMonolithImage(workdir, url, trepo, repos, largeBlob, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[largeSizeIdx] = manifestBySize
	} else {
		// Push blob given size
		var err error
		manifestHash, repos, err = pushMonolithImage(workdir, url, trepo, repos, config.size, client)
		if err != nil {
			return err
		}
	}

	manifestItem := manifestStruct{
		manifestHash:       manifestHash,
		manifestBySizeHash: manifestBySizeHash,
	}

	// download image
	for count := 0; count < requests; count++ {
		repos = pullAndCollect(url, repos, manifestItem, config, client, statsCh)
	}

	// clean up
	err := deleteTestRepo(repos, url, client)
	if err != nil {
		return err
	}

	return nil
}

func MixedPullAndPush(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	statusRequests = make(map[string]int)

	// Push blob given size
	manifestHash, repos, err := pushMonolithImage(workdir, url, trepo, repos, config.size, client)
	if err != nil {
		return err
	}

	manifestItem := manifestStruct{
		manifestHash: manifestHash,
	}

	for count := 0; count < requests; count++ {
		idx := flipFunc(config.probabilityRange)

		readTestIdx := 0
		writeTestIdx := 1

		if idx == readTestIdx {
			repos = pullAndCollect(url, repos, manifestItem, config, client, statsCh)
			statusRequests["Pull"]++
		} else if idx == writeTestIdx {
			repos = pushMonolithAndCollect(workdir, url, trepo, count, repos, config, client, statsCh)
			statusRequests["Push"]++
		}
	}

	// clean up
	err = deleteTestRepo(repos, url, client)
	if err != nil {
		return err
	}

	return nil
}

// test driver.

type testConfig struct {
	name  string
	tfunc testFunc
	// test-specific params
	size                 int
	probabilityRange     []float64
	mixedSize, mixedType bool
}

var testSuite = []testConfig{ // nolint:gochecknoglobals // used only in this test
	{
		name:  "Get Catalog",
		tfunc: GetCatalog,
	},
	{
		name:  "Push Monolith 1MB",
		tfunc: PushMonolithStreamed,
		size:  smallBlob,
	},
	{
		name:  "Push Monolith 10MB",
		tfunc: PushMonolithStreamed,
		size:  mediumBlob,
	},
	{
		name:  "Push Monolith 100MB",
		tfunc: PushMonolithStreamed,
		size:  largeBlob,
	},
	{
		name:  "Push Chunk Streamed 1MB",
		tfunc: PushChunkStreamed,
		size:  smallBlob,
	},
	{
		name:  "Push Chunk Streamed 10MB",
		tfunc: PushChunkStreamed,
		size:  mediumBlob,
	},
	{
		name:  "Push Chunk Streamed 100MB",
		tfunc: PushChunkStreamed,
		size:  largeBlob,
	},
	{
		name:  "Pull 1MB",
		tfunc: Pull,
		size:  smallBlob,
	},
	{
		name:  "Pull 10MB",
		tfunc: Pull,
		size:  mediumBlob,
	},
	{
		name:  "Pull 100MB",
		tfunc: Pull,
		size:  largeBlob,
	},
	{
		name:             "Pull Mixed 20% 1MB, 70% 10MB, 10% 100MB",
		tfunc:            Pull,
		probabilityRange: normalizeProbabilityRange([]float64{0.2, 0.7, 0.1}),
		mixedSize:        true,
	},
	{
		name:             "Push Monolith Mixed 20% 1MB, 70% 10MB, 10% 100MB",
		tfunc:            PushMonolithStreamed,
		probabilityRange: normalizeProbabilityRange([]float64{0.2, 0.7, 0.1}),
		mixedSize:        true,
	},
	{
		name:             "Push Chunk Mixed 33% 1MB, 33% 10MB, 33% 100MB",
		tfunc:            PushChunkStreamed,
		probabilityRange: normalizeProbabilityRange([]float64{0.33, 0.33, 0.33}),
		mixedSize:        true,
	},
	{
		name:             "Pull 75% and Push 25% Mixed 1MB",
		tfunc:            MixedPullAndPush,
		size:             smallBlob,
		mixedType:        true,
		probabilityRange: normalizeProbabilityRange([]float64{0.75, 0.25}),
	},
	{
		name:             "Pull 75% and Push 25% Mixed 10MB",
		tfunc:            MixedPullAndPush,
		size:             mediumBlob,
		mixedType:        true,
		probabilityRange: normalizeProbabilityRange([]float64{0.75, 0.25}),
	},
	{
		name:             "Pull 75% and Push 25% Mixed 100MB",
		tfunc:            MixedPullAndPush,
		size:             largeBlob,
		mixedType:        true,
		probabilityRange: normalizeProbabilityRange([]float64{0.75, 0.25}),
	},
}

func Perf(
	workdir, url, auth, repo string,
	concurrency int, requests int,
	outFmt string, srcIPs string, srcCIDR string,
) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	// logging
	log.SetFlags(0)
	log.SetOutput(tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent))

	// initialize test data
	setup(workdir)
	defer teardown(workdir)

	// common header
	log.Printf("Registry URL:\t%s", url)
	log.Printf("\n")
	log.Printf("Concurrency Level:\t%v", concurrency)
	log.Printf("Total requests:\t%v", requests)
	log.Printf("Working dir:\t%v", workdir)
	log.Printf("\n")

	zbError := false

	var err error

	// get host ips from command line to make requests from
	var ips []string
	if len(srcIPs) > 0 {
		ips = strings.Split(srcIPs, ",")
	} else if len(srcCIDR) > 0 {
		ips, err = getIPsFromCIDR(srcCIDR, maxSourceIPs)
		if err != nil {
			log.Fatal(err) //nolint: gocritic
		}
	}

	for _, tconfig := range testSuite {
		statsCh := make(chan statsRecord, requests)

		var wg sync.WaitGroup

		summary := newStatsSummary(tconfig.name)

		start := time.Now()

		for c := 0; c < concurrency; c++ {
			// parallelize with clients
			wg.Add(1)

			go func() {
				defer wg.Done()

				httpClient, err := getRandomClientIPs(auth, url, ips)
				if err != nil {
					log.Fatal(err)
				}

				_ = tconfig.tfunc(workdir, url, repo, requests/concurrency, tconfig, statsCh, httpClient)
			}()
		}
		wg.Wait()

		summary.total = time.Since(start)
		summary.rps = float32(requests) / float32(summary.total.Seconds())

		if tconfig.mixedSize {
			summary.mixedSize = true
		}

		if tconfig.mixedType {
			summary.mixedType = true
		}

		for count := 0; count < requests; count++ {
			record := <-statsCh
			updateStats(&summary, record)
		}

		sort.Sort(Durations(summary.latencies))

		printStats(requests, &summary, outFmt)

		if summary.errors != 0 && !zbError {
			zbError = true
		}
	}

	if outFmt == cicdFmt {
		jsonOut, err := json.Marshal(cicdSummary)
		if err != nil {
			log.Fatal(err) // file closed on exit
		}

		if err := ioutil.WriteFile(fmt.Sprintf("%s.json", outFmt), jsonOut, defaultFilePerms); err != nil {
			log.Fatal(err)
		}
	}

	if zbError {
		os.Exit(1)
	}
}

// getRandomClientIPs returns a resty client with a random bind address from ips slice.
func getRandomClientIPs(auth string, url string, ips []string) (*resty.Client, error) {
	client := resty.New()

	if auth != "" {
		creds := strings.Split(auth, ":")
		client.SetBasicAuth(creds[0], creds[1])
	}

	// get random ip client
	if len(ips) != 0 {
		// get random number
		nBig, err := crand.Int(crand.Reader, big.NewInt(int64(len(ips))))
		if err != nil {
			return nil, err
		}

		// get random ip
		ip := ips[nBig.Int64()]

		// set ip in transport
		localAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:0", ip))
		if err != nil {
			return nil, err
		}

		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   httpTimeout,
				KeepAlive: httpKeepAlive,
				LocalAddr: localAddr,
			}).DialContext,
			TLSHandshakeTimeout: TLSHandshakeTimeout,
		}

		client.SetTransport(transport)
	}

	parsedURL, err := urlparser.Parse(url)
	if err != nil {
		log.Fatal(err)
	}

	// nolint: gosec
	if parsedURL.Scheme == secureProtocol {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	return client, nil
}

// getIPsFromCIDR returns a list of ips given a cidr.
func getIPsFromCIDR(cidr string, maxIPs int) ([]string, error) {
	// nolint:varnamelen
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip) && len(ips) < maxIPs; inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// https://go.dev/play/p/sdzcMvZYWnc
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
