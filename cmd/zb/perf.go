package main

import (
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	urlparser "net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	jsoniter "github.com/json-iterator/go"
	godigest "github.com/opencontainers/go-digest"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api/constants"
)

const (
	KiB                  = 1 * 1024
	MiB                  = 1 * KiB * 1024
	GiB                  = 1 * MiB * 1024
	defaultDirPerms      = 0o700
	defaultFilePerms     = 0o600
	defaultSchemaVersion = 2
	smallBlob            = 1 * MiB
	mediumBlob           = 10 * MiB
	largeBlob            = 100 * MiB
	superLargeBlob       = 1 * GiB
	cicdFmt              = "ci-cd"
	secureProtocol       = "https"
	httpKeepAlive        = 30 * time.Second
	maxSourceIPs         = 1000
	httpTimeout          = 30 * time.Second
	TLSHandshakeTimeout  = 10 * time.Second
)

//nolint:gochecknoglobals
var blobHash map[string]godigest.Digest = map[string]godigest.Digest{}

//nolint:gochecknoglobals // used only in this test
var statusRequests sync.Map

func setup(workingDir string, sizesToPrepare []int) {
	_ = os.MkdirAll(workingDir, defaultDirPerms)

	const rndPageSize = 4 * KiB

	for _, size := range sizesToPrepare {
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
			log.Fatal(err) //nolint:gocritic // file closed on exit
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
	errorCount           int
	errors               map[string]int
	manifestHeadTTFBs    []time.Duration
	manifestGetTTFBs     []time.Duration
	configTTFBs          []time.Duration
	layerTTFBs           []time.Duration
}

func newStatsSummary(name string) statsSummary {
	summary := statsSummary{
		name:       name,
		min:        -1,
		max:        -1,
		statusHist: make(map[string]int),
		mixedSize:  false,
		mixedType:  false,
		errors:     make(map[string]int),
	}

	return summary
}

type perTagTiming struct {
	manifestHeadTTFB time.Duration
	manifestGetTTFB  time.Duration
	configTTFB       time.Duration
	layersTTFB       []time.Duration
}

type statsRecord struct {
	latency    time.Duration
	statusCode int
	isConnFail bool
	isErr      bool
	err        error

	// sync test specific items
	timings []perTagTiming
}

func updateStats(summary *statsSummary, record statsRecord) {
	if record.isConnFail || record.isErr {
		summary.errorCount++
	}

	if record.err != nil {
		summary.errors[record.err.Error()] += 1
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

	for _, timing := range record.timings {
		if timing.manifestHeadTTFB > 0 {
			summary.manifestHeadTTFBs = append(summary.manifestHeadTTFBs, timing.manifestHeadTTFB)
		}

		if timing.manifestGetTTFB > 0 {
			summary.manifestGetTTFBs = append(summary.manifestGetTTFBs, timing.manifestGetTTFB)
		}

		if timing.configTTFB > 0 {
			summary.configTTFBs = append(summary.configTTFBs, timing.configTTFB)
		}

		summary.layerTTFBs = append(summary.layerTTFBs, timing.layersTTFB...)
	}
}

type cicdTestSummary struct {
	Name  string `json:"name"`
	Unit  string `json:"unit"`
	Value any    `json:"value"`
	Range string `json:"range,omitempty"`
}

type manifestStruct struct {
	manifestHash       map[string]string
	manifestBySizeHash map[int](map[string]string)
}

func printStats(requests int, summary *statsSummary) {
	log.Printf("============\n")
	log.Printf("Test name:\t%s", summary.name)
	log.Printf("Time taken for tests:\t%v", summary.total)
	log.Printf("Requests per second:\t%v", summary.rps)
	log.Printf("Complete requests:\t%v", requests-summary.errorCount)
	log.Printf("Failed requests:\t%v", summary.errorCount)

	for errStr, count := range summary.errors {
		log.Printf("Error %s count:\t%d", errStr, count)
	}

	log.Printf("\n")

	if summary.mixedSize {
		current := loadOrStore(&statusRequests, "1MB", 0)
		log.Printf("1MB:\t%v", current)

		current = loadOrStore(&statusRequests, "10MB", 0)
		log.Printf("10MB:\t%v", current)

		current = loadOrStore(&statusRequests, "100MB", 0)
		log.Printf("100MB:\t%v", current)

		log.Printf("\n")
	}

	if summary.mixedType {
		pull := loadOrStore(&statusRequests, "Pull", 0)
		log.Printf("Pull:\t%v", pull)

		push := loadOrStore(&statusRequests, "Push", 0)
		log.Printf("Push:\t%v", push)

		log.Printf("\n")
	}

	for k, v := range summary.statusHist {
		log.Printf("%s responses:\t%v", k, v)
	}

	log.Printf("\n")
	sort.Sort(Durations(summary.latencies))
	log.Printf("min: %v", summary.min)
	log.Printf("max: %v", summary.max)
	log.Printf("%s:\t%v", "p50", summary.latencies[requests/2])
	log.Printf("%s:\t%v", "p75", summary.latencies[requests*3/4])
	log.Printf("%s:\t%v", "p90", summary.latencies[requests*9/10])
	log.Printf("%s:\t%v", "p99", summary.latencies[requests*99/100])
	log.Printf("\n")

	if len(summary.manifestHeadTTFBs) > 0 {
		sort.Sort(Durations(summary.manifestHeadTTFBs))
		n := len(summary.manifestHeadTTFBs)
		log.Printf("Manifest HEAD TTFB p50:\t%v", summary.manifestHeadTTFBs[n/2])
		log.Printf("Manifest HEAD TTFB p75:\t%v", summary.manifestHeadTTFBs[n*3/4])
		log.Printf("Manifest HEAD TTFB p90:\t%v", summary.manifestHeadTTFBs[n*9/10])
		log.Printf("Manifest HEAD TTFB p99:\t%v", summary.manifestHeadTTFBs[n*99/100])
		log.Printf("\n")
	}

	if len(summary.manifestGetTTFBs) > 0 {
		sort.Sort(Durations(summary.manifestGetTTFBs))
		n := len(summary.manifestGetTTFBs)
		log.Printf("Manifest GET TTFB p50:\t%v", summary.manifestGetTTFBs[n/2])
		log.Printf("Manifest GET TTFB p75:\t%v", summary.manifestGetTTFBs[n*3/4])
		log.Printf("Manifest GET TTFB p90:\t%v", summary.manifestGetTTFBs[n*9/10])
		log.Printf("Manifest GET TTFB p99:\t%v", summary.manifestGetTTFBs[n*99/100])
		log.Printf("\n")
	}

	if len(summary.configTTFBs) > 0 {
		sort.Sort(Durations(summary.configTTFBs))
		n := len(summary.configTTFBs)
		log.Printf("Config TTFB p50:\t%v", summary.configTTFBs[n/2])
		log.Printf("Config TTFB p75:\t%v", summary.configTTFBs[n*3/4])
		log.Printf("Config TTFB p90:\t%v", summary.configTTFBs[n*9/10])
		log.Printf("Config TTFB p99:\t%v", summary.configTTFBs[n*99/100])
		log.Printf("\n")
	}

	if len(summary.layerTTFBs) > 0 {
		sort.Sort(Durations(summary.layerTTFBs))
		n := len(summary.layerTTFBs)
		log.Printf("Layer TTFB p50:\t%v", summary.layerTTFBs[n/2])
		log.Printf("Layer TTFB p75:\t%v", summary.layerTTFBs[n*3/4])
		log.Printf("Layer TTFB p90:\t%v", summary.layerTTFBs[n*9/10])
		log.Printf("Layer TTFB p99:\t%v", summary.layerTTFBs[n*99/100])
		log.Printf("\n")
	}
}

// test suites/funcs.

type testFunc func(
	config testConfig,
	suiteCfg testSuiteCfg,
	statsCh chan statsRecord,
	client *resty.Client,
) error

//nolint:gosec
func GetCatalog(
	config testConfig,
	suiteCfg testSuiteCfg,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	var err error

	statusRequests = sync.Map{}

	for range suiteCfg.requests {
		// Push random blob
		_, repos, err = pushMonolithImage(suiteCfg.workDir, suiteCfg.targetServerURL, suiteCfg.repo, repos, config, client)
		if err != nil {
			return err
		}
	}

	for range suiteCfg.requests {
		func() {
			start := time.Now()

			var isConnFail, isErr bool

			var statusCode int

			var latency time.Duration

			var err error

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

			// send request and get response
			resp, err := client.R().Get(suiteCfg.targetServerURL + constants.RoutePrefix + constants.ExtCatalogPrefix)

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

	// clean up
	if !suiteCfg.skipCleanup {
		err = deleteTestRepo(repos, suiteCfg.targetServerURL, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func PushMonolithStreamed(
	config testConfig,
	suiteCfg testSuiteCfg,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	if config.mixedSize {
		statusRequests = sync.Map{}
	}

	for count := range suiteCfg.requests {
		repos = pushMonolithAndCollect(suiteCfg.workDir, suiteCfg.targetServerURL, suiteCfg.repo, count,
			repos, config, client, statsCh)
	}

	// clean up
	if !suiteCfg.skipCleanup {
		err := deleteTestRepo(repos, suiteCfg.targetServerURL, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func PushChunkStreamed(
	config testConfig,
	suiteCfg testSuiteCfg,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	if config.mixedSize {
		statusRequests = sync.Map{}
	}

	for count := range suiteCfg.requests {
		repos = pushChunkAndCollect(suiteCfg.workDir, suiteCfg.targetServerURL, suiteCfg.repo, count,
			repos, config, client, statsCh)
	}

	// clean up
	if !suiteCfg.skipCleanup {
		err := deleteTestRepo(repos, suiteCfg.targetServerURL, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func Pull(
	config testConfig,
	suiteCfg testSuiteCfg,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	var manifestHash map[string]string

	manifestBySizeHash := make(map[int](map[string]string))

	if config.mixedSize {
		statusRequests = sync.Map{}
	}

	pushTargetURL := suiteCfg.targetServerURL

	if suiteCfg.syncTest {
		pushTargetURL = suiteCfg.upstreamServerURL
	}

	if config.mixedSize {
		var manifestBySize map[string]string

		smallSizeIdx := 0
		mediumSizeIdx := 1
		largeSizeIdx := 2

		config.size = smallBlob

		// Push small blob
		manifestBySize, repos, err := pushMonolithImage(
			suiteCfg.workDir, pushTargetURL, suiteCfg.repo, repos, config, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[smallSizeIdx] = manifestBySize

		config.size = mediumBlob

		// Push medium blob
		manifestBySize, repos, err = pushMonolithImage(
			suiteCfg.workDir, pushTargetURL, suiteCfg.repo, repos, config, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[mediumSizeIdx] = manifestBySize

		config.size = largeBlob

		// Push large blob
		//nolint: ineffassign, staticcheck, wastedassign
		manifestBySize, repos, err = pushMonolithImage(
			suiteCfg.workDir, pushTargetURL, suiteCfg.repo, repos, config, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[largeSizeIdx] = manifestBySize
	} else {
		// Push blob given size
		var err error

		manifestHash, repos, err = pushMonolithImage(
			suiteCfg.workDir, pushTargetURL, suiteCfg.repo, repos, config, client)
		if err != nil {
			return err
		}
	}

	manifestItem := manifestStruct{
		manifestHash:       manifestHash,
		manifestBySizeHash: manifestBySizeHash,
	}

	// download image
	for range suiteCfg.requests {
		repos = pullAndCollect(suiteCfg.targetServerURL, repos, manifestItem, config, client, statsCh)
	}

	// clean up
	if !suiteCfg.skipCleanup {
		err := deleteTestRepo(repos, suiteCfg.targetServerURL, client)
		if err != nil {
			return err
		}

		if suiteCfg.syncTest {
			err := deleteTestRepo(repos, suiteCfg.upstreamServerURL, client)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func MixedPullAndPush(
	config testConfig,
	suiteCfg testSuiteCfg,
	statsCh chan statsRecord,
	client *resty.Client,
) error {
	var repos []string

	statusRequests = sync.Map{}

	// Push blob given size
	manifestHash, repos, err := pushMonolithImage(
		suiteCfg.workDir, suiteCfg.targetServerURL, suiteCfg.repo, repos, config, client)
	if err != nil {
		return err
	}

	manifestItem := manifestStruct{
		manifestHash: manifestHash,
	}

	for count := range suiteCfg.requests {
		idx := flipFunc(config.probabilityRange)

		readTestIdx := 0
		writeTestIdx := 1

		switch idx {
		case readTestIdx:
			repos = pullAndCollect(suiteCfg.targetServerURL, repos, manifestItem, config, client, statsCh)
			current := loadOrStore(&statusRequests, "Pull", 0)
			statusRequests.Store("Pull", current+1)
		case writeTestIdx:
			repos = pushMonolithAndCollect(
				suiteCfg.workDir, suiteCfg.targetServerURL, suiteCfg.repo, count, repos, config, client, statsCh)
			current := loadOrStore(&statusRequests, "Push", 0)
			statusRequests.Store("Pull", current+1)
		}
	}

	// clean up
	if !suiteCfg.skipCleanup {
		err = deleteTestRepo(repos, suiteCfg.targetServerURL, client)
		if err != nil {
			return err
		}
	}

	return nil
}

// test driver.

type testSuiteCfg struct {
	workDir           string
	targetServerURL   string
	upstreamServerURL string
	repo              string
	requests          int
	skipCleanup       bool
	syncTest          bool
}

type testConfig struct {
	name  string
	tfunc testFunc
	// test-specific params
	size                 int
	probabilityRange     []float64
	mixedSize, mixedType bool
	syncTest             bool
}

var testSuite = []testConfig{ //nolint:gochecknoglobals // used only in this test
	{
		name:             "Get Catalog",
		tfunc:            GetCatalog,
		probabilityRange: normalizeProbabilityRange([]float64{0.7, 0.2, 0.1}),
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
	{
		name:     "On-demand Sync 100MB",
		tfunc:    Pull,
		size:     largeBlob,
		syncTest: true,
	},
	{
		name:     "On-demand Sync 1GB",
		tfunc:    Pull,
		size:     superLargeBlob,
		syncTest: true,
	},
}

// ListTests logs the available test names with one on each line.
// When testRegex is not nil, only the tests that match the regex are listed.
func ListTests(testRegex *regexp.Regexp) {
	log.SetFlags(0)
	log.SetOutput(tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent))

	for _, tconfig := range testSuite {
		if testRegex != nil && !testRegex.MatchString(tconfig.name) {
			continue
		}

		log.Println(tconfig.name)
	}
}

// fatalWithCleanup calls teardown then logs fatal, ensuring cleanup happens before exit.
func fatalWithCleanup(syncObj *sync.Once, workdir string, err error) {
	syncObj.Do(func() {
		teardown(workdir)
	})
	log.Fatal(err)
}

func Perf(
	workdir, url, auth, repo string,
	concurrency int, requests int,
	outFmt string, srcIPs string, srcCIDR string, skipCleanup bool,
	testRegex *regexp.Regexp, upstreamServerURL string,
) {
	// logging
	log.SetFlags(0)
	log.SetOutput(tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent))

	// teardown sync object to ensure cleanup happens on fatal or at the end of tests
	var teardownOnce sync.Once

	// common header
	log.Printf("Registry URL:\t%s\n", url)
	if upstreamServerURL != "" {
		log.Printf("Upstream Registry URL:\t%s\n", upstreamServerURL)
	}
	log.Printf("Concurrency Level:\t%v", concurrency)
	log.Printf("Total requests:\t%v", requests)

	if workdir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal("unable to get current working dir")
		}

		log.Printf("Working dir:\t%v", cwd)
	} else {
		log.Printf("Working dir:\t%v", workdir)
	}

	log.Printf("\n")

	// pre-filter tests to know which data to initialize
	fileSizesMap := map[int]struct{}{}
	testsToRun := []testConfig{}

	for _, tconfig := range testSuite {
		if testRegex != nil && !testRegex.MatchString(tconfig.name) {
			log.Printf("Skipping test %s\n", tconfig.name)

			continue
		}

		if tconfig.syncTest && upstreamServerURL == "" {
			log.Printf("Skipping test %s\n", tconfig.name)

			continue
		}

		testsToRun = append(testsToRun, tconfig)

		if tconfig.size == 0 {
			sizes := []int{smallBlob, mediumBlob, largeBlob}
			for _, size := range sizes {
				fileSizesMap[size] = struct{}{}
			}
		} else if tconfig.size != 0 {
			fileSizesMap[tconfig.size] = struct{}{}
		}
	}

	// initialize test data
	log.Printf("Preparing test data ...\n")

	sizesToPrepare := []int{}
	for size := range fileSizesMap {
		sizesToPrepare = append(sizesToPrepare, size)
	}

	setup(workdir, sizesToPrepare)

	log.Printf("Starting tests ...\n")

	var err error

	zbError := false

	// get host ips from command line to make requests from
	var ips []string
	if len(srcIPs) > 0 {
		ips = strings.Split(srcIPs, ",")
	} else if len(srcCIDR) > 0 {
		ips, err = getIPsFromCIDR(srcCIDR, maxSourceIPs)
		if err != nil {
			fatalWithCleanup(&teardownOnce, workdir, err)
		}
	}

	statsSummaries := []statsSummary{}

	for _, tconfig := range testsToRun {
		statsCh := make(chan statsRecord, requests)

		var wg sync.WaitGroup

		summary := newStatsSummary(tconfig.name)

		start := time.Now()

		for range concurrency {
			// parallelize with clients
			wg.Go(func() {
				httpClient, err := getRandomClientIPs(auth, url, ips)
				if err != nil {
					fatalWithCleanup(&teardownOnce, workdir, err)
				}

				suiteConfig := testSuiteCfg{
					workDir:           workdir,
					targetServerURL:   url,
					upstreamServerURL: upstreamServerURL,
					repo:              repo,
					requests:          requests / concurrency,
					skipCleanup:       skipCleanup,
					syncTest:          tconfig.syncTest,
				}

				if tFuncErr := tconfig.tfunc(tconfig, suiteConfig, statsCh, httpClient); tFuncErr != nil {
					fatalWithCleanup(&teardownOnce, workdir, tFuncErr)
				}
			})
		}

		wg.Wait()

		summary.total = time.Since(start)
		summary.rps = float32(requests) / float32(summary.total.Seconds())

		if tconfig.mixedSize || tconfig.size == 0 {
			summary.mixedSize = true
		}

		if tconfig.mixedType {
			summary.mixedType = true
		}

		for range requests {
			record := <-statsCh
			updateStats(&summary, record)
		}

		printStats(requests, &summary)
		statsSummaries = append(statsSummaries, summary)

		if summary.errorCount != 0 && !zbError {
			zbError = true
		}
	}

	if err = outputTestResults(statsSummaries, outFmt); err != nil {
		fatalWithCleanup(&teardownOnce, workdir, err)
	}

	// Cleanup before exit (sync.Once ensures it only runs once, even if fatalWithCleanup was called)
	teardownOnce.Do(func() {
		teardown(workdir)
	})

	if zbError {
		os.Exit(1)
	}
}

// outputTestResults outputs the test results in the specified format.
// If the format is "ci-cd", it writes the results to a JSON file.
func outputTestResults(summary []statsSummary, outFmt string) error {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	if outFmt == cicdFmt {
		cicdSummary := []cicdTestSummary{}

		for _, s := range summary {
			cicdSummary = append(cicdSummary,
				cicdTestSummary{
					Name:  s.name,
					Unit:  "requests per sec",
					Value: s.rps,
					Range: "3",
				},
			)
		}

		jsonOut, err := json.Marshal(cicdSummary)
		if err != nil {
			return err
		}

		if err := os.WriteFile(outFmt+".json", jsonOut, defaultFilePerms); err != nil {
			return err
		}
	}

	return nil
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
		localAddr, err := net.ResolveTCPAddr("tcp", ip+":0")
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

	//nolint: gosec
	if parsedURL.Scheme == secureProtocol {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	return client, nil
}

// getIPsFromCIDR returns a list of ips given a cidr.
func getIPsFromCIDR(cidr string, maxIPs int) ([]string, error) {
	//nolint:varnamelen
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
