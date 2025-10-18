package common

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phayes/freeport"
	"gopkg.in/resty.v1"
)

const (
	BaseURL               = "http://127.0.0.1:%s"
	BaseSecureURL         = "https://127.0.0.1:%s"
	SleepTime             = 100 * time.Millisecond
	AuthorizationAllRepos = "**"
)

type isser interface {
	Is(string) bool
}

// Index returns the index of the first occurrence of name in s,
// or -1 if not present.
func Index[E isser](s []E, name string) int {
	for i, v := range s {
		if v.Is(name) {
			return i
		}
	}

	return -1
}

// Contains reports whether name is present in s.
func Contains[E isser](s []E, name string) bool {
	return Index(s, name) >= 0
}

func Location(baseURL string, resp *resty.Response) string {
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

type Controller interface {
	Init() error
	Run() error
	Shutdown()
	GetPort() int
}

type ControllerManager struct {
	controller Controller
}

func (cm *ControllerManager) RunServer() {
	// Useful to be able to call in the same goroutine for testing purposes
	if err := cm.controller.Run(); !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func (cm *ControllerManager) StartServer() {
	if err := cm.controller.Init(); err != nil {
		panic(err)
	}

	go func() {
		cm.RunServer()
	}()
}

func (cm *ControllerManager) StopServer() {
	cm.controller.Shutdown()
}

func (cm *ControllerManager) WaitServerToBeReady(port string) {
	url := GetBaseURL(port)
	WaitTillServerReady(url)
}

func (cm *ControllerManager) StartAndWait(port string) {
	cm.StartServer()

	url := GetBaseURL(port)
	WaitTillServerReady(url)
}

func NewControllerManager(controller Controller) ControllerManager {
	cm := ControllerManager{
		controller: controller,
	}

	return cm
}

func WaitTillServerReady(url string) {
	for {
		_, err := resty.R().Get(url)
		if err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

func WaitTillTrivyDBDownloadStarted(rootDir string) {
	for {
		if _, err := os.Stat(path.Join(rootDir, "_trivy", "db", "trivy.db")); err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

func GetFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return strconv.Itoa(port)
}

// GetFreePorts returns multiple unique free ports, useful for cluster tests.
func GetFreePorts(count int) []string {
	// Use the freeport library's GetFreePorts function which guarantees uniqueness
	intPorts, err := freeport.GetFreePorts(count)
	if err != nil {
		panic(err)
	}

	// Convert to strings
	ports := make([]string, count)
	for i, port := range intPorts {
		ports[i] = strconv.Itoa(port)
	}

	return ports
}

func GetBaseURL(port string) string {
	return fmt.Sprintf(BaseURL, port)
}

func GetSecureBaseURL(port string) string {
	return fmt.Sprintf(BaseSecureURL, port)
}

func CustomRedirectPolicy(noOfRedirect int) resty.RedirectPolicy {
	return resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if len(via) >= noOfRedirect {
			return fmt.Errorf("stopped after %d redirects", noOfRedirect) //nolint: err113
		}

		for key, val := range via[len(via)-1].Header {
			req.Header[key] = val
		}

		respCookies := req.Response.Cookies()
		for _, cookie := range respCookies {
			req.AddCookie(cookie)
		}

		return nil
	})
}

// Generates a random string with length 10 from lower case & upper case characters and
// a seed that can be logged in tests (if test fails, you can reconstruct random string).
func GenerateRandomString() (string, int64) {
	seed := time.Now().UnixNano()
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(seed))
	charset := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomBytes := make([]byte, 10)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes), seed
}

// Generates a random string with length 10 from lower case characters and digits and
// a seed that can be logged in tests (if test fails, you can reconstruct random string).
func GenerateRandomName() (string, int64) {
	seed := time.Now().UnixNano()
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(seed))
	charset := "abcdefghijklmnopqrstuvwxyz" + "0123456789"

	randomBytes := make([]byte, 10)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes), seed
}

func AccumulateField[T any, R any](list []T, accFunc func(T) R) []R {
	result := make([]R, 0, len(list))

	for i := range list {
		result = append(result, accFunc(list[i]))
	}

	return result
}

func ContainSameElements[T comparable](list1, list2 []T) bool {
	if len(list1) != len(list2) {
		return false
	}

	count1 := map[T]int{}
	count2 := map[T]int{}

	for i := range list1 {
		count1[list1[i]]++
		count2[list2[i]]++
	}

	for key := range count1 {
		if count1[key] != count2[key] {
			return false
		}
	}

	return true
}

// ThreadSafeLogBuffer is a thread-safe wrapper around bytes.Buffer for concurrent log capture.
type ThreadSafeLogBuffer struct {
	buffer *bytes.Buffer
	mutex  sync.RWMutex
}

// NewThreadSafeLogBuffer creates a new thread-safe log buffer.
func NewThreadSafeLogBuffer() *ThreadSafeLogBuffer {
	return &ThreadSafeLogBuffer{
		buffer: &bytes.Buffer{},
	}
}

// Write implements io.Writer interface with thread safety.
func (tsb *ThreadSafeLogBuffer) Write(p []byte) (int, error) {
	tsb.mutex.Lock()
	defer tsb.mutex.Unlock()

	return tsb.buffer.Write(p)
}

// String returns the buffer contents as a string with thread safety.
func (tsb *ThreadSafeLogBuffer) String() string {
	tsb.mutex.RLock()
	defer tsb.mutex.RUnlock()

	return tsb.buffer.String()
}

// WaitForLogMessages waits for a specific number of log messages to appear in the log buffer
// within the given timeout. This is useful for verifying goroutine termination or other
// asynchronous operations that log specific messages.
//
// Parameters:
//   - logBuffer: A ThreadSafeLogBuffer that captures log output
//   - message: The log message to search for (e.g., "htpasswd watcher terminating...")
//   - minCount: Minimum number of occurrences to wait for
//   - timeout: Maximum time to wait for the messages
//
// Returns:
//   - true if at least minCount messages were found within the timeout
//   - false if the timeout was reached before finding enough messages
func WaitForLogMessages(logBuffer *ThreadSafeLogBuffer, message string, minCount int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		logOutput := logBuffer.String()
		actualCount := strings.Count(logOutput, message)

		if actualCount >= minCount {
			return true
		}

		time.Sleep(10 * time.Millisecond)
	}

	return false
}

// CreateLogCapturingWriter creates a multi-writer that captures log output to a thread-safe buffer
// while also writing to the original writer (typically os.Stdout). This is useful for
// tests that need to programmatically verify log messages.
//
// Parameters:
//   - originalWriter: The original writer to continue writing to (e.g., os.Stdout)
//
// Returns:
//   - A ThreadSafeLogBuffer that captures the log output
//   - An io.Writer that writes to both the original writer and the buffer
func CreateLogCapturingWriter(originalWriter io.Writer) (*ThreadSafeLogBuffer, io.Writer) {
	logBuffer := NewThreadSafeLogBuffer()
	multiWriter := io.MultiWriter(originalWriter, logBuffer)

	return logBuffer, multiWriter
}
