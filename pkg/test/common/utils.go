package common

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
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

	return fmt.Sprint(port)
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
			return fmt.Errorf("stopped after %d redirects", noOfRedirect) //nolint: goerr113
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
