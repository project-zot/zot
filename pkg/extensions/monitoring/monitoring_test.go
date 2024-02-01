//go:build metrics
// +build metrics

package monitoring_test

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/scheduler"
	common "zotregistry.dev/zot/pkg/storage/common"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
)

func TestExtensionMetrics(t *testing.T) {
	Convey("Make a new controller with explicitly enabled metrics", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		rootDir := t.TempDir()

		conf.Storage.RootDirectory = rootDir
		conf.Extensions = &extconf.ExtensionConfig{}
		enabled := true
		conf.Extensions.Metrics = &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &enabled},
			Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
		}

		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// improve code coverage
		ctlr.Metrics.SendMetric(baseURL)
		ctlr.Metrics.ForceSendMetric(baseURL)

		So(ctlr.Metrics.IsEnabled(), ShouldBeTrue)
		So(ctlr.Metrics.ReceiveMetrics(), ShouldBeNil)

		monitoring.ObserveHTTPRepoLatency(ctlr.Metrics,
			"/v2/alpine/blobs/uploads/299148f0-0e32-4830-90d2-a3fa744137d9", time.Millisecond)
		monitoring.IncDownloadCounter(ctlr.Metrics, "alpine")
		monitoring.IncUploadCounter(ctlr.Metrics, "alpine")

		srcStorageCtlr := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)
		err := WriteImageToFileSystem(CreateDefaultImage(), "alpine", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		monitoring.SetStorageUsage(ctlr.Metrics, rootDir, "alpine")

		monitoring.ObserveStorageLockLatency(ctlr.Metrics, time.Millisecond, rootDir, "RWLock")

		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		respStr := string(resp.Body())
		So(respStr, ShouldContainSubstring, "zot_repo_downloads_total{repo=\"alpine\"} 1")
		So(respStr, ShouldContainSubstring, "zot_repo_uploads_total{repo=\"alpine\"} 1")
		So(respStr, ShouldContainSubstring, "zot_repo_storage_bytes{repo=\"alpine\"}")
		So(respStr, ShouldContainSubstring, "zot_storage_lock_latency_seconds_bucket")
		So(respStr, ShouldContainSubstring, "zot_storage_lock_latency_seconds_sum")
		So(respStr, ShouldContainSubstring, "zot_storage_lock_latency_seconds_bucket")
	})
	Convey("Make a new controller with disabled metrics extension", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		conf.Storage.RootDirectory = t.TempDir()
		conf.Extensions = &extconf.ExtensionConfig{}
		var disabled bool
		conf.Extensions.Metrics = &extconf.MetricsConfig{BaseConfig: extconf.BaseConfig{Enable: &disabled}}

		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		So(ctlr.Metrics.IsEnabled(), ShouldBeFalse)

		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestMetricsAuthentication(t *testing.T) {
	Convey("test metrics without authentication and metrics enabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// metrics endpoint not available
		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
	Convey("test metrics without authentication and with metrics enabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		enabled := true
		metricsConfig := &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &enabled},
			Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Metrics: metricsConfig,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// without auth set metrics endpoint is available
		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
	Convey("test metrics with authentication and metrics enabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		username := generateRandomString()
		password := generateRandomString()
		metricsuser := generateRandomString()
		metricspass := generateRandomString()
		content := test.GetCredString(username, password) + "\n" + test.GetCredString(metricsuser, metricspass)
		htpasswdPath := test.MakeHtpasswdFileFromString(content)
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		enabled := true
		metricsConfig := &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &enabled},
			Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Metrics: metricsConfig,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// without credentials
		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// with wrong credentials
		resp, err = resty.R().SetBasicAuth("atacker", "wrongpassword").Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// authenticated users
		resp, err = resty.R().SetBasicAuth(username, password).Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().SetBasicAuth(metricsuser, metricspass).Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestMetricsAuthorization(t *testing.T) {
	const AuthorizationAllRepos = "**"

	Convey("Make a new controller with auth & metrics enabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		username := generateRandomString()
		password := generateRandomString()
		metricsuser := generateRandomString()
		metricspass := generateRandomString()
		content := test.GetCredString(username, password) + "\n" + test.GetCredString(metricsuser, metricspass)
		htpasswdPath := test.MakeHtpasswdFileFromString(content)
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		enabled := true
		metricsConfig := &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &enabled},
			Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Metrics: metricsConfig,
		}

		Convey("with basic auth: no metrics users in accessControl", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					Users: []string{},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// authenticated but not authorized user should not have access to/metrics
			client := resty.New()
			client.SetBasicAuth(username, password)
			resp, err := client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// authenticated but not authorized user should not have access to/metrics
			client.SetBasicAuth(metricsuser, metricspass)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})
		Convey("with basic auth: metrics users in accessControl", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					Users: []string{metricsuser},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// authenticated but not authorized user should not have access to/metrics
			client := resty.New()
			client.SetBasicAuth(username, password)
			resp, err := client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// authenticated & authorized user should have access to/metrics
			client.SetBasicAuth(metricsuser, metricspass)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
		Convey("with basic auth: with anonymousPolicy in accessControl", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					Users: []string{metricsuser},
				},
				Repositories: config.Repositories{
					AuthorizationAllRepos: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{},
								Actions: []string{},
							},
						},
						AnonymousPolicy: []string{"read"},
						DefaultPolicy:   []string{},
					},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated clients should not have access to /metrics
			resp, err := resty.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// unauthenticated clients should not have access to /metrics
			resp, err = resty.R().SetBasicAuth("hacker", "trywithwrongpass").Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// authenticated but not authorized user should not have access to/metrics
			client := resty.New()
			client.SetBasicAuth(username, password)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// authenticated & authorized user should have access to/metrics
			client.SetBasicAuth(metricsuser, metricspass)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
		Convey("with basic auth: with adminPolicy in accessControl", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					Users: []string{metricsuser},
				},
				Repositories: config.Repositories{
					AuthorizationAllRepos: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{},
								Actions: []string{},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{"test"},
					Groups:  []string{"admins"},
					Actions: []string{"read", "create", "update", "delete"},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated clients should not have access to /metrics
			resp, err := resty.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// unauthenticated clients should not have access to /metrics
			resp, err = resty.R().SetBasicAuth("hacker", "trywithwrongpass").Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// authenticated admin user (but not authorized) should not have access to/metrics
			client := resty.New()
			client.SetBasicAuth(username, password)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// authenticated & authorized user should have access to/metrics
			client.SetBasicAuth(metricsuser, metricspass)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
	})
}

func TestPopulateStorageMetrics(t *testing.T) {
	Convey("Start a scheduler when metrics enabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		rootDir := t.TempDir()

		conf.Storage.RootDirectory = rootDir
		conf.Extensions = &extconf.ExtensionConfig{}
		enabled := true
		conf.Extensions.Metrics = &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &enabled},
			Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
		}

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		if err != nil {
			panic(err)
		}

		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// write a couple of images
		srcStorageCtlr := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)
		err = WriteImageToFileSystem(CreateDefaultImage(), "alpine", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(CreateDefaultImage(), "busybox", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		metrics := monitoring.NewMetricsServer(true, ctlr.Log)
		sch := scheduler.NewScheduler(conf, metrics, ctlr.Log)
		sch.RunScheduler()

		generator := &common.StorageMetricsInitGenerator{
			ImgStore: ctlr.StoreController.DefaultStore,
			Metrics:  ctlr.Metrics,
			Log:      ctlr.Log,
			MaxDelay: 1, // maximum delay between jobs (each job computes repo's storage size)
		}

		sch.SubmitGenerator(generator, time.Duration(0), scheduler.LowPriority)

		// Wait for storage metrics to update
		found, err := test.ReadLogFileAndSearchString(logPath,
			"computed storage usage for repo alpine", time.Minute)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
		found, err = test.ReadLogFileAndSearchString(logPath,
			"computed storage usage for repo busybox", time.Minute)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		sch.Shutdown()
		alpineSize, err := monitoring.GetDirSize(path.Join(rootDir, "alpine"))
		So(err, ShouldBeNil)
		busyboxSize, err := monitoring.GetDirSize(path.Join(rootDir, "busybox"))
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		alpineMetric := fmt.Sprintf("zot_repo_storage_bytes{repo=\"alpine\"} %d", alpineSize)
		busyboxMetric := fmt.Sprintf("zot_repo_storage_bytes{repo=\"busybox\"} %d", busyboxSize)
		respStr := string(resp.Body())
		So(respStr, ShouldContainSubstring, alpineMetric)
		So(respStr, ShouldContainSubstring, busyboxMetric)
	})
}

func generateRandomString() string {
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomBytes := make([]byte, 10)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes)
}
