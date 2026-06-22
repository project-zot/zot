//go:build metrics

package monitoring_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	authutils "zotregistry.dev/zot/v2/pkg/test/auth"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
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

		// Write image before starting controller to avoid race condition with garbage collection
		srcStorageCtlr := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)
		err := WriteImageToFileSystem(CreateDefaultImage(), "alpine", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

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

		var disabled bool

		conf.Storage.RootDirectory = t.TempDir()
		conf.Extensions = &extconf.ExtensionConfig{}
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
		content := test.GetBcryptCredString(username, password) + "\n" + test.GetBcryptCredString(metricsuser, metricspass)

		htpasswdPath := test.MakeHtpasswdFileFromString(t, content)

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
		content := test.GetBcryptCredString(username, password) + "\n" + test.GetBcryptCredString(metricsuser, metricspass)

		htpasswdPath := test.MakeHtpasswdFileFromString(t, content)

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
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// authenticated but not authorized user should not have access to/metrics
			client.SetBasicAuth(metricsuser, metricspass)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)
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
		Convey("with basic auth: metrics.anonymousPolicy=[read] allows unauthenticated scraping", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					AnonymousPolicy: []string{"read"},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated client should be allowed to scrape /metrics
			resp, err := resty.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// wrong credentials should still be rejected at authn
			resp, err = resty.R().SetBasicAuth("hacker", "wrongpass").Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// Scrape should not be allowed for the metrics user when allowed metrics users
			// are not configured.
			metricsUserClient := resty.New()
			metricsUserClient.SetBasicAuth(metricsuser, metricspass)
			resp, err = metricsUserClient.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// Scrape should not be allowed for a valid user when allowed metrics users
			// are not configured.
			normalUserClient := resty.New()
			normalUserClient.SetBasicAuth(username, password)
			resp, err = normalUserClient.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// anonymous access to registry endpoints should remain protected
			resp, err = resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})
		Convey("with basic auth: metrics.anonymousPolicy and users list, allow permitted user", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					Users:           []string{metricsuser},
					AnonymousPolicy: []string{"read"},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated client should be allowed to scrape /metrics
			resp, err := resty.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// wrong credentials should still be rejected at authn
			resp, err = resty.R().SetBasicAuth("hacker", "wrongpass").Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// scrape should be allowed for a valid user in the metrics users list
			metricsUserClient := resty.New()
			metricsUserClient.SetBasicAuth(metricsuser, metricspass)
			resp, err = metricsUserClient.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// scrape should not be allowed for a valid user who is not in the metrics users list
			normalUserClient := resty.New()
			normalUserClient.SetBasicAuth(username, password)
			resp, err = normalUserClient.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// anonymous access to registry endpoints should remain protected
			resp, err = resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})
		Convey("with basic auth: empty metrics.anonymousPolicy blocks unauthenticated scraping", func() {
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Metrics: config.Metrics{
					AnonymousPolicy: nil,
					Users:           []string{metricsuser},
				},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated client should be blocked
			resp, err := resty.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// authorized user should still have access
			client := resty.New()
			client.SetBasicAuth(metricsuser, metricspass)
			resp, err = client.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
	})
	Convey("Make a new controller with bearer auth & metrics enabled", t, func() {
		serverCertPath, serverKeyPath := setupMetricsBearerAuthServerCerts(t)

		authTestServer := authutils.MakeAuthTestServer(serverKeyPath, "RS256", "unauthorized-repo")
		defer authTestServer.Close()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		authURL, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		conf.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    serverCertPath,
				Realm:   authTestServer.URL + "/auth/token",
				Service: authURL.Host,
			},
		}

		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{
			Metrics: &extconf.MetricsConfig{
				BaseConfig: extconf.BaseConfig{Enable: &enabled},
				Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
			},
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Metrics: config.Metrics{
				AnonymousPolicy: []string{"read"},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		Convey("with bearer auth: metrics.anonymousPolicy=[read] allows unauthenticated scraping", func() {
			// unauthenticated client should be allowed to scrape /metrics
			resp, err := resty.R().Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// invalid bearer token should still be rejected at authn
			resp, err = resty.R().SetHeader("Authorization", "Bearer invalidToken").Get(baseURL + "/metrics")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// anonymous access to registry endpoints should remain protected
			resp, err = resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})
	})
}

func TestMetricsAnonymousAccessNoAuth(t *testing.T) {
	Convey("Make a new controller with no auth and metrics.anonymousPolicy=[read]", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{
			Metrics: &extconf.MetricsConfig{
				BaseConfig: extconf.BaseConfig{Enable: &enabled},
				Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
			},
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Metrics: config.Metrics{
				AnonymousPolicy: []string{"read"},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// unauthenticated client should be allowed to scrape /metrics
		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestMetricsAnonymousPolicyNilAccessControl(t *testing.T) {
	Convey("Nil access control does not match metrics anonymous policy", t, func() {
		var accessControlConfig *config.AccessControlConfig

		So(accessControlConfig.ContainsOnlyMetricsAnonymousPolicy(), ShouldBeFalse)
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

		logFile := test.MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		logPath := logFile.Name()

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)
		ctlr.Log = log.NewLoggerWithWriter("debug", writers)

		// Write images before starting controller to avoid race condition with garbage collection
		srcStorageCtlr := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)
		err := WriteImageToFileSystem(CreateDefaultImage(), "alpine", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(CreateDefaultImage(), "busybox", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		metrics := monitoring.NewMetricsServer(true, ctlr.Log)
		sch := scheduler.NewScheduler(conf, metrics, ctlr.Log)
		sch.RunScheduler()

		generator := common.NewStorageMetricsInitGenerator(
			ctlr.StoreController.DefaultStore,
			ctlr.Metrics,
			ctlr.Log,
		)

		generator.MaxDelay = 1 // maximum delay between jobs (each job computes repo's storage size)

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

func TestGCMetrics(t *testing.T) {
	Convey("GC metrics should be emitted after garbage collection", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		rootDir := t.TempDir()
		conf.Storage.RootDirectory = rootDir
		conf.Storage.GC = false
		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Metrics = &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &enabled},
			Prometheus: &extconf.PrometheusConfig{Path: "/metrics"},
		}

		ctlr := api.NewController(conf)

		srcStorageCtlr := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)
		err := WriteImageToFileSystem(CreateDefaultImage(), "gc-metrics-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		imgStore := ctlr.StoreController.DefaultStore

		orphanBlob := []byte("orphaned-blob-content")
		_, _, err = imgStore.FullBlobUpload(context.Background(), "gc-metrics-test",
			bytes.NewReader(orphanBlob), godigest.FromBytes(orphanBlob))
		So(err, ShouldBeNil)

		audit := log.NewAuditLogger("debug", "/dev/null")
		gcObj := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{Delay: 0},
			audit, ctlr.Log, ctlr.Metrics)

		err = gcObj.CleanRepo(context.Background(), "gc-metrics-test")
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/metrics")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		respStr := string(resp.Body())
		So(respStr, ShouldContainSubstring, "zot_gc_runs_total")
		So(respStr, ShouldContainSubstring, "zot_gc_duration_seconds")
		So(respStr, ShouldContainSubstring, "zot_gc_deleted_total{type=\"blob\"}")
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

func setupMetricsBearerAuthServerCerts(t *testing.T) (string, string) {
	t.Helper()

	tempDir := t.TempDir()
	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
		KeyType:    tlsutils.KeyTypeRSA,
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	serverCertPath := path.Join(tempDir, "server.cert")
	serverKeyPath := path.Join(tempDir, "server.key")
	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeRSA,
	}
	err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	return serverCertPath, serverKeyPath
}
