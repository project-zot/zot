//go:build !metrics
// +build !metrics

package api_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zotapi "zotregistry.dev/zot/pkg/api"
	zotcfg "zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/exporter/api"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/scheduler"
	. "zotregistry.dev/zot/pkg/test/common"
)

func getRandomLatencyN(max int64) time.Duration {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}

	return time.Duration(nBig.Int64())
}

func getRandomLatency() time.Duration {
	return getRandomLatencyN(int64(2 * time.Minute)) // a random latency (in nanoseconds) that can be up to 2 minutes
}

func TestNew(t *testing.T) {
	Convey("Make a new controller", t, func() {
		config := api.DefaultConfig()
		So(config, ShouldNotBeNil)
		So(api.NewController(config), ShouldNotBeNil)
	})
}

func isChannelDrained(ch chan prometheus.Metric) bool {
	time.Sleep(SleepTime)
	select {
	case <-ch:
		return false
	default:
		return true
	}
}

func readDefaultMetrics(collector *api.Collector, chMetric chan prometheus.Metric) {
	var metric dto.Metric

	pmMetric := <-chMetric
	So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_up"].String())

	err := pmMetric.Write(&metric)
	So(err, ShouldBeNil)
	So(*metric.Gauge.Value, ShouldEqual, 1)

	pmMetric = <-chMetric
	So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_scheduler_workers_total"].String())

	err = pmMetric.Write(&metric)
	So(err, ShouldBeNil)
	So(*metric.Gauge.Value, ShouldEqual, runtime.NumCPU()*scheduler.NumWorkersMultiplier)

	pmMetric = <-chMetric
	So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_info"].String())

	err = pmMetric.Write(&metric)
	So(err, ShouldBeNil)
	So(*metric.Gauge.Value, ShouldEqual, 0)

	pmMetric = <-chMetric
	So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_scheduler_generators_total"].String())
}

func TestNewExporter(t *testing.T) {
	Convey("Make an exporter controller", t, func() {
		exporterConfig := api.DefaultConfig()
		So(exporterConfig, ShouldNotBeNil)
		exporterPort := GetFreePort()
		serverPort := GetFreePort()
		exporterConfig.Exporter.Port = exporterPort
		exporterConfig.Exporter.Metrics.Path = strings.TrimPrefix(t.TempDir(), "/tmp/")
		exporterConfig.Server.Port = serverPort
		exporterController := api.NewController(exporterConfig)

		Convey("Start the zot exporter", func() {
			go func() {
				// this blocks
				exporterController.Run()
				So(nil, ShouldNotBeNil) // Fail the test in case zot exporter unexpectedly exits
			}()
			time.Sleep(SleepTime)

			collector := api.GetCollector(exporterController)
			chMetric := make(chan prometheus.Metric)

			Convey("When zot server not running", func() {
				go func() {
					// this blocks
					collector.Collect(chMetric)
				}()
				// Read from the channel expected values
				pm := <-chMetric
				So(pm.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_up"].String())

				var metric dto.Metric
				err := pm.Write(&metric)
				So(err, ShouldBeNil)
				So(*metric.Gauge.Value, ShouldEqual, 0) // "zot_up=0" means zot server is not running

				// Check that no more data was written to the channel
				So(isChannelDrained(chMetric), ShouldEqual, true)
			})
			Convey("When zot server is running", func() {
				servercConfig := zotcfg.New()
				So(servercConfig, ShouldNotBeNil)
				baseURL := fmt.Sprintf(BaseURL, serverPort)
				servercConfig.HTTP.Port = serverPort
				servercConfig.BinaryType = "minimal"
				servercConfig.Storage.Dedupe = false
				servercConfig.Storage.GC = false
				serverController := zotapi.NewController(servercConfig)
				So(serverController, ShouldNotBeNil)

				dir := t.TempDir()
				serverController.Config.Storage.RootDirectory = dir
				go func(ctrl *zotapi.Controller) {
					if err := ctrl.Init(); err != nil {
						panic(err)
					}

					// this blocks
					if err := ctrl.Run(); !errors.Is(err, http.ErrServerClosed) {
						panic(err)
					}
				}(serverController)
				defer func(ctrl *zotapi.Controller) {
					_ = ctrl.Server.Shutdown(context.TODO())
				}(serverController)
				// wait till ready
				for {
					_, err := resty.R().Get(baseURL)
					if err == nil {
						break
					}
					time.Sleep(SleepTime)
				}

				// Side effect of calling this endpoint is that it will enable metrics
				resp, err := resty.R().Get(baseURL + "/metrics")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				Convey("Collecting data: default metrics", func() {
					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)
					So(isChannelDrained(chMetric), ShouldEqual, true)
				})

				Convey("Collecting data: Test init value & that increment works on Counters", func() {
					// Testing initial value of the counter to be 1 after first incrementation call
					monitoring.IncUploadCounter(serverController.Metrics, "testrepo")
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric := <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_repo_uploads_total"].String())

					var metric dto.Metric
					err := pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					So(isChannelDrained(chMetric), ShouldEqual, true)

					// Testing that counter is incremented by 1
					monitoring.IncUploadCounter(serverController.Metrics, "testrepo")
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_repo_uploads_total"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 2)

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Collecting data: Test that concurent Counter increment requests works properly", func() {
					nBig, err := rand.Int(rand.Reader, big.NewInt(1000))
					if err != nil {
						panic(err)
					}
					reqsSize := int(nBig.Int64())
					for i := 0; i < reqsSize; i++ {
						monitoring.IncDownloadCounter(serverController.Metrics, "dummyrepo")
					}
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)
					pm := <-chMetric
					So(pm.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_repo_downloads_total"].String())

					var metric dto.Metric
					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, reqsSize)

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Collecting data: Test init value & that observe works on Summaries", func() {
					// Testing initial value of the summary counter to be 1 after first observation call
					var latency1, latency2 time.Duration
					latency1 = getRandomLatency()
					monitoring.ObserveHTTPRepoLatency(serverController.Metrics, "/v2/testrepo/blogs/dummydigest", latency1)
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric := <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_repo_latency_seconds_count"].String())

					var metric dto.Metric
					err := pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_repo_latency_seconds_sum"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latency1.Seconds())

					So(isChannelDrained(chMetric), ShouldEqual, true)

					// Testing that summary counter is incremented by 1 and summary sum is  properly updated
					latency2 = getRandomLatency()
					monitoring.ObserveHTTPRepoLatency(serverController.Metrics, "/v2/testrepo/blogs/dummydigest", latency2)
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_repo_latency_seconds_count"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 2)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_repo_latency_seconds_sum"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, (latency1.Seconds())+(latency2.Seconds()))

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Collecting data: Test that concurent Summary observation requests works properly", func() {
					var latencySum float64
					nBig, err := rand.Int(rand.Reader, big.NewInt(1000))
					if err != nil {
						panic(err)
					}
					reqsSize := int(nBig.Int64())
					for i := 0; i < reqsSize; i++ {
						latency := getRandomLatency()
						latencySum += latency.Seconds()
						monitoring.ObserveHTTPRepoLatency(serverController.Metrics, "/v2/dummyrepo/manifests/testreference", latency)
					}
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric := <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_repo_latency_seconds_count"].String())

					var metric dto.Metric
					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, reqsSize)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_repo_latency_seconds_sum"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latencySum)

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Collecting data: Test init value & that observe works on Histogram buckets", func() {
					// Testing initial value of the histogram counter to be 1 after first observation call
					latency := getRandomLatency()
					monitoring.ObserveHTTPMethodLatency(serverController.Metrics, "GET", latency)
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric := <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_method_latency_seconds_count"].String())

					var metric dto.Metric
					err := pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_method_latency_seconds_sum"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latency.Seconds())

					for _, fvalue := range monitoring.GetDefaultBuckets() {
						pmMetric = <-chMetric
						So(pmMetric.Desc().String(), ShouldEqual,
							collector.MetricsDesc["zot_http_method_latency_seconds_bucket"].String())

						err = pmMetric.Write(&metric)
						So(err, ShouldBeNil)
						if latency.Seconds() < fvalue {
							So(*metric.Counter.Value, ShouldEqual, 1)
						} else {
							So(*metric.Counter.Value, ShouldEqual, 0)
						}
					}

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Collecting data: Test init value & that observe works on Histogram buckets (lock latency)", func() {
					// Testing initial value of the histogram counter to be 1 after first observation call
					latency := getRandomLatency()
					monitoring.ObserveStorageLockLatency(serverController.Metrics, latency, "/tmp/zot", "RWLock")
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric := <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_storage_lock_latency_seconds_count"].String())

					var metric dto.Metric
					err := pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_storage_lock_latency_seconds_sum"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latency.Seconds())

					for _, fvalue := range monitoring.GetBuckets("zot.storage.lock.latency.seconds") {
						pmMetric = <-chMetric
						So(pmMetric.Desc().String(), ShouldEqual,
							collector.MetricsDesc["zot_storage_lock_latency_seconds_bucket"].String())

						err = pmMetric.Write(&metric)
						So(err, ShouldBeNil)
						if latency.Seconds() < fvalue {
							So(*metric.Counter.Value, ShouldEqual, 1)
						} else {
							So(*metric.Counter.Value, ShouldEqual, 0)
						}
					}

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Collecting data: Test init Histogram buckets \n", func() {
					// Generate a random  latency within each bucket and finally test
					// that "higher" rank bucket counter is incremented by 1
					var latencySum float64

					dBuckets := monitoring.GetDefaultBuckets()
					for index, fvalue := range dBuckets {
						var latency time.Duration
						if index == 0 {
							// first bucket value
							latency = getRandomLatencyN(int64(fvalue * float64(time.Second)))
						} else {
							pvalue := dBuckets[index-1] // previous bucket value
							latency = time.Duration(pvalue*float64(time.Second)) +
								getRandomLatencyN(int64(dBuckets[0]*float64(time.Second)))
						}
						latencySum += latency.Seconds()
						monitoring.ObserveHTTPMethodLatency(serverController.Metrics, "GET", latency)
					}
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						collector.Collect(chMetric)
					}()
					readDefaultMetrics(collector, chMetric)

					pmMetric := <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual, collector.MetricsDesc["zot_http_method_latency_seconds_count"].String())

					var metric dto.Metric
					err := pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, len(dBuckets))

					pmMetric = <-chMetric
					So(pmMetric.Desc().String(), ShouldEqual,
						collector.MetricsDesc["zot_http_method_latency_seconds_sum"].String())

					err = pmMetric.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latencySum)

					for index := range dBuckets {
						pmMetric = <-chMetric
						So(pmMetric.Desc().String(), ShouldEqual,
							collector.MetricsDesc["zot_http_method_latency_seconds_bucket"].String())

						err = pmMetric.Write(&metric)
						So(err, ShouldBeNil)
						So(*metric.Counter.Value, ShouldEqual, index+1)
					}

					So(isChannelDrained(chMetric), ShouldEqual, true)
				})
				Convey("Negative testing: Send unknown metric type to MetricServer", func() {
					serverController.Metrics.SendMetric(getRandomLatency())
				})
				Convey("Concurrent metrics scrape", func() {
					var wg sync.WaitGroup

					nBig, err := rand.Int(rand.Reader, big.NewInt(100))
					if err != nil {
						panic(err)
					}
					workersSize := int(nBig.Int64())
					for i := 0; i < workersSize; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							m := serverController.Metrics.ReceiveMetrics()
							json := jsoniter.ConfigCompatibleWithStandardLibrary

							_, err := json.Marshal(m)
							if err != nil {
								exporterController.Log.Error().Err(err).Msg("Concurrent metrics scrape fail")
							}
						}()
					}
					wg.Wait()
				})
				Convey("Negative testing: Increment a counter that does not exist", func() {
					cv := monitoring.CounterValue{Name: "dummyName"}
					serverController.Metrics.SendMetric(cv)
				})
				Convey("Negative testing: Set a gauge for a metric with len(labelNames)!=len(knownLabelNames)", func() {
					gv := monitoring.GaugeValue{
						Name:       "zot.info",
						Value:      1,
						LabelNames: []string{"commit", "binaryType", "version"},
					}
					serverController.Metrics.SendMetric(gv)
				})
				Convey("Negative testing: Summary observe for a metric with labelNames!=knownLabelNames", func() {
					sv := monitoring.SummaryValue{
						Name:        "zot.repo.latency.seconds",
						LabelNames:  []string{"dummyRepoLabelName"},
						LabelValues: []string{"dummyrepo"},
					}
					serverController.Metrics.SendMetric(sv)
				})
				Convey("Negative testing: Histogram observe for a metric with len(labelNames)!=len(LabelValues)", func() {
					hv := monitoring.HistogramValue{
						Name:        "zot.method.latency.seconds",
						LabelNames:  []string{"method"},
						LabelValues: []string{"GET", "POST", "DELETE"},
					}
					serverController.Metrics.SendMetric(hv)
				})
				Convey("Negative testing: error in getting the size for a repo directory", func() {
					monitoring.SetStorageUsage(serverController.Metrics, "/tmp/zot", "dummyrepo")
				})
				Convey("Disabling metrics after idle timeout", func() {
					So(serverController.Metrics.IsEnabled(), ShouldEqual, true)
					time.Sleep(monitoring.GetMaxIdleScrapeInterval())
					So(serverController.Metrics.IsEnabled(), ShouldEqual, false)
				})
			})
		})
	})
}
