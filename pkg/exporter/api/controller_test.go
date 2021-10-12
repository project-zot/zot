// +build minimal

package api_test

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	zotapi "github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/exporter/api"
	"github.com/anuvu/zot/pkg/extensions/monitoring"
	jsoniter "github.com/json-iterator/go"
	"github.com/phayes/freeport"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	BaseURL             = "http://127.0.0.1:%s"
	SleepTime           = 50 * time.Millisecond
	SecondToNanoseconds = 1000000000
)

func getRandomLatencyN(maxNanoSeconds int64) time.Duration {
	rand.Seed(time.Now().UnixNano())
	return time.Duration(rand.Int63n(maxNanoSeconds))
}

func getRandomLatency() time.Duration {
	return getRandomLatencyN(120 * SecondToNanoseconds) // a random latency (in nanoseconds) that can be up to 2 minutes
}

func getFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return fmt.Sprint(port)
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

func readDefaultMetrics(zc *api.ZotCollector, ch chan prometheus.Metric) {
	var metric dto.Metric

	pm := <-ch
	So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_up"].String())

	err := pm.Write(&metric)
	So(err, ShouldBeNil)
	So(*metric.Gauge.Value, ShouldEqual, 1)

	pm = <-ch
	So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_info"].String())

	err = pm.Write(&metric)
	So(err, ShouldBeNil)
	So(*metric.Gauge.Value, ShouldEqual, 0)
}

func TestNewExporter(t *testing.T) {
	Convey("Make an exporter controller", t, func() {
		exporterConfig := api.DefaultConfig()
		So(exporterConfig, ShouldNotBeNil)
		exporterPort := getFreePort()
		serverPort := getFreePort()
		exporterConfig.ZotExporter.Port = exporterPort
		dir, _ := ioutil.TempDir("", "metrics")
		exporterConfig.ZotExporter.Metrics.Path = strings.TrimPrefix(dir, "/tmp/")
		exporterConfig.ZotServer.Port = serverPort
		exporterController := api.NewController(exporterConfig)

		Convey("Start the zot exporter", func() {
			go func() {
				// this blocks
				exporterController.Run()
				So(nil, ShouldNotBeNil) // Fail the test in case zot exporter unexpectedly exits
			}()
			time.Sleep(SleepTime)

			zc := api.GetZotCollector(exporterController)
			ch := make(chan prometheus.Metric)

			Convey("When zot server not running", func() {
				go func() {
					// this blocks
					zc.Collect(ch)
				}()
				// Read from the channel expected values
				pm := <-ch
				So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_up"].String())

				var metric dto.Metric
				err := pm.Write(&metric)
				So(err, ShouldBeNil)
				So(*metric.Gauge.Value, ShouldEqual, 0) // "zot_up=0" means zot server is not running

				// Check that no more data was written to the channel
				So(isChannelDrained(ch), ShouldEqual, true)
			})
			Convey("When zot server is running", func() {
				servercConfig := zotapi.NewConfig()
				So(servercConfig, ShouldNotBeNil)
				baseURL := fmt.Sprintf(BaseURL, serverPort)
				servercConfig.HTTP.Port = serverPort
				serverController := zotapi.NewController(servercConfig)
				So(serverController, ShouldNotBeNil)

				dir, err := ioutil.TempDir("", "exporter-test")
				So(err, ShouldBeNil)
				defer os.RemoveAll(dir)
				serverController.Config.Storage.RootDirectory = dir
				go func(c *zotapi.Controller) {
					// this blocks
					if err := c.Run(); !errors.Is(err, http.ErrServerClosed) {
						panic(err)
					}
				}(serverController)
				defer func(c *zotapi.Controller) {
					_ = c.Server.Shutdown(context.TODO())
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
				resp, err := resty.R().Get(baseURL + "/v2/metrics")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				Convey("Collecting data: default metrics", func() {
					go func() {
						// this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)
					So(isChannelDrained(ch), ShouldEqual, true)
				})

				Convey("Collecting data: Test init value & that increment works on Counters", func() {
					//Testing initial value of the counter to be 1 after first incrementation call
					monitoring.IncUploadCounter(serverController.Metrics, "testrepo")
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm := <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_uploads_total"].String())

					var metric dto.Metric
					err := pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					So(isChannelDrained(ch), ShouldEqual, true)

					//Testing that counter is incremented by 1
					monitoring.IncUploadCounter(serverController.Metrics, "testrepo")
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_uploads_total"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 2)

					So(isChannelDrained(ch), ShouldEqual, true)
				})
				Convey("Collecting data: Test that concurent Counter increment requests works properly", func() {
					reqsSize := rand.Intn(1000)
					for i := 0; i < reqsSize; i++ {
						monitoring.IncDownloadCounter(serverController.Metrics, "dummyrepo")
					}
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)
					pm := <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_downloads_total"].String())

					var metric dto.Metric
					err := pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, reqsSize)

					So(isChannelDrained(ch), ShouldEqual, true)
				})
				Convey("Collecting data: Test init value & that observe works on Summaries", func() {
					//Testing initial value of the summary counter to be 1 after first observation call
					var latency1, latency2 time.Duration
					latency1 = getRandomLatency()
					monitoring.ObserveHTTPRepoLatency(serverController.Metrics, "/v2/testrepo/blogs/dummydigest", latency1)
					time.Sleep(SleepTime)

					go func() {
						//this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm := <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_latency_seconds_count"].String())

					var metric dto.Metric
					err := pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_latency_seconds_sum"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latency1.Seconds())

					So(isChannelDrained(ch), ShouldEqual, true)

					//Testing that summary counter is incremented by 1 and summary sum is  properly updated
					latency2 = getRandomLatency()
					monitoring.ObserveHTTPRepoLatency(serverController.Metrics, "/v2/testrepo/blogs/dummydigest", latency2)
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_latency_seconds_count"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 2)

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_latency_seconds_sum"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, (latency1.Seconds())+(latency2.Seconds()))

					So(isChannelDrained(ch), ShouldEqual, true)
				})
				Convey("Collecting data: Test that concurent Summary observation requests works properly", func() {
					var latencySum float64
					reqsSize := rand.Intn(1000)
					for i := 0; i < reqsSize; i++ {
						latency := getRandomLatency()
						latencySum += latency.Seconds()
						monitoring.ObserveHTTPRepoLatency(serverController.Metrics, "/v2/dummyrepo/manifests/testreference", latency)
					}
					time.Sleep(SleepTime)

					go func() {
						// this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm := <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_latency_seconds_count"].String())

					var metric dto.Metric
					err := pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, reqsSize)

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_repo_latency_seconds_sum"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latencySum)

					So(isChannelDrained(ch), ShouldEqual, true)
				})
				Convey("Collecting data: Test init value & that observe works on Histogram buckets", func() {
					//Testing initial value of the histogram counter to be 1 after first observation call
					latency := getRandomLatency()
					monitoring.ObserveHTTPMethodLatency(serverController.Metrics, "GET", latency)
					time.Sleep(SleepTime)

					go func() {
						//this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm := <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_method_latency_seconds_count"].String())

					var metric dto.Metric
					err := pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, 1)

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_method_latency_seconds_sum"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latency.Seconds())

					for _, fvalue := range monitoring.GetDefaultBuckets() {
						pm = <-ch
						So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_method_latency_seconds_bucket"].String())

						err = pm.Write(&metric)
						So(err, ShouldBeNil)
						if latency.Seconds() < fvalue {
							So(*metric.Counter.Value, ShouldEqual, 1)
						} else {
							So(*metric.Counter.Value, ShouldEqual, 0)
						}
					}

					So(isChannelDrained(ch), ShouldEqual, true)
				})
				Convey("Collecting data: Test init Histogram buckets \n", func() {
					//Generate a random  latency within each bucket and finally test
					// that "higher" rank bucket counter is incremented by 1
					var latencySum float64

					dBuckets := monitoring.GetDefaultBuckets()
					for i, fvalue := range dBuckets {
						var latency time.Duration
						if i == 0 {
							//first bucket value
							latency = getRandomLatencyN(int64(fvalue * SecondToNanoseconds))
						} else {
							pvalue := dBuckets[i-1] // previous bucket value
							latency = time.Duration(pvalue*SecondToNanoseconds) +
								getRandomLatencyN(int64(dBuckets[0]*SecondToNanoseconds))
						}
						latencySum += latency.Seconds()
						monitoring.ObserveHTTPMethodLatency(serverController.Metrics, "GET", latency)
					}
					time.Sleep(SleepTime)

					go func() {
						//this blocks
						zc.Collect(ch)
					}()
					readDefaultMetrics(zc, ch)

					pm := <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_method_latency_seconds_count"].String())

					var metric dto.Metric
					err := pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, len(dBuckets))

					pm = <-ch
					So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_method_latency_seconds_sum"].String())

					err = pm.Write(&metric)
					So(err, ShouldBeNil)
					So(*metric.Counter.Value, ShouldEqual, latencySum)

					for i := range dBuckets {
						pm = <-ch
						So(pm.Desc().String(), ShouldEqual, zc.MetricsDesc["zot_method_latency_seconds_bucket"].String())

						err = pm.Write(&metric)
						So(err, ShouldBeNil)
						So(*metric.Counter.Value, ShouldEqual, i+1)
					}

					So(isChannelDrained(ch), ShouldEqual, true)
				})
				Convey("Negative testing: Send unknown metric type to MetricServer", func() {
					serverController.Metrics.SendMetric(getRandomLatency())
				})
				Convey("Concurrent metrics scrape", func() {
					var wg sync.WaitGroup

					workersSize := rand.Intn(100)
					for i := 0; i < workersSize; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							m := serverController.Metrics.ReceiveMetrics()
							var json = jsoniter.ConfigCompatibleWithStandardLibrary

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
