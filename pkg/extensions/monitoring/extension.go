// +build extended

package monitoring

import (
	"time"
	"regexp"
	"strconv"
	"os"
	"path"
	"path/filepath"
	
	"github.com/anuvu/zot/pkg/extensions/prometheus/metrics"
)

func IncHttpConnRequests(method string, statusCode int) {
	metrics.HttpConnRequests.WithLabelValues(method, strconv.Itoa(statusCode)).Inc()
}

func ObserveHttpServeLatency(path string, latency time.Duration) {
	re := regexp.MustCompile("\\/v2\\/(.*?)\\/(blobs|tags|manifests)\\/(.*)$")
	match := re.FindStringSubmatch(path)
	if len(match) > 1 {
		metrics.HttpServeLatency.WithLabelValues(match[1]).Observe(latency.Seconds())
	} else {
		metrics.HttpServeLatency.WithLabelValues("N/A").Observe(latency.Seconds())
	}
}

func IncDownloadCounter(repo string) {
	metrics.DownloadCounter.WithLabelValues(repo).Inc()
}

func SetStorageUsage(repo string, rootDir string) {
	dir := path.Join(rootDir, repo)
	repoSize, err := getDirSize(dir)

	if err == nil {
		metrics.StorageUsage.WithLabelValues(repo).Set(float64(repoSize))
	}
}

func IncUploadCounter(repo string) {
	metrics.UploadCounter.WithLabelValues(repo).Inc()
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})

	return size, err
}
