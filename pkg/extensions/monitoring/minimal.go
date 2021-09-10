// +build minimal

package monitoring

import (
	"time"
)

func IncHttpConnRequests(method string, statusCode int) {

}

func ObserveHttpServeLatency(path string, latency time.Duration) {
	
}

func IncDownloadCounter(repo string) {

}

func SetStorageUsage(repo string, rootDir string) {

}

func IncUploadCounter(repo string) {

}
