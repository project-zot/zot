//go:build sync

package sync

import (
	"bytes"
	"runtime"
	"testing"

	"zotregistry.dev/zot/v2/pkg/log"
)

func TestGetImageStoreDoesNotLeakMetricsGoroutines(t *testing.T) {
	logger := log.NewTestLogger()

	before := countMetricServerRunGoroutines()

	const iterations = 25

	for range iterations {
		store := getImageStore(t.TempDir(), logger)
		if store == nil {
			t.Fatal("expected temp image store")
		}
	}

	// Yield once so a leaked go ms.Run() is scheduled into a stack dump.
	// getImageStore uses a nop server, so this count must stay exactly at `before`.
	runtime.Gosched()

	after := countMetricServerRunGoroutines()
	if after != before {
		t.Fatalf("getImageStore leaked metrics goroutines: before=%d after=%d", before, after)
	}
}

func countMetricServerRunGoroutines() int {
	buf := make([]byte, 1<<22)
	stackLen := runtime.Stack(buf, true)

	// Each NewMetricsServer(!metrics) leaves (*metricServer).Run and Run.func1.
	return bytes.Count(buf[:stackLen], []byte("(*metricServer).Run"))
}
