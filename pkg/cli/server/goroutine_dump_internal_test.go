package server

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestDumpGoroutinesOnSignalWritesStacksAndKeepsRunning(t *testing.T) {
	sigCh := make(chan os.Signal, 1)

	var (
		mu  sync.Mutex
		out bytes.Buffer
	)

	writer := lockedWriter{mu: &mu, w: &out}

	done := make(chan struct{})

	go func() {
		dumpGoroutinesOnSignal(sigCh, writer)
		close(done)
	}()

	for i := range 2 {
		sigCh <- syscall.SIGUSR1

		deadline := time.After(5 * time.Second)

		for {
			mu.Lock()
			count := strings.Count(out.String(), "=== end goroutine dump ===")
			mu.Unlock()

			if count == i+1 {
				break
			}

			select {
			case <-deadline:
				t.Fatalf("dump %d not written", i+1)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	mu.Lock()
	text := out.String()
	mu.Unlock()

	if !strings.Contains(text, "goroutine ") || !strings.Contains(text, "TestDumpGoroutinesOnSignalWritesStacksAndKeepsRunning") {
		t.Fatal("dump does not contain goroutine stacks")
	}

	select {
	case <-done:
		t.Fatal("handler exited; it must keep serving signals")
	default:
	}

	close(sigCh)
	<-done
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.w.Write(p)
}
