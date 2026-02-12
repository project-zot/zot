package api

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	// tlsCertificateEventDebounceInterval is the time window for coalescing multiple file change events
	// into a single reload operation. This prevents redundant reloads when both cert and key files are modified.
	tlsCertificateEventDebounceInterval = 150 * time.Millisecond
	// tlsCertificateStatCheckInterval is the rate limit for stat-based certificate change detection.
	tlsCertificateStatCheckInterval = 1 * time.Second
)

var tlsFileStat = os.Stat //nolint:gochecknoglobals // test hook for os.Stat

// TlsConfigWatcher watches TLS cert/key files and reloads certificates on change.
type TlsConfigWatcher struct {
	mu            sync.RWMutex
	watcher       *fsnotify.Watcher
	done          chan struct{}
	stopOnce      sync.Once
	useInotify    bool
	certPath      string
	keyPath       string
	log           log.Logger
	debounceTimer *time.Timer
	debounceMutex sync.Mutex
	// Certificate management fields
	tlsCert                  *tls.Certificate
	tlsCertModTime           time.Time
	tlsKeyModTime            time.Time
	tlsCertReloadInProgress  atomic.Bool
	tlsCertLastStatCheckTime atomic.Int64 // Unix timestamp in nanoseconds for last stat check
}

// NewTlsConfigWatcher creates a TLS config watcher for the given cert and key paths.
func NewTlsConfigWatcher(certPath, keyPath string, logger log.Logger) *TlsConfigWatcher {
	return &TlsConfigWatcher{
		certPath: certPath,
		keyPath:  keyPath,
		log:      logger,
	}
}

// Start begins watching the certificate and key files for changes.
// Returns an error if the watcher is already running. Safe to call multiple times if Stop is called
// between attempts.
func (w *TlsConfigWatcher) Start() error {
	// Check if watcher is already running to prevent duplicate goroutines and resource leaks
	w.mu.RLock()
	if w.done != nil {
		w.mu.RUnlock()

		return errors.ErrCertificateWatcherAlreadyRunning
	}
	w.mu.RUnlock()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.log.Error().Err(err).Msg("failed to create fsnotify watcher")
		w.disableUseInotify()

		return err
	}

	w.log.Debug().Str("cert", w.certPath).Str("key", w.keyPath).
		Msg("starting TLS certificate watcher")

	if err := watcher.Add(w.certPath); err != nil {
		w.log.Warn().Err(err).Str("cert", w.certPath).Msg("failed to watch certificate file")
		_ = watcher.Close()
		w.disableUseInotify()

		return err
	}

	if err := watcher.Add(w.keyPath); err != nil {
		w.log.Warn().Err(err).Str("key", w.keyPath).Msg("failed to watch key file")
		_ = watcher.Close()
		w.disableUseInotify()

		return err
	}

	w.mu.Lock()
	w.watcher = watcher
	w.useInotify = true
	w.done = make(chan struct{})
	w.stopOnce = sync.Once{}
	w.mu.Unlock()

	go w.loop()

	w.log.Info().Msg("TLS certificate watcher started using fsnotify")

	return nil
}

// Stop signals the watcher to stop and returns once the signal is sent.
// Safe to call even if Start() was never called or failed - it will return early if the watcher
// goroutine is not running.
func (w *TlsConfigWatcher) Stop() {
	w.mu.RLock()
	done := w.done
	w.mu.RUnlock()

	if done == nil {
		w.log.Debug().Msg("TLS certificate watcher stop requested with no active watcher")

		return
	}

	w.stopOnce.Do(func() {
		// Clean up any pending debounce timer
		w.debounceMutex.Lock()
		if w.debounceTimer != nil {
			w.debounceTimer.Stop()
			w.debounceTimer = nil
		}
		w.debounceMutex.Unlock()

		// Atomically capture and reset watcher state
		w.mu.Lock()
		capturedWatcher := w.watcher
		capturedDone := w.done
		w.done = nil
		w.watcher = nil
		w.useInotify = false
		w.mu.Unlock()

		// Close fsnotify watcher to terminate the goroutine promptly
		if capturedWatcher != nil {
			_ = capturedWatcher.Close()
		}

		// Signal the goroutine to exit via the done channel
		if capturedDone != nil {
			close(capturedDone)
		}

		w.log.Debug().Msg("TLS certificate watcher stopped and state cleared")
	})
}

// UseInotify reports whether file watching is active.
func (w *TlsConfigWatcher) UseInotify() bool {
	w.mu.RLock()
	useInotify := w.useInotify
	w.mu.RUnlock()

	return useInotify
}

func (w *TlsConfigWatcher) disableUseInotify() {
	w.mu.Lock()
	w.useInotify = false
	w.mu.Unlock()
}

func (w *TlsConfigWatcher) loop() {
	// Clear watcher state when loop exits so Start() can be called again.
	// This serves as a safety net for cases where the goroutine exits naturally
	// (e.g., channels closed unexpectedly) without Stop() being called.
	defer func() {
		w.mu.Lock()
		// Close done channel if not already closed by Stop()
		if w.done != nil {
			close(w.done)
			w.done = nil
		}
		if w.watcher != nil {
			_ = w.watcher.Close()
			w.watcher = nil
		}
		w.useInotify = false
		// Note: w.stopOnce is reset by Start() when a new watcher is initialized,
		// so we don't reset it here to avoid races with Stop() executing its callback
		w.mu.Unlock()
		w.log.Debug().Msg("TLS certificate watcher loop cleanup completed")
	}()

	w.mu.RLock()
	watcher := w.watcher
	done := w.done
	w.mu.RUnlock()

	if watcher == nil {
		w.log.Debug().Msg("TLS certificate watcher loop exited: watcher not initialized")

		return
	}

	for {
		select {
		case <-done:
			w.log.Debug().Msg("TLS certificate watcher loop exited: stop signal received")

			return
		case event, ok := <-watcher.Events:
			if !ok {
				w.log.Debug().Msg("TLS certificate watcher loop exited: events channel closed")

				return
			}

			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) != 0 {
				w.log.Debug().Str("file", event.Name).Str("op", event.Op.String()).
					Msg("certificate file change detected")

				if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
					if !w.retryAddWatch(event.Name, watcher, done) {
						w.log.Warn().Str("file", event.Name).
							Msg("failed to re-add watch after retries, switching to stat-based polling")
						w.disableUseInotify()
					}
				}

				select {
				case <-done:
					w.log.Debug().Msg("TLS certificate watcher loop exited: stop signal received before reload")

					return
				default:
				}

				// Debounce multiple file events to coalesce cert and key changes into a single reload
				w.scheduleReload()
			}
		case <-w.getDebounceChannel():
			// Debounce timer expired, perform the reload
			w.debounceMutex.Lock()
			w.debounceTimer = nil
			w.debounceMutex.Unlock()

			select {
			case <-done:
				w.log.Debug().Msg("TLS certificate watcher loop exited: stop signal received before debounced reload")

				return
			default:
			}

			w.log.Debug().Str("cert", w.certPath).Str("key", w.keyPath).
				Msg("reloading TLS certificate after debounced file change")
			if err := w.ReloadCertificate(); err != nil {
				w.log.Error().Err(err).Msg("failed to reload certificate on file change")
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				w.log.Debug().Msg("TLS certificate watcher loop exited: errors channel closed")

				return
			}

			w.log.Error().Err(err).Msg("failed to watch certificate files")
		}
	}
}

func (w *TlsConfigWatcher) getDebounceChannel() <-chan time.Time {
	w.debounceMutex.Lock()
	defer w.debounceMutex.Unlock()

	if w.debounceTimer == nil {
		return nil
	}

	return w.debounceTimer.C
}

func (w *TlsConfigWatcher) scheduleReload() {
	w.debounceMutex.Lock()
	defer w.debounceMutex.Unlock()

	// If a reload is already pending, just reset the timer to restart the debounce window
	if w.debounceTimer != nil {
		if !w.debounceTimer.Stop() {
			select {
			case <-w.debounceTimer.C:
			default:
			}
		}
		w.debounceTimer.Reset(tlsCertificateEventDebounceInterval)
		w.log.Debug().Msg("debounce timer reset for additional file change event")

		return
	}

	// First event after debounce window closed, schedule a new reload.
	// Use time.NewTimer instead of time.AfterFunc since we only care about the timer's
	// channel firing in the select statement, not about executing a callback function.
	w.debounceTimer = time.NewTimer(tlsCertificateEventDebounceInterval)
	w.log.Debug().Str("interval", tlsCertificateEventDebounceInterval.String()).
		Msg("debounce timer started for file change events")
}

func (w *TlsConfigWatcher) retryAddWatch(file string, watcher *fsnotify.Watcher, done <-chan struct{}) bool {
	for attempt := range 5 {
		select {
		case <-done:
			return false
		case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
		}

		if err := watcher.Add(file); err == nil {
			w.log.Debug().Str("file", file).Int("attempt", attempt+1).
				Msg("re-added watch after file removal/rename")

			return true
		}

		w.log.Debug().Str("file", file).Int("attempt", attempt+1).
			Msg("retrying watch add after failure")
	}

	return false
}

// GetCertificate is a callback used by tls.Config that dynamically loads TLS certificates.
// This allows certificates to be reloaded when they change on disk without restarting the server.
// It uses fsnotify for file watching when available or falls back to stat-based checking.
func (w *TlsConfigWatcher) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var needsReload bool

	var cert *tls.Certificate

	// First check if certificate is not yet loaded
	w.mu.RLock()
	cert = w.tlsCert
	if cert == nil {
		w.mu.RUnlock()
		needsReload = true
	} else {
		w.mu.RUnlock()
		useInotify := w.UseInotify()

		// If file watching is not being used, perform stat-based fallback polling.
		// Rate limit the stat checks to avoid I/O overhead on every TLS handshake.
		if !useInotify {
			now := time.Now().UnixNano()
			lastCheckTime := w.tlsCertLastStatCheckTime.Load()
			if now-lastCheckTime >= int64(tlsCertificateStatCheckInterval) {
				needsReload = w.CheckCertificateModTime()
				// Update the last check time only if we actually performed the check
				w.tlsCertLastStatCheckTime.Store(now)
			}
		}
	}

	// Only reload if necessary or if certificate is not yet loaded.
	// Use atomic flag to ensure only one goroutine performs the reload when multiple
	// concurrent requests detect a stale certificate, preventing duplicate reload operations.
	//
	// If another goroutine is already performing a reload, wait for it to complete before
	// returning to avoid spurious ErrCertificateNotLoaded errors during concurrent initial loads.
	if needsReload {
		// Only proceed with reload if no reload is already in progress
		if w.tlsCertReloadInProgress.CompareAndSwap(false, true) {
			defer w.tlsCertReloadInProgress.Store(false)
			if err := w.ReloadCertificate(); err != nil {
				return nil, fmt.Errorf("failed to reload certificate: %w", err)
			}
		} else {
			// Another goroutine is reloading - wait for it to complete (up to 5 seconds)
			// to avoid returning ErrCertificateNotLoaded during concurrent initial loads
			deadline := time.Now().Add(5 * time.Second)
			for w.tlsCertReloadInProgress.Load() && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	w.mu.RLock()
	cert = w.tlsCert
	w.mu.RUnlock()

	if cert == nil {
		return nil, errors.ErrCertificateNotLoaded
	}

	return cert, nil
}

// ReloadCertificate loads the TLS certificate and key from disk.
func (w *TlsConfigWatcher) ReloadCertificate() error {
	cert, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		w.log.Error().Err(err).Str("cert", w.certPath).Str("key", w.keyPath).
			Msg("failed to load certificate and key pair")

		return err
	}

	// Update modification times
	certInfo, certStatErr := tlsFileStat(w.certPath)
	if certStatErr != nil {
		w.log.Warn().Err(certStatErr).Str("cert", w.certPath).
			Msg("failed to stat certificate file")
	}
	keyInfo, keyStatErr := tlsFileStat(w.keyPath)
	if keyStatErr != nil {
		w.log.Warn().Err(keyStatErr).Str("key", w.keyPath).
			Msg("failed to stat key file")
	}

	// Edge case: If both stat calls fail, we don't update the modification times.
	// This prevents incorrectly treating a transient stat failure as "no change".
	// However, this means CheckCertificateModTime could return false positives on the next call
	// if either stat call fails again. Log a warning if this occurs.
	if certStatErr != nil && keyStatErr != nil {
		w.log.Warn().Msg("both cert and key stat failed during reload - mod times not updated, " +
			"next stat-based check may return false positives")
	}

	w.mu.Lock()
	w.tlsCert = &cert
	if certInfo != nil {
		w.tlsCertModTime = certInfo.ModTime()
	}
	if keyInfo != nil {
		w.tlsKeyModTime = keyInfo.ModTime()
	}
	w.mu.Unlock()

	w.log.Debug().Str("cert", w.certPath).Str("key", w.keyPath).
		Msg("TLS certificate reloaded")

	return nil
}

// CheckCertificateModTime checks if certificate or key files have been modified since last load.
// This is used as a fallback when inotify is not available.
func (w *TlsConfigWatcher) CheckCertificateModTime() bool {
	certInfo, err := tlsFileStat(w.certPath)
	if err != nil {
		w.log.Error().Err(err).Str("cert", w.certPath).Msg("failed to stat certificate file")

		return false
	}

	keyInfo, err := tlsFileStat(w.keyPath)
	if err != nil {
		w.log.Error().Err(err).Str("key", w.keyPath).Msg("failed to stat key file")

		return false
	}

	w.mu.RLock()
	certModTime := w.tlsCertModTime
	keyModTime := w.tlsKeyModTime
	w.mu.RUnlock()

	// Check if either file has been modified since last load
	if certInfo.ModTime().After(certModTime) || keyInfo.ModTime().After(keyModTime) {
		w.log.Debug().Msg("certificate or key file modification detected via stat")

		return true
	}

	return false
}
