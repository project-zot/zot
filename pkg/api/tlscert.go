package api

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	// certCheckCacheDuration is the minimum time between file stat checks when fsnotify is unavailable.
	// This prevents excessive file system calls during high TLS handshake rates.
	certCheckCacheDuration = 1 * time.Second
)

// CertReloader handles automatic reloading of TLS certificates without downtime.
// It monitors certificate and key files for changes and reloads them dynamically
// using a GetCertificate callback in tls.Config.
type CertReloader struct {
	certMu      sync.RWMutex
	cert        *tls.Certificate
	certPath    string
	keyPath     string
	certMod     time.Time
	keyMod      time.Time
	log         log.Logger
	watcher     *fsnotify.Watcher
	reloadMu    sync.Mutex // Prevents concurrent reload operations
	lastCheck   time.Time
	checkCache  time.Duration // Minimum time between file stat checks
	stopWatcher chan struct{}
	closeOnce   sync.Once // Ensures Close() can be called multiple times safely
}

// NewCertReloader creates a new certificate reloader and loads the initial certificate.
// It starts an fsnotify watcher to monitor certificate file changes.
func NewCertReloader(certPath, keyPath string, logger log.Logger) (*CertReloader, error) {
	reloader := &CertReloader{
		certPath:    certPath,
		keyPath:     keyPath,
		log:         logger,
		checkCache:  certCheckCacheDuration,
		stopWatcher: make(chan struct{}),
	}

	if err := reloader.reload(); err != nil {
		return nil, err
	}

	// Start fsnotify watcher in background
	if err := reloader.startWatcher(); err != nil {
		// Log warning but don't fail - we'll fall back to periodic checking
		logger.Warn().Err(err).Msg("failed to start fsnotify watcher, falling back to periodic checking")
	}

	// NOTE: Do not add initialization that can fail after this point without ensuring
	// the watcher is stopped (e.g., by calling Close on error), otherwise the
	// watchLoop goroutine started by startWatcher could be leaked.

	return reloader, nil
}

// Close stops the file watcher and releases resources.
// This method is safe to call multiple times.
func (cr *CertReloader) Close() error {
	var err error
	cr.closeOnce.Do(func() {
		if cr.stopWatcher != nil {
			close(cr.stopWatcher)
		}

		if cr.watcher != nil {
			err = cr.watcher.Close()
		}
	})

	return err
}

// startWatcher initializes the fsnotify watcher for certificate files.
func (cr *CertReloader) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	cr.watcher = watcher

	// Watch the directory containing the certificate files
	// This is more reliable than watching files directly, especially for atomic file updates
	certDir := filepath.Dir(cr.certPath)
	keyDir := filepath.Dir(cr.keyPath)

	if err := watcher.Add(certDir); err != nil {
		watcher.Close()
		return err
	}

	// If cert and key are in different directories, watch both
	if certDir != keyDir {
		if err := watcher.Add(keyDir); err != nil {
			watcher.Close()
			return err
		}
	}

	// Start goroutine to handle file system events
	go cr.watchLoop()

	return nil
}

// watchLoop handles file system events from fsnotify.
func (cr *CertReloader) watchLoop() {
	for {
		select {
		case <-cr.stopWatcher:
			return
		case event, ok := <-cr.watcher.Events:
			if !ok {
				return
			}

			// Check if the event is for our certificate or key files
			if event.Name == cr.certPath || event.Name == cr.keyPath {
				// Only process write and create events
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					cr.log.Debug().Str("file", event.Name).Str("op", event.Op.String()).
						Msg("certificate file change detected")

					// Try to reload the certificate
					cr.tryReload()
				}
			}
		case err, ok := <-cr.watcher.Errors:
			if !ok {
				return
			}
			cr.log.Warn().Err(err).Msg("fsnotify watcher error")
		}
	}
}

// tryReload attempts to reload certificates with proper concurrency control.
func (cr *CertReloader) tryReload() {
	// Use mutex to ensure only one reload happens at a time
	// This prevents race condition where multiple goroutines detect changes simultaneously
	cr.reloadMu.Lock()
	defer cr.reloadMu.Unlock()

	if err := cr.reload(); err != nil {
		cr.log.Warn().Err(err).Str("cert", cr.certPath).Str("key", cr.keyPath).
			Msg("failed to reload TLS certificates")
	} else {
		cr.log.Info().Str("cert", cr.certPath).Str("key", cr.keyPath).
			Msg("TLS certificates reloaded successfully")
	}
}

// reload loads the certificate and key from disk and updates the internal certificate.
func (cr *CertReloader) reload() error {
	// Get file modification times
	certInfo, err := os.Stat(cr.certPath)
	if err != nil {
		return err
	}

	keyInfo, err := os.Stat(cr.keyPath)
	if err != nil {
		return err
	}

	certMod := certInfo.ModTime()
	keyMod := keyInfo.ModTime()

	// Load the certificate
	newCert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
	if err != nil {
		return err
	}

	// Update the certificate and modification times
	cr.certMu.Lock()
	defer cr.certMu.Unlock()

	cr.cert = &newCert
	cr.certMod = certMod
	cr.keyMod = keyMod

	return nil
}

// maybeReload checks if the certificate files have been modified and reloads them if necessary.
// This is used as a fallback when fsnotify is not available or fails.
// Uses time-based caching to avoid excessive file system calls.
func (cr *CertReloader) maybeReload() error {
	// Use write lock for both check and update to prevent race conditions
	// While less efficient than RLock+Lock upgrade, this ensures only one goroutine
	// updates lastCheck at a time, preventing multiple goroutines from bypassing
	// the cache check simultaneously. Since we have a 1-second cache, this lock
	// is acquired at most once per second, making the performance impact acceptable.
	cr.certMu.Lock()
	if time.Since(cr.lastCheck) < cr.checkCache {
		// Recently checked, skip stat calls
		cr.certMu.Unlock()

		return nil
	}
	// Update last check time within the same critical section as the cache check
	cr.lastCheck = time.Now()
	cr.certMu.Unlock()

	// Check cert file modification time
	certInfo, err := os.Stat(cr.certPath)
	if err != nil {
		return err
	}

	keyInfo, err := os.Stat(cr.keyPath)
	if err != nil {
		return err
	}

	certMod := certInfo.ModTime()
	keyMod := keyInfo.ModTime()

	// Check if files have been modified
	cr.certMu.RLock()
	needsReload := certMod.After(cr.certMod) || keyMod.After(cr.keyMod)
	cr.certMu.RUnlock()

	if needsReload {
		// Use reloadMu to prevent concurrent reload operations
		cr.reloadMu.Lock()
		defer cr.reloadMu.Unlock()

		// Double-check after acquiring lock - another goroutine might have already reloaded
		cr.certMu.RLock()
		stillNeedsReload := certMod.After(cr.certMod) || keyMod.After(cr.keyMod)
		cr.certMu.RUnlock()

		if stillNeedsReload {
			if err := cr.reload(); err != nil {
				cr.log.Warn().Err(err).Str("cert", cr.certPath).Str("key", cr.keyPath).
					Msg("failed to reload TLS certificates")

				return err
			}

			cr.log.Info().Str("cert", cr.certPath).Str("key", cr.keyPath).
				Msg("TLS certificates reloaded successfully")
		}
	}

	return nil
}

// GetCertificateFunc returns a function that can be used as tls.Config.GetCertificate.
// This function checks for certificate updates on each TLS handshake and reloads if necessary.
// If fsnotify watcher is active, this only performs time-cached checks as a fallback.
func (cr *CertReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Try to reload the certificate if it has changed
		// This is a fallback mechanism when fsnotify is not available
		// Errors are logged but ignored to maintain availability with existing certificate
		_ = cr.maybeReload()

		cr.certMu.RLock()
		defer cr.certMu.RUnlock()

		return cr.cert, nil
	}
}
