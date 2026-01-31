package api

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// CertReloader handles automatic reloading of TLS certificates without downtime.
// It monitors certificate and key files for changes and reloads them dynamically
// using a GetCertificate callback in tls.Config.
type CertReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
	certMod  time.Time
	keyMod   time.Time
}

// NewCertReloader creates a new certificate reloader and loads the initial certificate.
func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	reloader := &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}

	if err := reloader.reload(); err != nil {
		return nil, err
	}

	return reloader, nil
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
func (cr *CertReloader) maybeReload() error {
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
		return cr.reload()
	}

	return nil
}

// GetCertificateFunc returns a function that can be used as tls.Config.GetCertificate.
// This function checks for certificate updates on each TLS handshake and reloads if necessary.
func (cr *CertReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Try to reload the certificate if it has changed
		// Ignore errors during reload attempts - keep using the existing certificate
		_ = cr.maybeReload()

		cr.certMu.RLock()
		defer cr.certMu.RUnlock()

		return cr.cert, nil
	}
}
