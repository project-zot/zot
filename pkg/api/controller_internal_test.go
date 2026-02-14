//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api

import (
	goerrors "errors"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"zotregistry.dev/zot/v2/pkg/log"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

var errGetCertificateFailed = goerrors.New("GetCertificate failed")

func TestReloadCertificateStatFailureKeepsModTimes(t *testing.T) {
	logger := log.NewLogger("debug", "")
	tempDir := t.TempDir()

	certPath := path.Join(tempDir, "cert.pem")
	keyPath := path.Join(tempDir, "key.pem")

	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
		KeyType:    tlsutils.KeyTypeECDSA,
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeECDSA,
	}
	if err := tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, serverOpts); err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	watcher := NewTlsConfigWatcher(certPath, keyPath, logger)

	if err := watcher.ReloadCertificate(); err != nil {
		t.Fatalf("failed to load initial certificate: %v", err)
	}

	watcher.mu.RLock()
	initialCertModTime := watcher.tlsCertModTime
	initialKeyModTime := watcher.tlsKeyModTime
	watcher.mu.RUnlock()

	if initialCertModTime.IsZero() || initialKeyModTime.IsZero() {
		t.Fatal("expected initial mod times to be set")
	}

	originalStat := tlsFileStat
	tlsFileStat = func(string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() {
		tlsFileStat = originalStat
	})

	time.Sleep(10 * time.Millisecond)
	if err := watcher.ReloadCertificate(); err != nil {
		t.Fatalf("unexpected reload error when stat fails: %v", err)
	}

	watcher.mu.RLock()
	updatedCertModTime := watcher.tlsCertModTime
	updatedKeyModTime := watcher.tlsKeyModTime
	watcher.mu.RUnlock()

	if !updatedCertModTime.Equal(initialCertModTime) {
		t.Fatal("certificate mod time changed despite stat failure")
	}
	if !updatedKeyModTime.Equal(initialKeyModTime) {
		t.Fatal("key mod time changed despite stat failure")
	}
}

func TestGetCertificateReloadConcurrency(t *testing.T) {
	logger := log.NewLogger("debug", "")
	tempDir := t.TempDir()

	certPath := path.Join(tempDir, "cert.pem")
	keyPath := path.Join(tempDir, "key.pem")

	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
		KeyType:    tlsutils.KeyTypeECDSA,
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeECDSA,
	}
	if err := tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, serverOpts); err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	watcher := NewTlsConfigWatcher(certPath, keyPath, logger)

	if err := watcher.ReloadCertificate(); err != nil {
		t.Fatalf("failed to load initial certificate: %v", err)
	}

	var wg sync.WaitGroup
	errorCh := make(chan error, 32)

	reloadWorker := func(iterations int) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := watcher.ReloadCertificate(); err != nil {
				errorCh <- err
				return
			}
		}
	}

	getWorker := func(iterations int) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cert, err := watcher.GetCertificate(nil)
			if err != nil || cert == nil {
				errorCh <- err
				return
			}
		}
	}

	wg.Add(3)
	go reloadWorker(50)
	go getWorker(100)
	go getWorker(100)

	wg.Wait()
	close(errorCh)

	for err := range errorCh {
		if err != nil {
			t.Fatalf("concurrent TLS operations failed: %v", err)
		}
	}
}

func TestGetCertificateInitialLoadConcurrency(t *testing.T) {
	logger := log.NewLogger("debug", "")
	tempDir := t.TempDir()

	certPath := path.Join(tempDir, "cert.pem")
	keyPath := path.Join(tempDir, "key.pem")

	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
		KeyType:    tlsutils.KeyTypeECDSA,
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeECDSA,
	}
	if err := tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, serverOpts); err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	watcher := NewTlsConfigWatcher(certPath, keyPath, logger)

	var wg sync.WaitGroup
	results := make(chan error, 16)

	worker := func(iterations int) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cert, err := watcher.GetCertificate(nil)
			if err == nil && cert == nil {
				results <- errGetCertificateFailed
				return
			}
			if err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}

	for range 8 {
		wg.Add(1)
		go worker(10)
	}

	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Fatalf("concurrent initial TLS load failed: %v", err)
		}
	}
}

func TestStartCertificateWatcherAddFailureFallsBack(t *testing.T) {
	logger := log.NewLogger("debug", "")
	tempDir := t.TempDir()

	keyPath := path.Join(tempDir, "key.pem")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	watcher := NewTlsConfigWatcher(path.Join(tempDir, "missing-cert.pem"), keyPath, logger)

	if err := watcher.Start(); err == nil {
		t.Fatal("expected watcher setup to fail for missing certificate file")
	}
	if watcher.UseInotify() {
		t.Fatal("expected file watching to be disabled after watcher add failure")
	}
}

func TestCertificateWatcherHandlesAtomicRename(t *testing.T) {
	logger := log.NewLogger("debug", "")
	tempDir := t.TempDir()

	certPath := path.Join(tempDir, "cert.pem")
	keyPath := path.Join(tempDir, "key.pem")

	// Generate initial certificates
	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
		KeyType:    tlsutils.KeyTypeECDSA,
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer-Initial",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeECDSA,
	}
	if err := tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, serverOpts); err != nil {
		t.Fatalf("failed to generate initial server cert: %v", err)
	}

	watcher := NewTlsConfigWatcher(certPath, keyPath, logger)

	if err := watcher.ReloadCertificate(); err != nil {
		t.Fatalf("failed to load initial certificate: %v", err)
	}

	if err := watcher.Start(); err != nil {
		t.Fatalf("failed to start certificate watcher: %v", err)
	}
	defer watcher.Stop()

	watcher.mu.RLock()
	initialModTime := watcher.tlsCertModTime
	watcher.mu.RUnlock()

	// Simulate atomic certificate replacement via rename (common pattern in k8s, cert-manager, etc.)
	// Sleep long enough to ensure filesystem records different timestamps (at least 1 second
	// to account for systems with second-level timestamp precision)
	time.Sleep(1100 * time.Millisecond)

	newServerOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.2",
		CommonName:         "*",
		OrganizationalUnit: "TestServer-Rotated",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeECDSA,
	}

	// Write to temp files first
	tempCertPath := certPath + ".tmp"
	tempKeyPath := keyPath + ".tmp"
	if err := tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, tempCertPath, tempKeyPath, newServerOpts); err != nil {
		t.Fatalf("failed to generate temp server cert: %v", err)
	}

	// Atomic rename (this is how most certificate rotation works)
	if err := os.Rename(tempCertPath, certPath); err != nil {
		t.Fatalf("failed to rename cert: %v", err)
	}
	if err := os.Rename(tempKeyPath, keyPath); err != nil {
		t.Fatalf("failed to rename key: %v", err)
	}

	// Poll until the certificate is reloaded or timeout is reached.
	// This accounts for fsnotify delivery time plus the 150ms debounce interval,
	// which can exceed fixed sleeps on slower systems.
	deadline := time.Now().Add(2 * time.Second)
	var newModTime time.Time
	reloaded := false
	for time.Now().Before(deadline) {
		watcher.mu.RLock()
		newModTime = watcher.tlsCertModTime
		watcher.mu.RUnlock()

		if newModTime.After(initialModTime) {
			reloaded = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !reloaded {
		t.Fatalf("expected certificate to be reloaded after atomic rename within 2s, initial: %v, new: %v",
			initialModTime, newModTime)
	}
}

func TestCertificateWatcherCanRestart(t *testing.T) {
	logger := log.NewLogger("debug", "")
	tempDir := t.TempDir()

	certPath := path.Join(tempDir, "cert.pem")
	keyPath := path.Join(tempDir, "key.pem")

	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
		KeyType:    tlsutils.KeyTypeECDSA,
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyType:            tlsutils.KeyTypeECDSA,
	}
	if err := tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, serverOpts); err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	watcher := NewTlsConfigWatcher(certPath, keyPath, logger)

	// Load initial certificate
	if err := watcher.ReloadCertificate(); err != nil {
		t.Fatalf("failed to load initial certificate: %v", err)
	}

	// Start the watcher
	if err := watcher.Start(); err != nil {
		t.Fatalf("failed to start certificate watcher: %v", err)
	}

	// Verify UseInotify returns true while running
	if !watcher.UseInotify() {
		t.Fatalf("expected UseInotify() to be true after Start()")
	}

	// Stop the watcher
	watcher.Stop()
	time.Sleep(100 * time.Millisecond) // Allow cleanup to complete

	// Verify UseInotify returns false after Stop
	if watcher.UseInotify() {
		t.Fatalf("expected UseInotify() to be false after Stop()")
	}

	// Verify we can call Start() again (should not return error)
	if err := watcher.Start(); err != nil {
		t.Fatalf("failed to restart certificate watcher: %v", err)
	}

	// Verify UseInotify is true again
	if !watcher.UseInotify() {
		t.Fatalf("expected UseInotify() to be true after restart")
	}

	watcher.Stop()
}
