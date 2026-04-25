//go:build !metrics

//nolint:testpackage // Tests intentionally cover unexported client construction helpers.
package monitoring

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zotregistry.dev/zot/v2/pkg/log"
)

func TestNewHTTPMetricsClientDefaultRootsAndTLSMinVersion(t *testing.T) {
	t.Parallel()

	client, err := newHTTPMetricsClient("")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS1.2, got: %d", transport.TLSClientConfig.MinVersion)
	}

	if transport.TLSClientConfig.RootCAs != nil {
		t.Fatal("expected RootCAs to be nil when no custom CA is provided")
	}
}

func TestNewHTTPMetricsClientInvalidCACertPath(t *testing.T) {
	t.Parallel()

	_, err := newHTTPMetricsClient(filepath.Join(t.TempDir(), "missing-ca.pem"))
	if err == nil {
		t.Fatal("expected error for missing CA cert file")
	}
}

func TestNewHTTPMetricsClientInvalidCACertPEM(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caPath, []byte("not-a-pem-cert"), 0o600); err != nil {
		t.Fatalf("failed writing temp CA file: %v", err)
	}

	_, err := newHTTPMetricsClient(caPath)
	if err == nil {
		t.Fatal("expected error for invalid PEM CA cert file")
	}
}

func TestNewHTTPMetricsClientCustomCAValidatesServer(t *testing.T) {
	t.Parallel()

	caPEM, serverCert, serverKey, err := generateServerCertificateChain()
	if err != nil {
		t.Fatalf("failed generating cert chain: %v", err)
	}

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("failed writing CA PEM: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("failed loading server key pair: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	client, err := newHTTPMetricsClient(caPath)
	if err != nil {
		t.Fatalf("expected no error creating client with CA cert, got: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected TLS handshake to succeed with custom CA, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestNewMetricsClientFallbackKeepsTLSHardening(t *testing.T) {
	t.Parallel()

	cfg := &MetricsConfig{Address: "https://127.0.0.1:8443", CACert: filepath.Join(t.TempDir(), "missing-ca.pem")}
	mc := NewMetricsClient(cfg, log.NewLogger("debug", ""))

	transport, ok := mc.config.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected fallback transport to be *http.Transport, got %T", mc.config.HTTPClient.Transport)
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be present on fallback client")
	}

	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected fallback MinVersion TLS1.2, got: %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestMetricsClientReturnsErrorForUnexpectedStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := &MetricsConfig{Address: srv.URL}
	mc := NewMetricsClient(cfg, log.NewLogger("debug", ""))

	_, err := mc.GetMetrics()
	if err == nil {
		t.Fatal("expected error for unauthorized metrics response")
	}

	if !strings.Contains(err.Error(), "unexpected status code 401") {
		t.Fatalf("expected status code in error, got: %v", err)
	}
}

func generateServerCertificateChain() ([]byte, []byte, []byte, error) {
	now := time.Now()

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "zot-test-ca"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	return caPEM, serverCertPEM, serverKeyPEM, nil
}
