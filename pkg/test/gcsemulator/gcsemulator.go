// Package gcsemulator points the distribution GCS driver at the storage-testbench
// emulator (GCSMOCK_ENDPOINT) for privileged tests.
//
// The driver always talks to the real Google endpoints over HTTPS, so Setup adds
// /etc/hosts entries redirecting them to 127.0.0.1 and serves an HTTPS proxy on port
// 443 that forwards to the emulator. Both need root (or CAP_NET_BIND_SERVICE), which
// is why only needprivileges builds use this package.
package gcsemulator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

var errBucketCreateFailed = errors.New("failed to create bucket")

// EndpointEnv names the environment variable holding the emulator endpoint.
const EndpointEnv = "GCSMOCK_ENDPOINT"

// httpsProxyServer manages an HTTPS proxy server on port 443.
type httpsProxyServer struct {
	server   *http.Server
	listener net.Listener
	wg       sync.WaitGroup
	target   string
	certFile string // Path to the certificate file for cleanup
}

// newHTTPSProxyServer creates a new HTTPS proxy server that forwards requests to the target.
func newHTTPSProxyServer(target string) (*httpsProxyServer, error) {
	// Generate self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "oauth2.googleapis.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"oauth2.googleapis.com", "www.googleapis.com", "storage.googleapis.com"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	// Write certificate to a temporary file so we can add it to the trusted certificates
	// via SSL_CERT_FILE environment variable. This is the standard way to add custom
	// trusted certificates and works with Go's crypto/x509 package, including OAuth2 clients.
	certFile, err := os.CreateTemp("", "gcs-test-cert-*.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp cert file: %w", err)
	}
	if _, err := certFile.Write(certPEM); err != nil {
		certFile.Close()
		os.Remove(certFile.Name())

		return nil, fmt.Errorf("failed to write cert to file: %w", err)
	}

	if err := certFile.Close(); err != nil {
		os.Remove(certFile.Name())

		return nil, fmt.Errorf("failed to close cert file: %w", err)
	}

	// Create proxy handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build target URL
		targetURL := target + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		// Create request to target.
		//nolint:gosec // proxy target is local test server
		req, err := http.NewRequestWithContext(
			r.Context(),
			r.Method,
			targetURL,
			r.Body,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		// Copy headers
		for key, values := range r.Header {
			if key != "Host" && key != "Connection" {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}

		// Make request
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req) //nolint:gosec // request is sent to local test server
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)

			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			if key != "Connection" && key != "Transfer-Encoding" {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
		}

		// Copy status and body
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// Create HTTP server with TLS config (test-only proxy).
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	// Try to listen on port 443 (requires root or CAP_NET_BIND_SERVICE for tests).
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", ":443") //nolint:gosec // G102: test proxy must listen on 443
	if err != nil {
		os.Remove(certFile.Name())

		return nil, fmt.Errorf("failed to listen on port 443: %w (may require root or CAP_NET_BIND_SERVICE)", err)
	}

	tlsListener := tls.NewListener(listener, server.TLSConfig)

	return &httpsProxyServer{
		server:   server,
		listener: tlsListener,
		target:   target,
		certFile: certFile.Name(),
	}, nil
}

func (p *httpsProxyServer) start() {
	p.wg.Go(func() {
		_ = p.server.Serve(p.listener)
	})
}

func (p *httpsProxyServer) stop() {
	_ = p.listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.server.Shutdown(ctx)
	p.wg.Wait()

	if p.certFile != "" {
		//nolint:gosec // G703: path is from CreateTemp in newHTTPSProxyServer, not user input
		os.Remove(p.certFile)
	}
}

// setupHostsEntries adds entries to /etc/hosts to redirect Google API domains to localhost.
// It returns the lines this invocation appended so teardown can remove only those.
func setupHostsEntries() ([]string, error) {
	entries := []string{
		"127.0.0.1 www.googleapis.com",
		"127.0.0.1 storage.googleapis.com",
		"127.0.0.1 oauth2.googleapis.com",
	}

	added := make([]string, 0, len(entries))

	for _, entry := range entries {
		// Check if entry already exists.
		//nolint:gosec // G204: test-only, fixed entries
		cmd := exec.CommandContext(context.Background(), "grep", "-q", strings.Fields(entry)[1], "/etc/hosts")
		if cmd.Run() == nil {
			// Entry already exists, skip
			continue
		}

		// Add entry (requires privileges).
		//nolint:gosec // G204: test-only, controlled entry
		cmd = exec.CommandContext(context.Background(), "sh", "-c", fmt.Sprintf("echo '%s' >> /etc/hosts", entry))
		if err := cmd.Run(); err != nil {
			return added, fmt.Errorf("failed to add %s to /etc/hosts: %w", entry, err)
		}

		added = append(added, entry)
	}

	return added, nil
}

// teardownHostsEntries removes only the /etc/hosts lines this harness appended.
func teardownHostsEntries(added []string) {
	for _, entry := range added {
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}

		domain := fields[1]
		// Delete only the localhost mapping we wrote (ip + domain), not other
		// pre-existing lines that mention the same domain.
		//nolint:gosec // G204: test-only, fixed domains
		pattern := fmt.Sprintf("/^127\\.0\\.0\\.1[[:space:]]\\+%s$/d", strings.ReplaceAll(domain, ".", "\\."))
		cmd := exec.CommandContext(context.Background(), "sed", "-i", pattern, "/etc/hosts")
		_ = cmd.Run() // Ignore errors - entry might not exist
	}
}

// Main wraps m.Run for a package TestMain. When GCSMOCK_ENDPOINT is set it adds the
// /etc/hosts entries and starts the HTTPS proxy before the tests, and removes both
// afterwards. It exits the process with the tests' exit code.
func Main(m *testing.M) {
	endpoint := os.Getenv(EndpointEnv)

	var proxy *httpsProxyServer

	var hostsAdded []string

	if endpoint != "" {
		var err error

		hostsAdded, err = setupHostsEntries()
		if err != nil {
			fmt.Printf("Warning: Could not modify /etc/hosts: %v\n", err)
			fmt.Printf("Tests may fail if /etc/hosts entries are not present\n")
		} else {
			fmt.Println("Added /etc/hosts entries for Google API domains")
		}

		proxy, err = newHTTPSProxyServer(strings.TrimSuffix(endpoint, "/"))
		if err != nil {
			// Fail fast: with /etc/hosts redirecting Google domains to 127.0.0.1,
			// OAuth/token calls will hit localhost:443 and fail with unclear errors
			// if the proxy is not listening. Require the proxy to start. Tear down
			// hosts first — os.Exit skips the normal Main teardown below.
			teardownHostsEntries(hostsAdded)
			fmt.Fprintf(os.Stderr, "Fatal: cannot start HTTPS proxy on port 443: %v\n", err)
			fmt.Fprintf(os.Stderr, "This may require root or CAP_NET_BIND_SERVICE. Exiting.\n")
			os.Exit(1)
		}

		proxy.start()
		// Set SSL_CERT_FILE to trust our self-signed certificate
		// This is respected by Go's crypto/x509 package when loading the system cert pool
		// and will affect all TLS connections, including those made by OAuth2 clients
		os.Setenv("SSL_CERT_FILE", proxy.certFile)
		fmt.Printf("HTTPS proxy started on port 443, certificate: %s\n", proxy.certFile)
	}

	code := m.Run()

	if proxy != nil {
		proxy.stop()
		fmt.Println("HTTPS proxy stopped")
	}

	if endpoint != "" {
		teardownHostsEntries(hostsAdded)
		fmt.Println("Removed /etc/hosts entries for Google API domains")
	}

	os.Exit(code)
}

// EnsureDummyCreds points GOOGLE_APPLICATION_CREDENTIALS at a throwaway service
// account key for the duration of the test, when the emulator is configured.
func EnsureDummyCreds(t *testing.T) {
	t.Helper()

	if os.Getenv(EndpointEnv) == "" {
		return
	}

	credsFile := path.Join(t.TempDir(), "dummy_creds.json")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	content := fmt.Sprintf(`{"type": "service_account", "project_id": "test-project", `+
		`"client_email": "test@test.com", "private_key": %q}`, string(privPEM))
	if err := os.WriteFile(credsFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)
}

// CreateBucket creates the bucket on the emulator; an existing bucket is fine.
func CreateBucket(bucket string) error {
	url := strings.TrimSuffix(os.Getenv(EndpointEnv), "/") + "/storage/v1/b?project=test-project"
	body := fmt.Sprintf(`{"name": "%s"}`, bucket)

	//nolint:gosec // URL points to the emulator endpoint in tests
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: test emulator
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated ||
		resp.StatusCode == http.StatusConflict {
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)

	return fmt.Errorf("%w %s: status %d body %s", errBucketCreateFailed, bucket, resp.StatusCode, string(respBody))
}
