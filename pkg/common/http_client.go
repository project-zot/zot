package common

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
)

func GetTLSConfig(certsPath string, caCertPool *x509.CertPool) (*tls.Config, error) {
	clientCert := filepath.Join(certsPath, ClientCertFilename)
	clientKey := filepath.Join(certsPath, ClientKeyFilename)
	caCertFile := filepath.Join(certsPath, CaCertFilename)

	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}

	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func loadPerHostCerts(caCertPool *x509.CertPool, host string) *tls.Config {
	// Check if the /home/user/.config/containers/certs.d/$IP:$PORT dir exists
	home := os.Getenv("HOME")
	clientCertsDir := filepath.Join(home, homeCertsDir, host)

	if DirExists(clientCertsDir) {
		tlsConfig, err := GetTLSConfig(clientCertsDir, caCertPool)
		if err == nil {
			return tlsConfig
		}
	}

	// Check if the /etc/containers/certs.d/$IP:$PORT dir exists
	clientCertsDir = filepath.Join(certsPath, host)
	if DirExists(clientCertsDir) {
		tlsConfig, err := GetTLSConfig(clientCertsDir, caCertPool)
		if err == nil {
			return tlsConfig
		}
	}

	return nil
}

// Holds certificate options for an HTTP client.
type HTTPClientCertOptions struct {
	ClientCertFile string // Holds the path to the client certificate file. Mandatory if ClientKeyFile is present.
	ClientKeyFile  string // Holds the path to the client key file. Mandatory if ClientCertFile is present.
	RootCaCertFile string // Optional. Holds the path to the custom Root CA cert file.
}

// Holds client options for creating an HTTP client.
type HTTPClientOptions struct {
	// Results in a client with TLS config if true.
	TLSEnabled bool

	// Results in a client without certificate config and TLS verification disabled if true.
	// Note: if TLSEnabled is false and VerifyTLS is true, the client will not have the verification
	// of insecure certificates set to false. For this, both TLSEnabled and VerifyTLS need to be
	// true.
	VerifyTLS bool

	// The target host for the imminent connection. Used for loading host specific certificates if any.
	Host string

	// Certificate options for the client.
	CertOptions HTTPClientCertOptions
}

func CreateHTTPClient(clientOptions *HTTPClientOptions) (*http.Client, error) {
	htr := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert

	// If TLS is not enabled, return the client without any further TLS config.
	if !clientOptions.TLSEnabled {
		return &http.Client{
			Timeout:   httpTimeout,
			Transport: htr,
		}, nil
	}

	if !clientOptions.VerifyTLS {
		htr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec

		return &http.Client{
			Timeout:   httpTimeout,
			Transport: htr,
		}, nil
	}

	// Add a copy of the system cert pool.
	caCertPool, _ := x509.SystemCertPool()

	// Add a custom CA cert if present in the options.
	if clientOptions.CertOptions.RootCaCertFile != "" {
		caCert, err := os.ReadFile(clientOptions.CertOptions.RootCaCertFile)
		if err != nil {
			return nil, err
		}

		caCertPool.AppendCertsFromPEM(caCert)
	}

	// Load certificates specific to the host if any.
	tlsConfig := loadPerHostCerts(caCertPool, clientOptions.Host)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12}
	}

	// Try to load certificate key pair if either are present in the options.
	if clientOptions.CertOptions.ClientCertFile != "" || clientOptions.CertOptions.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientOptions.CertOptions.ClientCertFile, clientOptions.CertOptions.ClientKeyFile)
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	htr.TLSClientConfig = tlsConfig

	return &http.Client{
		Transport: htr,
		Timeout:   httpTimeout,
	}, nil
}
