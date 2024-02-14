package common

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

func GetTLSConfig(certsPath string, caCertPool *x509.CertPool) (*tls.Config, error) {
	clientCert := filepath.Join(certsPath, clientCertFilename)
	clientKey := filepath.Join(certsPath, clientKeyFilename)
	caCertFile := filepath.Join(certsPath, caCertFilename)

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

func CreateHTTPClient(verifyTLS bool, host string, certDir string) (*http.Client, error) {
	htr := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	if !verifyTLS {
		htr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec

		return &http.Client{
			Timeout:   httpTimeout,
			Transport: htr,
		}, nil
	}

	// Add a copy of the system cert pool
	caCertPool, _ := x509.SystemCertPool()

	tlsConfig := loadPerHostCerts(caCertPool, host)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12}
	}

	htr.TLSClientConfig = tlsConfig

	if certDir != "" {
		clientCert := path.Join(certDir, "client.cert")
		clientKey := path.Join(certDir, "client.key")
		caCertPath := path.Join(certDir, "ca.crt")

		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, err
		}

		caCertPool.AppendCertsFromPEM(caCert)

		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, err
		}

		htr.TLSClientConfig.Certificates = append(htr.TLSClientConfig.Certificates, cert)
	}

	return &http.Client{
		Transport: htr,
		Timeout:   httpTimeout,
	}, nil
}
