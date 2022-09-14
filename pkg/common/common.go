package common

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf8"

	"zotregistry.io/zot/pkg/log"
)

const (
	httpTimeout        = 5 * time.Minute
	certsPath          = "/etc/containers/certs.d"
	homeCertsDir       = ".config/containers/certs.d"
	clientCertFilename = "client.cert"
	clientKeyFilename  = "client.key"
	caCertFilename     = "ca.crt"
)

func Contains(slice []string, item string) bool {
	for _, v := range slice {
		if item == v {
			return true
		}
	}

	return false
}

// first match of item in [].
func Index(slice []string, item string) int {
	for k, v := range slice {
		if item == v {
			return k
		}
	}

	return -1
}

// remove matches of item in [].
func RemoveFrom(input []string, item string) []string {
	var newList []string

	for _, v := range input {
		if item != v {
			newList = append(newList, v)
		}
	}

	return newList
}

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
		Timeout:   httpTimeout,
		Transport: htr,
	}, nil
}

func TypeOf(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

func MakeHTTPGetRequest(httpClient *http.Client, username string, password string, resultPtr interface{},
	blobURL string, mediaType string, log log.Logger,
) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, blobURL, nil) //nolint
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", mediaType)

	req.SetBasicAuth(username, password)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't get blob: %s", blobURL)

		return nil, -1, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't get blob: %s", blobURL)

		return nil, resp.StatusCode, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error().Str("status code", fmt.Sprint(resp.StatusCode)).Err(err).Msgf("couldn't get blob: %s", blobURL)

		return nil, resp.StatusCode, errors.New(string(body)) //nolint:goerr113
	}

	// read blob

	err = json.Unmarshal(body, &resultPtr)
	if err != nil {
		log.Error().Str("errorType", TypeOf(err)).
			Err(err).Msgf("couldn't unmarshal blob: %s", blobURL)

		return body, resp.StatusCode, err
	}

	return body, resp.StatusCode, err
}

func DirExists(d string) bool {
	if !utf8.ValidString(d) {
		return false
	}

	fileInfo, err := os.Stat(d)
	if err != nil {
		if e, ok := err.(*fs.PathError); ok && errors.Is(e.Err, syscall.ENAMETOOLONG) || //nolint: errorlint
			errors.Is(e.Err, syscall.EINVAL) {
			return false
		}
	}

	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fileInfo.IsDir() {
		return false
	}

	return true
}
