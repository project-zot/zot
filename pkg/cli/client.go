// +build extended

package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
)

var httpClientsMap = make(map[string]*http.Client) //nolint: gochecknoglobals
var httpClientLock sync.Mutex                      //nolint: gochecknoglobals

const (
	httpTimeout        = 5 * time.Minute
	certsPath          = "/etc/containers/certs.d"
	homeCertsDir       = ".config/containers/certs.d"
	clientCertFilename = "client.cert"
	clientKeyFilename  = "client.key"
	caCertFilename     = "ca.crt"
)

func createHTTPClient(verifyTLS bool, host string) *http.Client {
	var tr = http.DefaultTransport.(*http.Transport).Clone()
	if !verifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec

		return &http.Client{
			Timeout:   httpTimeout,
			Transport: tr,
		}
	}

	// Add a copy of the system cert pool
	caCertPool, _ := x509.SystemCertPool()

	tlsConfig := loadPerHostCerts(caCertPool, host)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{RootCAs: caCertPool}
	}

	tr = &http.Transport{TLSClientConfig: tlsConfig}

	return &http.Client{
		Timeout:   httpTimeout,
		Transport: tr,
	}
}

//nolint
func makeGETRequest(url, username, password string, verifyTLS bool, resultsPtr interface{}) (http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, password)

	return doHTTPRequest(req, verifyTLS, resultsPtr)
}

func makeGraphQLRequest(url, query, username,
	password string, verifyTLS bool, resultsPtr interface{}) error {
	req, err := http.NewRequest("GET", url, bytes.NewBufferString(query))
	if err != nil {
		return err
	}

	q := req.URL.Query()
	q.Add("query", query)

	req.URL.RawQuery = q.Encode()

	req.SetBasicAuth(username, password)
	req.Header.Add("Content-Type", "application/json")

	_, err = doHTTPRequest(req, verifyTLS, resultsPtr)
	if err != nil {
		return err
	}

	return nil
}

func doHTTPRequest(req *http.Request, verifyTLS bool, resultsPtr interface{}) (http.Header, error) {
	var httpClient *http.Client

	host := req.Host

	httpClientLock.Lock()

	if httpClientsMap[host] == nil {
		httpClient = createHTTPClient(verifyTLS, host)

		httpClientsMap[host] = httpClient
	} else {
		httpClient = httpClientsMap[host]
	}

	httpClientLock.Unlock()

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, zotErrors.ErrUnauthorizedAccess
		}

		bodyBytes, _ := ioutil.ReadAll(resp.Body)

		return nil, errors.New(string(bodyBytes)) //nolint: goerr113
	}

	if err := json.NewDecoder(resp.Body).Decode(resultsPtr); err != nil {
		return nil, err
	}

	return resp.Header, nil
}

func loadPerHostCerts(caCertPool *x509.CertPool, host string) *tls.Config {
	// Check if the /home/user/.config/containers/certs.d/$IP:$PORT dir exists
	home := os.Getenv("HOME")
	clientCertsDir := filepath.Join(home, homeCertsDir, host)

	if dirExists(clientCertsDir) {
		tlsConfig, err := getTLSConfig(clientCertsDir, caCertPool)

		if err == nil {
			return tlsConfig
		}
	}

	// Check if the /etc/containers/certs.d/$IP:$PORT dir exists
	clientCertsDir = filepath.Join(certsPath, host)
	if dirExists(clientCertsDir) {
		tlsConfig, err := getTLSConfig(clientCertsDir, caCertPool)

		if err == nil {
			return tlsConfig
		}
	}

	return nil
}

func getTLSConfig(certsPath string, caCertPool *x509.CertPool) (*tls.Config, error) {
	clientCert := filepath.Join(certsPath, clientCertFilename)
	clientKey := filepath.Join(certsPath, clientKeyFilename)
	caCertFile := filepath.Join(certsPath, caCertFilename)

	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}

	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}, nil
}

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fi.IsDir() {
		return false
	}

	return true
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
} // from https://stackoverflow.com/a/55551215
