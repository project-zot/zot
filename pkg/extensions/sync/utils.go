//go:build sync

package sync

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

// Get sync.FileCredentials from file.
func getFileCredentials(filepath string) (syncconf.CredentialsFile, error) {
	credsFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds syncconf.CredentialsFile

	err = json.Unmarshal(credsFile, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

// parse a reference, return its digest and if it's valid.
func parseReference(reference string) (digest.Digest, bool) {
	var ok bool

	d, err := digest.Parse(reference)
	if err == nil {
		ok = true
	}

	return d, ok
}

// Given a list of registry string URLs parse them and return *url.URLs slice.
func parseRegistryURLs(rawURLs []string) ([]*url.URL, error) {
	urls := make([]*url.URL, 0, len(rawURLs))

	for _, rawURL := range rawURLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}

		urls = append(urls, u)
	}

	return urls, nil
}

func GetDescriptorReference(desc ispec.Descriptor) string {
	v, ok := desc.Annotations[ispec.AnnotationRefName]
	if ok {
		return v
	}

	return desc.Digest.String()
}

func StripRegistryTransport(url string) string {
	return strings.Replace(strings.Replace(url, "http://", "", 1), "https://", "", 1)
}

func getCertificates(certDir string) (string, string, string, error) {
	var clientCert string

	var clientKey string

	var regCert string

	// Prefer canonical filenames when present to avoid ambiguity when a cert dir
	// contains multiple *.cert/*.key files.
	clientCertPath := path.Join(certDir, "client.cert")
	if buf, err := os.ReadFile(clientCertPath); err == nil {
		clientCert = string(buf)
	} else if !os.IsNotExist(err) {
		return "", "", "", err
	}

	clientKeyPath := path.Join(certDir, "client.key")
	if buf, err := os.ReadFile(clientKeyPath); err == nil {
		clientKey = string(buf)
	} else if !os.IsNotExist(err) {
		return "", "", "", err
	}

	caCertPath := path.Join(certDir, "ca.crt")
	if buf, err := os.ReadFile(caCertPath); err == nil {
		regCert = string(buf)
	} else if !os.IsNotExist(err) {
		return "", "", "", err
	}

	files, err := os.ReadDir(certDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", "", nil
		}

		return "", "", "", err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if clientCert == "" && strings.HasSuffix(file.Name(), ".cert") {
			certPath := path.Join(certDir, file.Name())

			buf, err := os.ReadFile(certPath)
			if err != nil {
				return "", "", "", err
			}

			clientCert = string(buf)
		}

		if clientKey == "" && strings.HasSuffix(file.Name(), ".key") {
			certPath := path.Join(certDir, file.Name())

			buf, err := os.ReadFile(certPath)
			if err != nil {
				return "", "", "", err
			}

			clientKey = string(buf)
		}

		if regCert == "" && strings.HasSuffix(file.Name(), ".crt") {
			certPath := path.Join(certDir, file.Name())

			buf, err := os.ReadFile(certPath)
			if err != nil {
				return "", "", "", err
			}

			regCert = string(buf)
		}
	}

	return clientCert, clientKey, regCert, nil
}
