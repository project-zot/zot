package test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"os"
	"path"
	"time"

	godigest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/phayes/freeport"
	"gopkg.in/resty.v1"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	SleepTime     = 100 * time.Millisecond
)

func GetFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return fmt.Sprint(port)
}

func GetBaseURL(port string) string {
	return fmt.Sprintf(BaseURL, port)
}

func GetSecureBaseURL(port string) string {
	return fmt.Sprintf(BaseSecureURL, port)
}

func MakeHtpasswdFile() string {
	// bcrypt(username="test", passwd="test")
	content := "test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n"

	return MakeHtpasswdFileFromString(content)
}

func MakeHtpasswdFileFromString(fileContent string) string {
	htpasswdFile, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte(fileContent)
	if err := ioutil.WriteFile(htpasswdFile.Name(), content, 0o600); err != nil { //nolint:gomnd
		panic(err)
	}

	return htpasswdFile.Name()
}

func Location(baseURL string, resp *resty.Response) string {
	// For some API responses, the Location header is set and is supposed to
	// indicate an opaque value. However, it is not clear if this value is an
	// absolute URL (https://server:port/v2/...) or just a path (/v2/...)
	// zot implements the latter as per the spec, but some registries appear to
	// return the former - this needs to be clarified
	loc := resp.Header().Get("Location")

	uloc, err := url.Parse(loc)
	if err != nil {
		return ""
	}

	path := uloc.Path

	return baseURL + path
}

func CopyFiles(sourceDir, destDir string) error {
	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles os.Stat failed: %w", err)
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return fmt.Errorf("CopyFiles os.MkdirAll failed: %w", err)
	}

	files, err := ioutil.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles ioutil.ReadDir failed: %w", err)
	}

	for _, file := range files {
		sourceFilePath := path.Join(sourceDir, file.Name())
		destFilePath := path.Join(destDir, file.Name())

		if file.IsDir() {
			if err = CopyFiles(sourceFilePath, destFilePath); err != nil {
				return err
			}
		} else {
			sourceFile, err := os.Open(sourceFilePath)
			if err != nil {
				return fmt.Errorf("CopyFiles os.Open failed: %w", err)
			}
			defer sourceFile.Close()

			destFile, err := os.Create(destFilePath)
			if err != nil {
				return fmt.Errorf("CopyFiles os.Create failed: %w", err)
			}
			defer destFile.Close()

			if _, err = io.Copy(destFile, sourceFile); err != nil {
				return fmt.Errorf("io.Copy failed: %w", err)
			}
		}
	}

	return nil
}

func WaitTillServerReady(url string) {
	for {
		_, err := resty.R().Get(url)
		if err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

// Adapted from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
func randomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

	ret := make([]byte, n)

	for count := 0; count < n; count++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}

		ret[count] = letters[num.Int64()]
	}

	return string(ret)
}

func GetRandomImageConfig() ([]byte, godigest.Digest) {
	const maxLen = 16

	randomAuthor := randomString(maxLen)

	config := imagespec.Image{
		Architecture: "amd64",
		OS:           "linux",
		RootFS: imagespec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: randomAuthor,
	}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}

func GetImageConfig() ([]byte, godigest.Digest) {
	config := imagespec.Image{
		Architecture: "amd64",
		OS:           "linux",
		RootFS: imagespec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "some author",
	}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}

func GetOciLayoutDigests(imagePath string) (godigest.Digest, godigest.Digest, godigest.Digest) {
	var (
		manifestDigest godigest.Digest
		configDigest   godigest.Digest
		layerDigest    godigest.Digest
	)

	oci, err := umoci.OpenLayout(imagePath)
	if err != nil {
		panic(err)
	}

	defer oci.Close()

	ctxUmoci := context.Background()

	index, err := oci.GetIndex(ctxUmoci)
	if err != nil {
		panic(err)
	}

	for _, manifest := range index.Manifests {
		manifestDigest = manifest.Digest

		manifestBlob, err := oci.GetBlob(ctxUmoci, manifest.Digest)
		if err != nil {
			panic(err)
		}

		manifestBuf, err := ioutil.ReadAll(manifestBlob)
		if err != nil {
			panic(err)
		}

		var manifest imagespec.Manifest

		err = json.Unmarshal(manifestBuf, &manifest)
		if err != nil {
			panic(err)
		}

		configDigest = manifest.Config.Digest

		for _, layer := range manifest.Layers {
			layerDigest = layer.Digest
		}
	}

	return manifestDigest, configDigest, layerDigest
}
