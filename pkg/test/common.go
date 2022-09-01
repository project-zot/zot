package test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
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

var (
	ErrPostBlob = errors.New("can't post blob")
	ErrPutBlob  = errors.New("can't put blob")
)

type Image struct {
	Manifest imagespec.Manifest
	Config   imagespec.Image
	Layers   [][]byte
	Tag      string
}

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
	htpasswdFile, err := os.CreateTemp("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte(fileContent)
	if err := os.WriteFile(htpasswdFile.Name(), content, 0o600); err != nil { //nolint:gomnd
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

	files, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles os.ReadDir failed: %w", err)
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

func WaitTillTrivyDBDownloadStarted(rootDir string) {
	for {
		if _, err := os.Stat(path.Join(rootDir, "trivy.db")); err == nil {
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

		manifestBuf, err := io.ReadAll(manifestBlob)
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

func GetImageComponents(layerSize int) (imagespec.Image, [][]byte, imagespec.Manifest, error) {
	config := imagespec.Image{
		Architecture: "amd64",
		OS:           "linux",
		RootFS: imagespec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err = Error(err); err != nil {
		return imagespec.Image{}, [][]byte{}, imagespec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		make([]byte, layerSize),
	}

	schemaVersion := 2

	manifest := imagespec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: imagespec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []imagespec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return config, layers, manifest, nil
}

func UploadImage(img Image, baseURL, repo string) error {
	for _, blob := range img.Layers {
		resp, err := resty.R().Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusAccepted {
			return ErrPostBlob
		}

		loc := resp.Header().Get("Location")

		digest := godigest.FromBytes(blob).String()

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)

		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusCreated {
			return ErrPutBlob
		}
	}
	// upload config
	cblob, err := json.Marshal(img.Config)
	if err = Error(err); err != nil {
		return err
	}

	cdigest := godigest.FromBytes(cblob)

	resp, err := resty.R().
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = Error(err); err != nil {
		return err
	}

	if ErrStatusCode(resp.StatusCode()) != http.StatusAccepted && ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	loc := Location(baseURL, resp)

	// uploading blob should get 201
	resp, err = resty.R().
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)
	if err = Error(err); err != nil {
		return err
	}

	if ErrStatusCode(resp.StatusCode()) != http.StatusCreated && ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	// put manifest
	manifestBlob, err := json.Marshal(img.Manifest)
	if err = Error(err); err != nil {
		return err
	}

	_, err = resty.R().
		SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + img.Tag)

	return err
}
