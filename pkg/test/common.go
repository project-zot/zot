package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mathRand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/phayes/freeport"
	"github.com/project-zot/mockoidc"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	zLog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	storageCommon "zotregistry.io/zot/pkg/storage/common"
	"zotregistry.io/zot/pkg/storage/local"
	stypes "zotregistry.io/zot/pkg/storage/types"
	"zotregistry.io/zot/pkg/test/inject"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	SleepTime     = 100 * time.Millisecond
)

var ErrNoGoModFileFound = errors.New("test: no go.mod file found in parent directories")

var vulnerableLayer []byte //nolint: gochecknoglobals

var NotationPathLock = new(sync.Mutex) //nolint: gochecknoglobals

// which: manifest, config, layer
func GetTestBlobDigest(image, which string) godigest.Digest {
	prePath := "../test/data"

	for _, err := os.Stat(prePath); err != nil; _, err = os.Stat(prePath) {
		prePath = "../" + prePath
	}

	imgPath := path.Join(prePath, image)
	manifest, config, layer := GetOciLayoutDigests(imgPath)

	switch which {
	case "manifest":
		return manifest
	case "config":
		return config
	case "layer":
		return layer
	}

	return ""
}

var (
	ErrPostBlob    = errors.New("can't post blob")
	ErrPutBlob     = errors.New("can't put blob")
	ErrKeyNotFound = errors.New("key not found")
	ErrPutIndex    = errors.New("can't put index")
)

type ArtifactBlobs struct {
	Blob      []byte
	MediaType string
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

func GetCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
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
			if strings.HasPrefix(file.Name(), "_") {
				// Some tests create the trivy related folders under test/_trivy
				continue
			}

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

func CopyTestFiles(sourceDir, destDir string) {
	err := CopyFiles(sourceDir, destDir)
	if err != nil {
		panic(err)
	}
}

func CopyTestKeysAndCerts(destDir string) error {
	files := []string{
		"ca.crt", "ca.key", "client.cert", "client.csr",
		"client.key", "server.cert", "server.csr", "server.key",
	}

	rootPath, err := GetProjectRootDir()
	if err != nil {
		return err
	}

	sourceDir := filepath.Join(rootPath, "test/data")

	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles os.Stat failed: %w", err)
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return err
	}

	for _, file := range files {
		err = CopyFile(filepath.Join(sourceDir, file), filepath.Join(destDir, file))
		if err != nil {
			return err
		}
	}

	return nil
}

type Controller interface {
	Init(ctx context.Context) error
	Run(ctx context.Context) error
	Shutdown()
	GetPort() int
}

type ControllerManager struct {
	controller Controller
	// used to stop background tasks(goroutines)
	cancelRoutinesFunc context.CancelFunc
}

func (cm *ControllerManager) RunServer(ctx context.Context) {
	// Useful to be able to call in the same goroutine for testing purposes
	if err := cm.controller.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func (cm *ControllerManager) StartServer() {
	ctx, cancel := context.WithCancel(context.Background())
	cm.cancelRoutinesFunc = cancel

	if err := cm.controller.Init(ctx); err != nil {
		panic(err)
	}

	go func() {
		cm.RunServer(ctx)
	}()
}

func (cm *ControllerManager) StopServer() {
	// stop background tasks
	if cm.cancelRoutinesFunc != nil {
		cm.cancelRoutinesFunc()
	}

	cm.controller.Shutdown()
}

func (cm *ControllerManager) WaitServerToBeReady(port string) {
	url := GetBaseURL(port)
	WaitTillServerReady(url)
}

func (cm *ControllerManager) StartAndWait(port string) {
	cm.StartServer()

	url := GetBaseURL(port)
	WaitTillServerReady(url)
}

func NewControllerManager(controller Controller) ControllerManager {
	cm := ControllerManager{
		controller: controller,
	}

	return cm
}

func WriteImageToFileSystem(image Image, repoName, ref string, storeController storage.StoreController) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(repoName)
	if err != nil {
		return err
	}

	for _, layerBlob := range image.Layers {
		layerReader := bytes.NewReader(layerBlob)
		layerDigest := godigest.FromBytes(layerBlob)

		_, _, err = store.FullBlobUpload(repoName, layerReader, layerDigest)
		if err != nil {
			return err
		}
	}

	configBlob, err := json.Marshal(image.Config)
	if err != nil {
		return err
	}

	configReader := bytes.NewReader(configBlob)
	configDigest := godigest.FromBytes(configBlob)

	_, _, err = store.FullBlobUpload(repoName, configReader, configDigest)
	if err != nil {
		return err
	}

	manifestBlob, err := json.Marshal(image.Manifest)
	if err != nil {
		return err
	}

	_, _, err = store.PutImageManifest(repoName, ref, ispec.MediaTypeImageManifest, manifestBlob)
	if err != nil {
		return err
	}

	return nil
}

func WriteMultiArchImageToFileSystem(multiarchImage MultiarchImage, repoName, ref string,
	storeController storage.StoreController,
) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(repoName)
	if err != nil {
		return err
	}

	for _, image := range multiarchImage.Images {
		err := WriteImageToFileSystem(image, repoName, image.DigestStr(), storeController)
		if err != nil {
			return err
		}
	}

	indexBlob, err := json.Marshal(multiarchImage.Index)
	if err != nil {
		return err
	}

	_, _, err = store.PutImageManifest(repoName, ref, ispec.MediaTypeImageIndex,
		indexBlob)

	return err
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
		if _, err := os.Stat(path.Join(rootDir, "_trivy", "db", "trivy.db")); err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

// Adapted from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
func RandomString(n int) string {
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

	randomAuthor := RandomString(maxLen)

	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
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

func GetEmptyImageConfig() ([]byte, godigest.Digest) {
	config := ispec.Image{}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}

func GetImageConfig() ([]byte, godigest.Digest) {
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
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
		panic(fmt.Errorf("error opening layout at '%s' : %w", imagePath, err))
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

		var manifest ispec.Manifest

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

// Deprecated: Should use the new functions starting with "Create".
func GetImageComponents(layerSize int) (ispec.Image, [][]byte, ispec.Manifest, error) {
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err = inject.Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		make([]byte, layerSize),
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return config, layers, manifest, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomImageComponents(layerSize int) (ispec.Image, [][]byte, ispec.Manifest, error) {
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err = inject.Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		GetRandomLayer(layerSize),
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return config, layers, manifest, nil
}

// These are the 3 vulnerabilities found for the returned image by the GetVulnImage function.
const (
	Vulnerability1ID = "CVE-2023-2650"
	Vulnerability2ID = "CVE-2023-1255"
	Vulnerability3ID = "CVE-2023-2975"
)

// Deprecated: Should use the new functions starting with "Create".
func GetVulnImageWithConfig(config ispec.Image) (Image, error) {
	vulnerableLayer, err := GetLayerWithVulnerability()
	if err != nil {
		return Image{}, err
	}

	vulnerableConfig := ispec.Image{
		Platform: config.Platform,
		Config:   config.Config,
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{"sha256:f1417ff83b319fbdae6dd9cd6d8c9c88002dcd75ecf6ec201c8c6894681cf2b5"},
		},
		Created: config.Created,
		History: config.History,
	}

	img, err := GetImageWithComponents(
		vulnerableConfig,
		[][]byte{
			vulnerableLayer,
		})
	if err != nil {
		return Image{}, err
	}

	return img, err
}

func GetLayerWithVulnerability() ([]byte, error) {
	if vulnerableLayer != nil {
		return vulnerableLayer, nil
	}

	projectRootDir, err := GetProjectRootDir()
	if err != nil {
		return nil, err
	}

	// this is the path of the blob relative to the root of the zot folder
	vulnBlobPath := "test/data/alpine/blobs/sha256/f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09"

	absoluteVulnBlobPath, _ := filepath.Abs(filepath.Join(projectRootDir, vulnBlobPath))

	vulnerableLayer, err := os.ReadFile(absoluteVulnBlobPath) //nolint: lll
	if err != nil {
		return nil, err
	}

	return vulnerableLayer, nil
}

func GetProjectRootDir() (string, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		goModPath := filepath.Join(workDir, "go.mod")

		_, err := os.Stat(goModPath)
		if err == nil {
			return workDir, nil
		}

		if workDir == filepath.Dir(workDir) {
			return "", ErrNoGoModFileFound
		}

		workDir = filepath.Dir(workDir)
	}
}

func GetRandomLayer(size int) []byte {
	layer := make([]byte, size)

	_, err := rand.Read(layer)
	if err != nil {
		return layer
	}

	return layer
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomImage() (Image, error) {
	const layerSize = 20

	config, layers, manifest, err := GetRandomImageComponents(layerSize)
	if err != nil {
		return Image{}, err
	}

	return Image{
		Manifest: manifest,
		Layers:   layers,
		Config:   config,
	}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageComponentsWithConfig(conf ispec.Image) (ispec.Image, [][]byte, ispec.Manifest, error) {
	configBlob, err := json.Marshal(conf)
	if err = inject.Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layerSize := 100
	layer := make([]byte, layerSize)

	_, err = rand.Read(layer)
	if err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	layers := [][]byte{
		layer,
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return conf, layers, manifest, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageWithConfig(conf ispec.Image) (Image, error) {
	config, layers, manifest, err := GetImageComponentsWithConfig(conf)
	if err != nil {
		return Image{}, err
	}

	return Image{
		Manifest: manifest,
		Config:   config,
		Layers:   layers,
	}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageWithComponents(config ispec.Image, layers [][]byte) (Image, error) {
	configBlob, err := json.Marshal(config)
	if err != nil {
		return Image{}, err
	}

	manifestLayers := make([]ispec.Descriptor, 0, len(layers))

	for _, layer := range layers {
		manifestLayers = append(manifestLayers, ispec.Descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar",
			Digest:    godigest.FromBytes(layer),
			Size:      int64(len(layer)),
		})
	}

	const schemaVersion = 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    godigest.FromBytes(configBlob),
			Size:      int64(len(configBlob)),
		},
		Layers: manifestLayers,
	}

	return Image{
		Manifest: manifest,
		Config:   config,
		Layers:   layers,
	}, nil
}

func GetCosignSignatureTagForManifest(manifest ispec.Manifest) (string, error) {
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}

	manifestDigest := godigest.FromBytes(manifestBlob)

	return GetCosignSignatureTagForDigest(manifestDigest), nil
}

func GetCosignSignatureTagForDigest(manifestDigest godigest.Digest) string {
	return manifestDigest.Algorithm().String() + "-" + manifestDigest.Encoded() + ".sig"
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageWithSubject(subjectDigest godigest.Digest, mediaType string) (Image, error) {
	num := 100

	conf, layers, manifest, err := GetRandomImageComponents(num)
	if err != nil {
		return Image{}, err
	}

	manifest.Subject = &ispec.Descriptor{
		Digest:    subjectDigest,
		MediaType: mediaType,
	}

	return Image{
		Manifest: manifest,
		Config:   conf,
		Layers:   layers,
	}, nil
}

func UploadImage(img Image, baseURL, repo, ref string) error {
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

	var err error

	cblob := img.ConfigDescriptor.Data

	// we'll remove this check once we make the full transition to the new way of generating test images
	if len(cblob) == 0 {
		cblob, err = json.Marshal(img.Config)
		if err = inject.Error(err); err != nil {
			return err
		}
	}

	cdigest := godigest.FromBytes(cblob)

	if img.Manifest.Config.MediaType == ispec.MediaTypeEmptyJSON ||
		img.Manifest.Config.Digest == ispec.DescriptorEmptyJSON.Digest {
		cblob = ispec.DescriptorEmptyJSON.Data
		cdigest = ispec.DescriptorEmptyJSON.Digest
	}

	resp, err := resty.R().
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || inject.ErrStatusCode(resp.StatusCode()) == -1 {
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
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	manifestBlob := img.ManifestDescriptor.Data

	// we'll remove this check once we make the full transition to the new way of generating test images
	if len(manifestBlob) == 0 {
		manifestBlob, err = json.Marshal(img.Manifest)
		if err = inject.Error(err); err != nil {
			return err
		}
	}

	// validate manifest
	if err := storageCommon.ValidateManifestSchema(manifestBlob); err != nil {
		return err
	}

	resp, err = resty.R().
		SetHeader("Content-type", ispec.MediaTypeImageManifest).
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated {
		return ErrPutBlob
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated {
		return ErrPutBlob
	}

	return err
}

func DeleteImage(repo, reference, baseURL string) (int, error) {
	resp, err := resty.R().Delete(
		fmt.Sprintf(baseURL+"/v2/%s/manifests/%s", repo, reference),
	)
	if err != nil {
		return -1, err
	}

	return resp.StatusCode(), err
}

func UploadBlob(baseURL, repo string, blob []byte, artifactBlobMediaType string) error {
	resp, err := resty.R().Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusAccepted {
		return ErrPostBlob
	}

	loc := resp.Header().Get("Location")

	blobDigest := godigest.FromBytes(blob).String()

	resp, err = resty.R().
		SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
		SetHeader("Content-Type", artifactBlobMediaType).
		SetQueryParam("digest", blobDigest).
		SetBody(blob).
		Put(baseURL + loc)

	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return ErrPutBlob
	}

	return nil
}

func PushTestImage(repoName string, tag string, //nolint:unparam
	baseURL string, manifest ispec.Manifest,
	config ispec.Image, layers [][]byte,
) error {
	err := UploadImage(
		Image{
			Manifest: manifest,
			Config:   config,
			Layers:   layers,
		},
		baseURL,
		repoName,
		tag,
	)

	return err
}

func ReadLogFileAndSearchString(logPath string, stringToMatch string, timeout time.Duration) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Contains(string(content), stringToMatch) {
				return true, nil
			}
		}
	}
}

func ReadLogFileAndCountStringOccurence(logPath string, stringToMatch string,
	timeout time.Duration, count int,
) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Count(string(content), stringToMatch) >= count {
				return true, nil
			}
		}
	}
}

func CopyFile(sourceFilePath, destFilePath string) error {
	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	sourceFile, err := os.Open(sourceFilePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return nil
}

func IsDigestReference(ref string) bool {
	parts := strings.SplitN(ref, "/", 2) //nolint:gomnd
	if len(parts) == 1 {
		return false
	}

	index := strings.Index(parts[1], "@")

	return index != -1
}

type isser interface {
	Is(string) bool
}

// Index returns the index of the first occurrence of name in s,
// or -1 if not present.
func Index[E isser](s []E, name string) int {
	for i, v := range s {
		if v.Is(name) {
			return i
		}
	}

	return -1
}

// Contains reports whether name is present in s.
func Contains[E isser](s []E, name string) bool {
	return Index(s, name) >= 0
}

func UploadImageWithBasicAuth(img Image, baseURL, repo, ref, user, password string) error {
	for _, blob := range img.Layers {
		resp, err := resty.R().
			SetBasicAuth(user, password).
			Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
		if err != nil {
			return err
		}

		if resp.StatusCode() != http.StatusAccepted {
			return ErrPostBlob
		}

		loc := resp.Header().Get("Location")

		digest := godigest.FromBytes(blob).String()

		resp, err = resty.R().
			SetBasicAuth(user, password).
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
	if err = inject.Error(err); err != nil {
		return err
	}

	cdigest := godigest.FromBytes(cblob)

	if img.Manifest.Config.MediaType == ispec.MediaTypeEmptyJSON {
		cblob = ispec.DescriptorEmptyJSON.Data
		cdigest = ispec.DescriptorEmptyJSON.Digest
	}

	resp, err := resty.R().
		SetBasicAuth(user, password).
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	loc := Location(baseURL, resp)

	// uploading blob should get 201
	resp, err = resty.R().
		SetBasicAuth(user, password).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)
	if err = inject.Error(err); err != nil {
		return err
	}

	if inject.ErrStatusCode(resp.StatusCode()) != http.StatusCreated || inject.ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	// put manifest
	manifestBlob, err := json.Marshal(img.Manifest)
	if err = inject.Error(err); err != nil {
		return err
	}

	_, err = resty.R().
		SetBasicAuth(user, password).
		SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	return err
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomMultiarchImageComponents() (ispec.Index, []Image, error) {
	const layerSize = 100

	randomLayer1 := make([]byte, layerSize)

	_, err := rand.Read(randomLayer1)
	if err != nil {
		return ispec.Index{}, []Image{}, err
	}

	image1, err := GetImageWithComponents(
		ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		},
		[][]byte{
			randomLayer1,
		})
	if err != nil {
		return ispec.Index{}, []Image{}, err
	}

	randomLayer2 := make([]byte, layerSize)

	_, err = rand.Read(randomLayer2)
	if err != nil {
		return ispec.Index{}, []Image{}, err
	}

	image2, err := GetImageWithComponents(
		ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "386",
			},
		},
		[][]byte{
			randomLayer2,
		})
	if err != nil {
		return ispec.Index{}, []Image{}, err
	}

	randomLayer3 := make([]byte, layerSize)

	_, err = rand.Read(randomLayer3)
	if err != nil {
		return ispec.Index{}, []Image{}, err
	}

	image3, err := GetImageWithComponents(
		ispec.Image{
			Platform: ispec.Platform{
				OS:           "windows",
				Architecture: "amd64",
			},
		},
		[][]byte{
			randomLayer3,
		})
	if err != nil {
		return ispec.Index{}, []Image{}, err
	}

	index := ispec.Index{
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    getManifestDigest(image1.Manifest),
				Size:      getManifestSize(image1.Manifest),
			},
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    getManifestDigest(image2.Manifest),
				Size:      getManifestSize(image2.Manifest),
			},
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    getManifestDigest(image3.Manifest),
				Size:      getManifestSize(image3.Manifest),
			},
		},
	}

	return index, []Image{image1, image2, image3}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomMultiarchImage(reference string) (MultiarchImage, error) {
	index, images, err := GetRandomMultiarchImageComponents()
	if err != nil {
		return MultiarchImage{}, err
	}

	index.SchemaVersion = 2

	return MultiarchImage{
		Index: index, Images: images, Reference: reference,
	}, err
}

// Deprecated: Should use the new functions starting with "Create".
func GetMultiarchImageForImages(images []Image) MultiarchImage {
	var index ispec.Index

	for _, image := range images {
		index.Manifests = append(index.Manifests, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    getManifestDigest(image.Manifest),
			Size:      getManifestSize(image.Manifest),
		})
	}

	index.SchemaVersion = 2

	return MultiarchImage{Index: index, Images: images}
}

func getManifestSize(manifest ispec.Manifest) int64 {
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return 0
	}

	return int64(len(manifestBlob))
}

func getManifestDigest(manifest ispec.Manifest) godigest.Digest {
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return ""
	}

	return godigest.FromBytes(manifestBlob)
}

func UploadMultiarchImage(multiImage MultiarchImage, baseURL string, repo, ref string) error {
	for _, image := range multiImage.Images {
		err := UploadImage(image, baseURL, repo, image.DigestStr())
		if err != nil {
			return err
		}
	}

	// put manifest
	indexBlob, err := json.Marshal(multiImage.Index)
	if err = inject.Error(err); err != nil {
		return err
	}

	// validate manifest
	if err := storageCommon.ValidateImageIndexSchema(indexBlob); err != nil {
		return err
	}

	resp, err := resty.R().
		SetHeader("Content-type", ispec.MediaTypeImageIndex).
		SetBody(indexBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + ref)

	if resp.StatusCode() != http.StatusCreated {
		return ErrPutIndex
	}

	return err
}

func GetIndexBlobWithManifests(manifestDigests []godigest.Digest) ([]byte, error) {
	manifests := make([]ispec.Descriptor, 0, len(manifestDigests))

	for _, manifestDigest := range manifestDigests {
		manifests = append(manifests, ispec.Descriptor{
			Digest:    manifestDigest,
			MediaType: ispec.MediaTypeImageManifest,
		})
	}

	indexContent := ispec.Index{
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: manifests,
	}

	return json.Marshal(indexContent)
}

func MockOIDCRun() (*mockoidc.MockOIDC, error) {
	// Create a fresh RSA Private Key for token signing
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048) //nolint: gomnd

	// Create an unstarted MockOIDC server
	mockServer, _ := mockoidc.NewServer(rsaKey)

	// Create the net.Listener, kernel will chose a valid port
	listener, _ := net.Listen("tcp", "127.0.0.1:0")

	bearerMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
			// stateVal := req.Form.Get("state")
			header := req.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2) //nolint: gomnd
			if header != "" {
				if strings.ToLower(parts[0]) == "bearer" {
					req.Header.Set("Authorization", strings.Join([]string{"Bearer", parts[1]}, " "))
				}
			}

			next.ServeHTTP(response, req)
		})
	}

	err := mockServer.AddMiddleware(bearerMiddleware)
	if err != nil {
		return mockServer, err
	}
	// tlsConfig can be nil if you want HTTP
	return mockServer, mockServer.Start(listener, nil)
}

func CustomRedirectPolicy(noOfRedirect int) resty.RedirectPolicy {
	return resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if len(via) >= noOfRedirect {
			return fmt.Errorf("stopped after %d redirects", noOfRedirect) //nolint: goerr113
		}

		for key, val := range via[len(via)-1].Header {
			req.Header[key] = val
		}

		respCookies := req.Response.Cookies()
		for _, cookie := range respCookies {
			req.AddCookie(cookie)
		}

		return nil
	})
}

func DateRef(year int, month time.Month, day, hour, min, sec, nsec int, loc *time.Location) *time.Time {
	date := time.Date(year, month, day, hour, min, sec, nsec, loc)

	return &date
}

func RandomDateRef(loc *time.Location) *time.Time {
	var (
		year  = 1990 + mathRand.Intn(30)          //nolint: gosec,gomnd
		month = time.Month(1 + mathRand.Intn(10)) //nolint: gosec,gomnd
		day   = 1 + mathRand.Intn(5)              //nolint: gosec,gomnd
		hour  = 1 + mathRand.Intn(22)             //nolint: gosec,gomnd
		min   = 1 + mathRand.Intn(58)             //nolint: gosec,gomnd
		sec   = 1 + mathRand.Intn(58)             //nolint: gosec,gomnd
		nsec  = 1
	)

	return DateRef(year, month, day, hour, min, sec, nsec, time.UTC)
}

func GetDefaultConfig() ispec.Image {
	return ispec.Image{
		Created: DefaultTimeRef(),
		Author:  "ZotUser",
		Platform: ispec.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
	}
}

func GetDefaultVulnConfig() ispec.Image {
	return ispec.Image{
		Created: DefaultTimeRef(),
		Author:  "ZotUser",
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		Config: ispec.ImageConfig{
			Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cmd: []string{"/bin/sh"},
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{"sha256:f1417ff83b319fbdae6dd9cd6d8c9c88002dcd75ecf6ec201c8c6894681cf2b5"},
		},
	}
}

func DefaultTimeRef() *time.Time {
	var (
		year  = 2010
		month = time.Month(1)
		day   = 1
		hour  = 1
		min   = 1
		sec   = 1
		nsec  = 0
	)

	return DateRef(year, month, day, hour, min, sec, nsec, time.UTC)
}

func GetDefaultLayers() []Layer {
	return []Layer{
		{Blob: []byte("abc"), Digest: godigest.FromBytes([]byte("abc")), MediaType: ispec.MediaTypeImageLayerGzip},
		{Blob: []byte("123"), Digest: godigest.FromBytes([]byte("123")), MediaType: ispec.MediaTypeImageLayerGzip},
		{Blob: []byte("xyz"), Digest: godigest.FromBytes([]byte("xyz")), MediaType: ispec.MediaTypeImageLayerGzip},
	}
}

func GetDefaultLayersBlobs() [][]byte {
	return [][]byte{
		[]byte("abc"),
		[]byte("123"),
		[]byte("xyz"),
	}
}

func GetDefaultImageStore(rootDir string, log zLog.Logger) stypes.ImageStore {
	return local.NewImageStore(rootDir, false, false, time.Hour, time.Hour, false, false, log,
		monitoring.NewMetricsServer(false, log),
		mocks.MockedLint{
			LintFn: func(repo string, manifestDigest godigest.Digest, imageStore stypes.ImageStore) (bool, error) {
				return true, nil
			},
		},
		mocks.CacheMock{},
	)
}

func GetDefaultStoreController(rootDir string, log zLog.Logger) storage.StoreController {
	return storage.StoreController{
		DefaultStore: GetDefaultImageStore(rootDir, log),
	}
}

func RemoveLocalStorageContents(imageStore stypes.ImageStore) error {
	repos, err := imageStore.GetRepositories()
	if err != nil {
		return err
	}

	for _, repo := range repos {
		// take just the first path
		err = os.RemoveAll(filepath.Join(imageStore.RootDir(), filepath.SplitList(repo)[0]))
		if err != nil {
			return err
		}
	}

	return nil
}
