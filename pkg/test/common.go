package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	notconfig "github.com/notaryproject/notation-go/config"
	"github.com/notaryproject/notation-go/dir"
	notreg "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/notation-go/verifier"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/phayes/freeport"
	"github.com/project-zot/mockoidc"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"gopkg.in/resty.v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
	storageCommon "zotregistry.io/zot/pkg/storage/common"
	"zotregistry.io/zot/pkg/test/inject"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	SleepTime     = 100 * time.Millisecond
)

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
	ErrPostBlob              = errors.New("can't post blob")
	ErrPutBlob               = errors.New("can't put blob")
	ErrAlreadyExists         = errors.New("already exists")
	ErrKeyNotFound           = errors.New("key not found")
	ErrSignatureVerification = errors.New("signature verification failed")
	ErrPutIndex              = errors.New("can't put index")
)

type Image struct {
	Manifest  ispec.Manifest
	Config    ispec.Image
	Layers    [][]byte
	Reference string
}

func (img Image) Digest() (godigest.Digest, error) {
	blob, err := json.Marshal(img.Manifest)
	if err != nil {
		return "", err
	}

	return godigest.FromBytes(blob), nil
}

type ArtifactBlobs struct {
	Blob      []byte
	MediaType string
}

type MultiarchImage struct {
	Index     ispec.Index
	Images    []Image
	Reference string
}

func (mi *MultiarchImage) Digest() (godigest.Digest, error) {
	indexBlob, err := json.Marshal(mi.Index)
	if err != nil {
		return "", err
	}

	return godigest.FromBytes(indexBlob), nil
}

func (mi *MultiarchImage) IndexData() (repodb.IndexData, error) {
	indexBlob, err := json.Marshal(mi.Index)
	if err != nil {
		return repodb.IndexData{}, err
	}

	return repodb.IndexData{IndexBlob: indexBlob}, nil
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

func WriteImageToFileSystem(image Image, repoName string, storeController storage.StoreController) error {
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

	_, _, err = store.PutImageManifest(repoName, image.Reference, ispec.MediaTypeImageManifest, manifestBlob)
	if err != nil {
		return err
	}

	return nil
}

func WriteMultiArchImageToFileSystem(multiarchImage MultiarchImage, repoName string,
	storeController storage.StoreController,
) error {
	store := storeController.GetImageStore(repoName)

	err := store.InitRepo(repoName)
	if err != nil {
		return err
	}

	for _, image := range multiarchImage.Images {
		err := WriteImageToFileSystem(image, repoName, storeController)
		if err != nil {
			return err
		}
	}

	indexBlob, err := json.Marshal(multiarchImage.Index)
	if err != nil {
		return err
	}

	_, _, err = store.PutImageManifest(repoName, multiarchImage.Reference, ispec.MediaTypeImageIndex,
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

// These are the 2 vulnerabilities found for the returned image by the GetVulnImage function.
const (
	Vulnerability1ID = "CVE-2023-2650"
	Vulnerability2ID = "CVE-2023-1255"
)

func GetVulnImage(ref string) (Image, error) {
	const skipStackFrame = 2

	vulnerableLayer, err := GetLayerWithVulnerability(skipStackFrame)
	if err != nil {
		return Image{}, err
	}

	vulnerableConfig := ispec.Image{
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

	img, err := GetImageWithComponents(
		vulnerableConfig,
		[][]byte{
			vulnerableLayer,
		})
	if err != nil {
		return Image{}, err
	}

	img.Reference = ref

	return img, err
}

func GetVulnImageWithConfig(ref string, config ispec.Image) (Image, error) {
	const skipStackFrame = 2

	vulnerableLayer, err := GetLayerWithVulnerability(skipStackFrame)
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

	img.Reference = ref

	return img, err
}

func GetLayerWithVulnerability(skip int) ([]byte, error) {
	if vulnerableLayer != nil {
		return vulnerableLayer, nil
	}

	_, b, _, ok := runtime.Caller(skip)
	if !ok {
		return []byte{}, zerr.ErrCallerInfo
	}

	absoluteCallerpath := filepath.Dir(b)
	fmt.Println(absoluteCallerpath)

	// we know pkg folder inside zot must exist, and since all tests are called from within pkg we'll use it as reference
	relCallerPath := absoluteCallerpath[strings.LastIndex(absoluteCallerpath, "pkg"):]

	relCallerSlice := strings.Split(relCallerPath, string(os.PathSeparator))
	fmt.Println(relCallerPath, relCallerSlice)

	// we'll calculate how many folder we should go back to reach the root of the zot folder relative
	// to the callers position
	backPathSlice := make([]string, len(relCallerSlice))

	for i := 0; i < len(backPathSlice); i++ {
		backPathSlice[i] = ".."
	}

	backPath := filepath.Join(backPathSlice...)

	// this is the path of the blob relative to the root of the zot folder
	vulnBlobPath := "test/data/alpine/blobs/sha256/f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09"

	var err error

	x, _ := filepath.Abs(filepath.Join(backPath, vulnBlobPath))
	_ = x

	vulnerableLayer, err = os.ReadFile(filepath.Join(backPath, vulnBlobPath)) //nolint: lll
	if err != nil {
		return nil, err
	}

	return vulnerableLayer, nil
}

func GetRandomLayer(size int) []byte {
	layer := make([]byte, size)

	_, err := rand.Read(layer)
	if err != nil {
		return layer
	}

	return layer
}

func GetRandomImage(reference string) (Image, error) {
	const layerSize = 20

	config, layers, manifest, err := GetRandomImageComponents(layerSize)
	if err != nil {
		return Image{}, err
	}

	if reference == "" {
		blob, err := json.Marshal(manifest)
		if err != nil {
			return Image{}, err
		}

		reference = godigest.FromBytes(blob).String()
	}

	return Image{
		Manifest:  manifest,
		Layers:    layers,
		Config:    config,
		Reference: reference,
	}, nil
}

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

func GetImageWithConfig(conf ispec.Image) (Image, error) {
	config, layers, manifest, err := GetImageComponentsWithConfig(conf)
	if err != nil {
		return Image{}, err
	}

	blob, err := json.Marshal(manifest)
	if err != nil {
		return Image{}, err
	}

	return Image{
		Manifest:  manifest,
		Config:    config,
		Layers:    layers,
		Reference: godigest.FromBytes(blob).String(),
	}, nil
}

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

	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return Image{}, err
	}

	return Image{
		Manifest:  manifest,
		Config:    config,
		Layers:    layers,
		Reference: godigest.FromBytes(manifestBlob).String(),
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

	blob, err := json.Marshal(manifest)
	if err != nil {
		return Image{}, err
	}

	return Image{
		Manifest:  manifest,
		Config:    conf,
		Layers:    layers,
		Reference: godigest.FromBytes(blob).String(),
	}, nil
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
	if err = inject.Error(err); err != nil {
		return err
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

	// put manifest
	manifestBlob, err := json.Marshal(img.Manifest)
	if err = inject.Error(err); err != nil {
		return err
	}

	// validate manifest
	if err := storageCommon.ValidateManifestSchema(manifestBlob); err != nil {
		return err
	}

	if img.Reference == "" {
		img.Reference = godigest.FromBytes(manifestBlob).String()
	}

	resp, err = resty.R().
		SetHeader("Content-type", ispec.MediaTypeImageManifest).
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + img.Reference)

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
			Manifest:  manifest,
			Config:    config,
			Layers:    layers,
			Reference: tag,
		},
		baseURL,
		repoName,
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

func LoadNotationPath(tdir string) {
	dir.UserConfigDir = filepath.Join(tdir, "notation")

	// set user libexec
	dir.UserLibexecDir = dir.UserConfigDir
}

func GenerateNotationCerts(tdir string, certName string) error {
	// generate RSA private key
	bits := 2048

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	rsaCertTuple := testhelper.GetRSASelfSignedCertTupleWithPK(key, "cert")

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCertTuple.Cert.Raw})

	// write private key
	relativeKeyPath, relativeCertPath := dir.LocalKeyPath(certName)

	configFS := dir.ConfigFS()

	keyPath, err := configFS.SysPath(relativeKeyPath)
	if err != nil {
		return err
	}

	certPath, err := configFS.SysPath(relativeCertPath)
	if err != nil {
		return err
	}

	if err := WriteFileWithPermission(keyPath, keyPEM, 0o600, false); err != nil { //nolint:gomnd
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// write self-signed certificate
	if err := WriteFileWithPermission(certPath, certBytes, 0o644, false); err != nil { //nolint:gomnd
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	signingKeys, err := notconfig.LoadSigningKeys()
	if err != nil {
		return err
	}

	keySuite := notconfig.KeySuite{
		Name: certName,
		X509KeyPair: &notconfig.X509KeyPair{
			KeyPath:         keyPath,
			CertificatePath: certPath,
		},
	}

	// addKeyToSigningKeys
	if Contains(signingKeys.Keys, keySuite.Name) {
		return ErrAlreadyExists
	}

	signingKeys.Keys = append(signingKeys.Keys, keySuite)

	// Add to the trust store
	trustStorePath := path.Join(tdir, fmt.Sprintf("notation/truststore/x509/ca/%s", certName))

	if _, err := os.Stat(filepath.Join(trustStorePath, filepath.Base(certPath))); err == nil {
		return ErrAlreadyExists
	}

	if err := os.MkdirAll(trustStorePath, 0o755); err != nil { //nolint:gomnd
		return fmt.Errorf("GenerateNotationCerts os.MkdirAll failed: %w", err)
	}

	trustCertPath := path.Join(trustStorePath, fmt.Sprintf("%s%s", certName, dir.LocalCertificateExtension))

	err = CopyFile(certPath, trustCertPath)
	if err != nil {
		return err
	}

	// Save to the SigningKeys.json
	if err := signingKeys.Save(); err != nil {
		return err
	}

	return nil
}

func SignWithNotation(keyName string, reference string, tdir string) error {
	ctx := context.TODO()

	// getSigner
	var newSigner notation.Signer

	mediaType := jws.MediaTypeEnvelope

	// ResolveKey
	signingKeys, err := LoadNotationSigningkeys(tdir)
	if err != nil {
		return err
	}

	idx := Index(signingKeys.Keys, keyName)
	if idx < 0 {
		return ErrKeyNotFound
	}

	key := signingKeys.Keys[idx]

	if key.X509KeyPair != nil {
		newSigner, err = signer.NewFromFiles(key.X509KeyPair.KeyPath, key.X509KeyPair.CertificatePath)
		if err != nil {
			return err
		}
	}

	// prepareSigningContent
	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	plainHTTP := true

	// Resolve referance
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repositoryOpts := notreg.RepositoryOptions{}

	sigRepo := notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	sigOpts := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: mediaType,
			PluginConfig:       map[string]string{},
		},
		ArtifactReference: ref.String(),
	}

	_, err = notation.Sign(ctx, newSigner, sigRepo, sigOpts)
	if err != nil {
		return err
	}

	return nil
}

func VerifyWithNotation(reference string, tdir string) error {
	// check if trustpolicy.json exists
	trustpolicyPath := path.Join(tdir, "notation/trustpolicy.json")

	if _, err := os.Stat(trustpolicyPath); errors.Is(err, os.ErrNotExist) {
		trustPolicy := `
			{
				"version": "1.0",
				"trustPolicies": [
					{
						"name": "good",
						"registryScopes": [ "*" ],
						"signatureVerification": {
							"level" : "audit" 
						},
						"trustStores": ["ca:good"],
						"trustedIdentities": [
							"*"
						]
					}
				]
			}`

		file, err := os.Create(trustpolicyPath)
		if err != nil {
			return err
		}

		defer file.Close()

		_, err = file.WriteString(trustPolicy)
		if err != nil {
			return err
		}
	}

	// start verifying signatures
	ctx := context.TODO()

	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	plainHTTP := true

	// Resolve referance
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repositoryOpts := notreg.RepositoryOptions{}

	repo := notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	manifestDesc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return err
	}

	if err := ref.ValidateReferenceAsDigest(); err != nil {
		ref.Reference = manifestDesc.Digest.String()
	}

	// getVerifier
	newVerifier, err := verifier.NewFromConfig()
	if err != nil {
		return err
	}

	remoteRepo = &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repo = notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	configs := map[string]string{}

	verifyOpts := notation.VerifyOptions{
		ArtifactReference:    ref.String(),
		PluginConfig:         configs,
		MaxSignatureAttempts: math.MaxInt64,
	}

	_, outcomes, err := notation.Verify(ctx, newVerifier, repo, verifyOpts)
	if err != nil || len(outcomes) == 0 {
		return ErrSignatureVerification
	}

	return nil
}

func ListNotarySignatures(reference string, tdir string) ([]godigest.Digest, error) {
	signatures := []godigest.Digest{}

	ctx := context.TODO()

	// getSignatureRepository
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return signatures, err
	}

	plainHTTP := true

	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	sigRepo := notreg.NewRepository(remoteRepo)

	artifectDesc, err := sigRepo.Resolve(ctx, reference)
	if err != nil {
		return signatures, err
	}

	err = sigRepo.ListSignatures(ctx, artifectDesc, func(signatureManifests []ispec.Descriptor) error {
		for _, sigManifestDesc := range signatureManifests {
			signatures = append(signatures, sigManifestDesc.Digest)
		}

		return nil
	})

	return signatures, err
}

func LoadNotationSigningkeys(tdir string) (*notconfig.SigningKeys, error) {
	var err error

	var signingKeysInfo *notconfig.SigningKeys

	filePath := path.Join(tdir, "notation/signingkeys.json")

	file, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// create file
			newSigningKeys := notconfig.NewSigningKeys()

			newFile, err := os.Create(filePath)
			if err != nil {
				return newSigningKeys, err
			}

			defer newFile.Close()

			encoder := json.NewEncoder(newFile)
			encoder.SetIndent("", "    ")

			err = encoder.Encode(newSigningKeys)

			return newSigningKeys, err
		}

		return nil, err
	}

	defer file.Close()

	err = json.NewDecoder(file).Decode(&signingKeysInfo)

	return signingKeysInfo, err
}

func LoadNotationConfig(tdir string) (*notconfig.Config, error) {
	var configInfo *notconfig.Config

	filePath := path.Join(tdir, "notation/signingkeys.json")

	file, err := os.Open(filePath)
	if err != nil {
		return configInfo, err
	}

	defer file.Close()

	err = json.NewDecoder(file).Decode(&configInfo)
	if err != nil {
		return configInfo, err
	}

	// set default value
	configInfo.SignatureFormat = strings.ToLower(configInfo.SignatureFormat)
	if configInfo.SignatureFormat == "" {
		configInfo.SignatureFormat = "jws"
	}

	return configInfo, nil
}

func WriteFileWithPermission(path string, data []byte, perm fs.FileMode, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}
	flag := os.O_WRONLY | os.O_CREATE

	if overwrite {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_EXCL
	}

	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()

		return err
	}

	return file.Close()
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

func UploadImageWithBasicAuth(img Image, baseURL, repo, user, password string) error {
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

	if img.Reference == "" {
		img.Reference = godigest.FromBytes(manifestBlob).String()
	}

	_, err = resty.R().
		SetBasicAuth(user, password).
		SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + img.Reference)

	return err
}

func SignImageUsingCosign(repoTag, port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "cosign")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
	if err != nil {
		return err
	}

	imageURL := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	const timeoutPeriod = 5

	// sign the image
	return sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: timeoutPeriod * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.SignOptions{
			Registry:          options.RegistryOptions{AllowInsecure: true},
			AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=1.0"}},
			Upload:            true,
		},
		[]string{imageURL})
}

func SignImageUsingNotary(repoTag, port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "notation")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	NotationPathLock.Lock()
	defer NotationPathLock.Unlock()

	LoadNotationPath(tdir)

	// generate a keypair
	err = GenerateNotationCerts(tdir, "notation-sign-test")
	if err != nil {
		return err
	}

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	err = SignWithNotation("notation-sign-test", image, tdir)

	return err
}

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

	image1.Reference = getManifestDigest(image1.Manifest).String()

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

	image2.Reference = getManifestDigest(image2.Manifest).String()

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

	image3.Reference = getManifestDigest(image3.Manifest).String()

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

func GetMultiarchImageForImages(reference string, images []Image) MultiarchImage {
	var index ispec.Index

	for i, image := range images {
		index.Manifests = append(index.Manifests, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    getManifestDigest(image.Manifest),
			Size:      getManifestSize(image.Manifest),
		})

		// update the reference with the digest of the manifest
		images[i].Reference = getManifestDigest(image.Manifest).String()
	}

	index.SchemaVersion = 2

	return MultiarchImage{Index: index, Images: images, Reference: reference}
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

func UploadMultiarchImage(multiImage MultiarchImage, baseURL string, repo string) error {
	for _, image := range multiImage.Images {
		err := UploadImage(image, baseURL, repo)
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
		Put(baseURL + "/v2/" + repo + "/manifests/" + multiImage.Reference)

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
