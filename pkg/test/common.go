package test

import (
	"bytes"
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
	"os/exec"
	"path"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/phayes/freeport"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/storage"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	SleepTime     = 100 * time.Millisecond
)

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
	ErrPostBlob = errors.New("can't post blob")
	ErrPutBlob  = errors.New("can't put blob")
)

type Image struct {
	Manifest ispec.Manifest
	Config   ispec.Image
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

type Controller interface {
	Run(ctx context.Context) error
	Shutdown()
	GetPort() int
}

type ControllerManager struct {
	controller Controller
}

func (cm *ControllerManager) StartServer() {
	// this blocks
	ctx := context.Background()

	go func() {
		if err := cm.controller.Run(ctx); err != nil {
			return
		}
	}()
}

func (cm *ControllerManager) StopServer() {
	cm.controller.Shutdown()
}

func (cm *ControllerManager) WaitServerToBeReady(port string) {
	url := GetBaseURL(port)
	WaitTillServerReady(url)
}

func (cm *ControllerManager) StartAndWait(port string) {
	// this blocks
	ctx := context.Background()

	go func() {
		if err := cm.controller.Run(ctx); err != nil {
			return
		}
	}()

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

	_, err = store.PutImageManifest(repoName, image.Tag, ispec.MediaTypeImageManifest, manifestBlob)
	if err != nil {
		return err
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
	if err = Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		make([]byte, layerSize),
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
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
	if err = Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

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

func GetImageWithConfig(conf ispec.Image) (ispec.Image, [][]byte, ispec.Manifest, error) {
	configBlob, err := json.Marshal(conf)
	if err = Error(err); err != nil {
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

	if ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || ErrStatusCode(resp.StatusCode()) == -1 {
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

	if ErrStatusCode(resp.StatusCode()) != http.StatusCreated || ErrStatusCode(resp.StatusCode()) == -1 {
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

func UploadArtifact(baseURL, repo string, artifactManifest *ispec.Artifact) error {
	// put manifest
	artifactManifestBlob, err := json.Marshal(artifactManifest)
	if err != nil {
		return err
	}

	artifactManifestDigest := godigest.FromBytes(artifactManifestBlob)

	_, err = resty.R().
		SetHeader("Content-type", ispec.MediaTypeArtifactManifest).
		SetBody(artifactManifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + artifactManifestDigest.String())

	return err
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
	if err = Error(err); err != nil {
		return err
	}

	cdigest := godigest.FromBytes(cblob)

	resp, err := resty.R().
		SetBasicAuth(user, password).
		Post(baseURL + "/v2/" + repo + "/blobs/uploads/")
	if err = Error(err); err != nil {
		return err
	}

	if ErrStatusCode(resp.StatusCode()) != http.StatusAccepted || ErrStatusCode(resp.StatusCode()) == -1 {
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
	if err = Error(err); err != nil {
		return err
	}

	if ErrStatusCode(resp.StatusCode()) != http.StatusCreated || ErrStatusCode(resp.StatusCode()) == -1 {
		return ErrPostBlob
	}

	// put manifest
	manifestBlob, err := json.Marshal(img.Manifest)
	if err = Error(err); err != nil {
		return err
	}

	_, err = resty.R().
		SetBasicAuth(user, password).
		SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(manifestBlob).
		Put(baseURL + "/v2/" + repo + "/manifests/" + img.Tag)

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

	err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
	if err != nil {
		return err
	}

	imageURL := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	// sign the image
	return sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.RegistryOptions{AllowInsecure: true},
		map[string]interface{}{"tag": "1.0"},
		[]string{imageURL},
		"", "", true, "", "", "", false, false, "", true)
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

	_, err = exec.LookPath("notation")
	if err != nil {
		return err
	}

	os.Setenv("XDG_CONFIG_HOME", tdir)

	// generate a keypair
	cmd := exec.Command("notation", "cert", "generate-test", "--trust", "notation-sign-test")

	err = cmd.Run()
	if err != nil {
		return err
	}

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	cmd = exec.Command("notation", "sign", "--key", "notation-sign-test", "--plain-http", image)

	return cmd.Run()
}
