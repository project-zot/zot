//go:build search && imagetrust
// +build search,imagetrust

package extensions_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

type errReader int

func (errReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("test error") //nolint:goerr113
}

func TestSignatureHandlers(t *testing.T) {
	conf := config.New()
	log := log.NewLogger("debug", "")

	trust := extensions.ImageTrust{
		Conf: conf,
		Log:  log,
	}

	Convey("Test error handling when Cosign handler reads the request body", t, func() {
		request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPost, "baseURL", errReader(0))
		response := httptest.NewRecorder()

		trust.HandleCosignPublicKeyUpload(response, request)

		resp := response.Result()
		defer resp.Body.Close()
		So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
	})

	Convey("Test error handling when Notation handler reads the request body", t, func() {
		request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPost, "baseURL", errReader(0))
		query := request.URL.Query()
		query.Add("truststoreName", "someName")
		request.URL.RawQuery = query.Encode()

		response := httptest.NewRecorder()
		trust.HandleNotationCertificateUpload(response, request)

		resp := response.Result()
		defer resp.Body.Close()
		So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
	})
}

func TestSignaturesAllowedMethodsHeader(t *testing.T) {
	defaultVal := true

	Convey("Test http options response", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultVal
		conf.Extensions.Trust.Cosign = defaultVal
		conf.Extensions.Trust.Notation = defaultVal

		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)
		defer ctrlManager.StopServer()

		resp, _ := resty.R().Options(baseURL + constants.FullCosign)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "POST,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		resp, _ = resty.R().Options(baseURL + constants.FullNotation)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "POST,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
	})
}

func TestSignatureUploadAndVerification(t *testing.T) {
	repo := "repo"
	tag := "0.0.1"
	certName := "test"
	defaultValue := true
	imageQuery := `
		{
			Image(image:"%s:%s"){
				RepoName Tag Digest IsSigned
				Manifests {
					Digest
					SignatureInfo { Tool IsTrusted Author }
				}
				SignatureInfo { Tool IsTrusted Author }
			}
		}`

	Convey("Verify cosign public key upload without search or notation being enabled", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Cosign = defaultValue

		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := test.CreateRandomImage()
		err = test.WriteImageToFileSystem(image, repo, tag, storeController)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up image trust routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// generate a keypair
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// upload the public key
		client := resty.New()
		resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sign the image
		err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
			options.KeyOpts{KeyRef: path.Join(keyDir, "cosign.key"), PassFunc: generate.GetPass},
			options.SignOptions{
				Registry:          options.RegistryOptions{AllowInsecure: true},
				AnnotationOptions: options.AnnotationOptions{Annotations: []string{fmt.Sprintf("tag=%s", tag)}},
				Upload:            true,
			},
			[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repo, image.DigestStr())})
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished generating tasks for updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished resetting task generator for updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody([]byte("wrong content")).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Get(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		resp, err = client.R().Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})

	Convey("Verify notation certificate upload without search or cosign being enabled", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Notation = defaultValue

		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := test.CreateRandomImage()
		err = test.WriteImageToFileSystem(image, repo, tag, storeController)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up image trust routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err = test.GenerateNotationCerts(rootDir, certName)
		So(err, ShouldBeNil)

		// upload the certificate
		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", fmt.Sprintf("%s.crt", certName)))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		client := resty.New()
		resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", certName).
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sign the image
		imageURL := fmt.Sprintf("localhost:%s/%s", port, fmt.Sprintf("%s:%s", repo, tag))

		err = test.SignWithNotation(certName, imageURL, rootDir)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "").
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "test").
			SetQueryParam("truststoreType", "signatureAuthority").
			SetBody([]byte("wrong content")).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Get(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		resp, err = client.R().Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})

	Convey("Verify uploading notation certificates", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Notation = defaultValue

		baseURL := test.GetBaseURL(port)
		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, constants.FullSearchPrefix)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := test.CreateRandomImage()
		err = test.WriteImageToFileSystem(image, repo, tag, storeController)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up image trust routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		strQuery := fmt.Sprintf(imageQuery, repo, tag)
		gqlTargetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		// Verify the image is initially shown as not being signed
		resp, err := resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse := zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.IsSigned, ShouldEqual, false)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 0)
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 0)

		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err = test.GenerateNotationCerts(rootDir, certName)
		So(err, ShouldBeNil)

		// upload the certificate
		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", fmt.Sprintf("%s.crt", certName)))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		client := resty.New()
		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", certName).
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sign the image
		imageURL := fmt.Sprintf("localhost:%s/%s", port, fmt.Sprintf("%s:%s", repo, tag))

		err = test.SignWithNotation(certName, imageURL, rootDir)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// verify the image is shown as signed and trusted
		resp, err = resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse = zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary = imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, image.Digest().Encoded())
		t.Log(imgSummary.SignatureInfo)
		So(imgSummary.IsSigned, ShouldEqual, true)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 1)
		So(imgSummary.SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.SignatureInfo[0].Tool, ShouldEqual, "notation")
		So(imgSummary.SignatureInfo[0].Author,
			ShouldEqual, "CN=cert,O=Notary,L=Seattle,ST=WA,C=US")
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 1)
		t.Log(imgSummary.Manifests[0].SignatureInfo)
		So(imgSummary.Manifests[0].SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.Manifests[0].SignatureInfo[0].Tool, ShouldEqual, "notation")
		So(imgSummary.Manifests[0].SignatureInfo[0].Author,
			ShouldEqual, "CN=cert,O=Notary,L=Seattle,ST=WA,C=US")

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "").
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "test").
			SetQueryParam("truststoreType", "signatureAuthority").
			SetBody([]byte("wrong content")).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Get(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		resp, err = client.R().Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
	})

	Convey("Verify uploading cosign public keys", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Cosign = defaultValue

		baseURL := test.GetBaseURL(port)
		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, constants.FullSearchPrefix)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := test.CreateRandomImage()
		err = test.WriteImageToFileSystem(image, repo, tag, storeController)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up image trust routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		strQuery := fmt.Sprintf(imageQuery, repo, tag)
		gqlTargetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		// Verify the image is initially shown as not being signed
		resp, err := resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse := zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.IsSigned, ShouldEqual, false)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 0)
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 0)

		// generate a keypair
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// upload the public key
		client := resty.New()
		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sign the image
		err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
			options.KeyOpts{KeyRef: path.Join(keyDir, "cosign.key"), PassFunc: generate.GetPass},
			options.SignOptions{
				Registry:          options.RegistryOptions{AllowInsecure: true},
				AnnotationOptions: options.AnnotationOptions{Annotations: []string{fmt.Sprintf("tag=%s", tag)}},
				Upload:            true,
			},
			[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repo, image.DigestStr())})
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// verify the image is shown as signed and trusted
		resp, err = resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse = zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary = imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, image.Digest().Encoded())
		t.Log(imgSummary.SignatureInfo)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(imgSummary.IsSigned, ShouldEqual, true)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 1)
		So(imgSummary.SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.SignatureInfo[0].Tool, ShouldEqual, "cosign")
		So(imgSummary.SignatureInfo[0].Author, ShouldEqual, string(publicKeyContent))
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 1)
		t.Log(imgSummary.Manifests[0].SignatureInfo)
		So(imgSummary.Manifests[0].SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.Manifests[0].SignatureInfo[0].Tool, ShouldEqual, "cosign")
		So(imgSummary.Manifests[0].SignatureInfo[0].Author, ShouldEqual, string(publicKeyContent))

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody([]byte("wrong content")).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Get(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		resp, err = client.R().Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
	})

	Convey("Verify uploading cosign public keys with auth configured", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()
		testCreds := test.GetCredString("admin", "admin") + "\n" + test.GetCredString("test", "test")
		htpasswdPath := test.MakeHtpasswdFileFromString(testCreds)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			AdminPolicy: config.Policy{
				Users:   []string{"admin"},
				Actions: []string{},
			},
		}
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Cosign = defaultValue

		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up image trust routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// generate a keypair
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// fail to upload the public key without credentials
		client := resty.New()
		resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// fail to upload the public key with bad credentials
		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// upload the public key using credentials and non-admin user
		resp, err = client.R().SetBasicAuth("test", "test").SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// upload the public key using credentials and admin user
		resp, err = client.R().SetBasicAuth("admin", "admin").SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})

	Convey("Verify signatures are read from the disk and updated in the DB when zot starts", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Cosign = defaultValue

		baseURL := test.GetBaseURL(port)
		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, constants.FullSearchPrefix)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		// Write image
		image := test.CreateRandomImage()
		err = test.WriteImageToFileSystem(image, repo, tag, storeController)
		So(err, ShouldBeNil)

		// Write signature
		signature := test.CreateImageWith().RandomLayers(1, 2).RandomConfig().Build()
		So(err, ShouldBeNil)
		ref, err := test.GetCosignSignatureTagForManifest(image.Manifest)
		So(err, ShouldBeNil)
		err = test.WriteImageToFileSystem(signature, repo, ref, storeController)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		strQuery := fmt.Sprintf(imageQuery, repo, tag)
		gqlTargetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up image trust routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// verify the image is shown as signed and trusted
		resp, err := resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse := zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, image.Digest().Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, image.Digest().Encoded())
		t.Log(imgSummary.SignatureInfo)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(imgSummary.IsSigned, ShouldEqual, true)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 1)
		So(imgSummary.SignatureInfo[0].IsTrusted, ShouldEqual, false)
		So(imgSummary.SignatureInfo[0].Tool, ShouldEqual, "cosign")
		So(imgSummary.SignatureInfo[0].Author, ShouldEqual, "")
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 1)
		t.Log(imgSummary.Manifests[0].SignatureInfo)
		So(imgSummary.Manifests[0].SignatureInfo[0].IsTrusted, ShouldEqual, false)
		So(imgSummary.Manifests[0].SignatureInfo[0].Tool, ShouldEqual, "cosign")
		So(imgSummary.Manifests[0].SignatureInfo[0].Author, ShouldEqual, "")
	})

	Convey("Verify failures when saving uploaded certificates and public keys", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Notation = defaultValue
		conf.Extensions.Trust.Cosign = defaultValue

		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate Notation cert
		err := test.GenerateNotationCerts(rootDir, "test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		// generate Cosign keys
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// Make sure the write to disk fails
		So(os.Chmod(globalDir, 0o000), ShouldBeNil)
		defer func() {
			So(os.Chmod(globalDir, 0o755), ShouldBeNil)
		}()

		client := resty.New()
		resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "test").
			SetBody(certificateContent).Post(baseURL + constants.FullNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
	})
}
