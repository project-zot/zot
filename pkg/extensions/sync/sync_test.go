//go:build sync
// +build sync

package sync_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	goSync "sync"
	"testing"
	"time"

	"github.com/notaryproject/notation-go-lib"
	notreg "github.com/notaryproject/notation/pkg/registry"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	perr "github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/oci/remote"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/cli"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	ServerCert = "../../../test/data/server.cert"
	ServerKey  = "../../../test/data/server.key"
	CACert     = "../../../test/data/ca.crt"
	ClientCert = "../../../test/data/client.cert"
	ClientKey  = "../../../test/data/client.key"

	testImage    = "zot-test"
	testImageTag = "0.0.1"
	testCveImage = "zot-cve-test"

	testSignedImage = "signed-repo"
)

var (
	errSync      = errors.New("sync error, src oci repo differs from dest one")
	errBadStatus = errors.New("bad http status")
)

type TagsList struct {
	Name string
	Tags []string
}

type ReferenceList struct {
	References []notation.Descriptor `json:"references"`
}

type catalog struct {
	Repositories []string `json:"repositories"`
}

func copyFile(sourceFilePath, destFilePath string) error {
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

func startUpstreamServer(
	t *testing.T, secure, basicAuth bool,
) (*api.Controller, string, string, string, *resty.Client) {
	t.Helper()

	srcPort := test.GetFreePort()
	srcConfig := config.New()
	client := resty.New()

	var srcBaseURL string
	if secure {
		srcBaseURL = test.GetSecureBaseURL(srcPort)

		srcConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		caCert, err := ioutil.ReadFile(CACert)
		if err != nil {
			panic(err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(ClientCert, ClientKey)
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
	} else {
		srcBaseURL = test.GetBaseURL(srcPort)
	}

	var htpasswdPath string
	if basicAuth {
		htpasswdPath = test.MakeHtpasswdFile()
		srcConfig.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
	}

	srcConfig.HTTP.Port = srcPort

	srcDir := t.TempDir()

	err := test.CopyFiles("../../../test/data", srcDir)
	if err != nil {
		panic(err)
	}

	srcConfig.Storage.RootDirectory = srcDir

	sctlr := api.NewController(srcConfig)

	go func() {
		// this blocks
		if err := sctlr.Run(context.Background()); err != nil {
			return
		}
	}()

	// wait till ready
	for {
		_, err := client.R().Get(srcBaseURL)
		if err == nil {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return sctlr, srcBaseURL, srcDir, htpasswdPath, client
}

func startDownstreamServer(
	t *testing.T, secure bool, syncConfig *sync.Config,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	destPort := test.GetFreePort()
	destConfig := config.New()
	client := resty.New()

	var destBaseURL string
	if secure {
		destBaseURL = test.GetSecureBaseURL(destPort)

		destConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		caCert, err := ioutil.ReadFile(CACert)
		if err != nil {
			panic(err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(ClientCert, ClientKey)
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
	} else {
		destBaseURL = test.GetBaseURL(destPort)
	}

	destConfig.HTTP.Port = destPort

	destDir := t.TempDir()

	destConfig.Storage.RootDirectory = destDir
	destConfig.Storage.Dedupe = false
	destConfig.Storage.GC = false

	destConfig.Extensions = &extconf.ExtensionConfig{}
	destConfig.Extensions.Search = nil
	destConfig.Extensions.Sync = syncConfig

	dctlr := api.NewController(destConfig)

	go func() {
		// this blocks
		if err := dctlr.Run(context.Background()); err != nil {
			return
		}
	}()

	// wait till ready
	for {
		_, err := client.R().Get(destBaseURL)
		if err == nil {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return dctlr, destBaseURL, destDir, client
}

func TestORAS(t *testing.T) {
	Convey("Verify sync on demand for oras objects", t, func() {
		sctlr, srcBaseURL, _, _, srcClient := startUpstreamServer(t, false, false)

		test.WaitTillServerReady(srcBaseURL)

		defer func() {
			sctlr.Shutdown()
		}()

		content := []byte("{\"name\":\"foo\",\"value\":\"bar\"}")

		fileDir := t.TempDir()

		err := os.WriteFile(path.Join(fileDir, "config.json"), content, 0o600)
		if err != nil {
			panic(err)
		}

		content = []byte("helloworld")

		err = os.WriteFile(path.Join(fileDir, "artifact.txt"), content, 0o600)
		if err != nil {
			panic(err)
		}

		cmd := exec.Command("oras", "version")

		err = cmd.Run()
		if err != nil {
			panic(err)
		}

		fmt.Println(fileDir)

		srcURL := strings.Join([]string{sctlr.Server.Addr, "/oras-artifact:v2"}, "")

		cmd = exec.Command("oras", "push", "--plain-http", srcURL, "--manifest-config",
			"config.json:application/vnd.acme.rocket.config.v1+json", "artifact.txt:text/plain", "-d", "-v")
		cmd.Dir = fileDir

		// Pushing ORAS artifact to upstream
		err = cmd.Run()
		So(err, ShouldBeNil)

		var tlsVerify bool

		regex := ".*"

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: "oras-artifact",
					Tags: &sync.Tags{
						Regex: &regex,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		test.WaitTillServerReady(destBaseURL)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + "oras-artifact" + "/manifests/v2")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + "oras-artifact" + "/manifests/v2")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		destURL := strings.Join([]string{dctlr.Server.Addr, "/oras-artifact:v2"}, "")
		cmd = exec.Command("oras", "pull", "--plain-http", destURL, "-d", "-v")
		destDir := t.TempDir()
		cmd.Dir = destDir
		// pulling oras artifact from dest server
		err = cmd.Run()
		So(err, ShouldBeNil)

		cmd = exec.Command("grep", "helloworld", "artifact.txt")
		cmd.Dir = destDir
		output, err := cmd.CombinedOutput()

		So(err, ShouldBeNil)
		So(string(output), ShouldContainSubstring, "helloworld")
	})
}

func TestOnDemand(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		sctlr, srcBaseURL, _, _, srcClient := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		var tlsVerify bool

		regex := ".*"
		semver := true

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err := json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.MkdirAll(path.Join(destDir, testImage), 0o000)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 500)

		err = os.Chmod(path.Join(destDir, testImage), 0o755)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.MkdirAll(path.Join(destDir, testImage, sync.SyncBlobUploadDir), 0o000)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.Chmod(path.Join(destDir, testImage, sync.SyncBlobUploadDir), 0o755)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(path.Join(destDir, testImage, "blobs"), 0o000)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.Chmod(path.Join(destDir, testImage, "blobs"), 0o755)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &destTagsList)
		if err != nil {
			panic(err)
		}

		So(destTagsList, ShouldResemble, srcTagsList)
	})
}

func TestPeriodically(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, srcClient := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		semver := true
		var tlsVerify bool

		maxRetries := 1
		delay := 1 * time.Second

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			MaxRetries:   &maxRetries,
			RetryDelay:   &delay,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err := json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(destTagsList, ShouldResemble, srcTagsList)

		Convey("Test sync with more contents", func() {
			regex := ".*"
			semver := true

			invalidRegex := "invalid"

			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						Prefix: testImage,
						Tags: &sync.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
					{
						Prefix: testCveImage,
						Tags: &sync.Tags{
							Regex:  &invalidRegex,
							Semver: &semver,
						},
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			syncConfig := &sync.Config{
				Enable:     &defaultVal,
				Registries: []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, err := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			for {
				resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
				if err != nil {
					panic(err)
				}

				err = json.Unmarshal(resp.Body(), &destTagsList)
				if err != nil {
					panic(err)
				}

				if len(destTagsList.Tags) > 0 {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			So(destTagsList, ShouldResemble, srcTagsList)

			// testCveImage should not be synced because of regex being "invalid", shouldn't match anything
			resp, _ = srcClient.R().Get(srcBaseURL + "/v2/" + testCveImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			So(err, ShouldBeNil)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testCveImage + "/tags/list")
			So(err, ShouldBeNil)

			err = json.Unmarshal(resp.Body(), &destTagsList)
			So(err, ShouldBeNil)

			So(destTagsList, ShouldNotResemble, srcTagsList)
		})
	})
}

func TestOnDemandPermsDenied(t *testing.T) {
	Convey("Verify sync on demand feature without perm on sync cache", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)

		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		dctlr := api.NewController(destConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		syncSubDir := path.Join(destDir, testImage, sync.SyncBlobUploadDir)

		err := os.MkdirAll(syncSubDir, 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(syncSubDir, 0o000)
		So(err, ShouldBeNil)

		go func() {
			// this blocks
			if err := dctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(destBaseURL)

		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.Chmod(syncSubDir, 0o755)
		if err != nil {
			panic(err)
		}
	})
}

func TestConfigReloader(t *testing.T) {
	Convey("Verify periodically sync config reloader works", t, func() {
		duration, _ := time.ParseDuration("3s")

		sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			sctlr.Shutdown()
		}()

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: duration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)

		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		destConfig.Log.Output = logFile.Name()

		dctlr := api.NewController(destConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		content := fmt.Sprintf(`{"distSpecVersion": "0.1.0-dev", "storage": {"rootDirectory": "%s"},
		"http": {"address": "127.0.0.1", "port": "%s"},
		"log": {"level": "debug", "output": "%s"}}`, destDir, destPort, logFile.Name())

		cfgfile, err := ioutil.TempFile("", "zot-test*.json")
		So(err, ShouldBeNil)

		defer os.Remove(cfgfile.Name()) // clean up

		_, err = cfgfile.Write([]byte(content))
		So(err, ShouldBeNil)

		hotReloader, err := cli.NewHotReloader(dctlr, cfgfile.Name())
		So(err, ShouldBeNil)

		reloadCtx := hotReloader.Start()

		go func() {
			// this blocks
			if err := dctlr.Run(reloadCtx); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		// let it sync
		time.Sleep(3 * time.Second)

		// modify config
		_, err = cfgfile.WriteString(" ")
		So(err, ShouldBeNil)

		err = cfgfile.Close()
		So(err, ShouldBeNil)

		time.Sleep(2 * time.Second)

		data, err := os.ReadFile(logFile.Name())
		t.Logf("downstream log: %s", string(data))
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "reloaded params")
		So(string(data), ShouldContainSubstring, "new configuration settings")
		So(string(data), ShouldContainSubstring, "\"Sync\":null")
		So(string(data), ShouldNotContainSubstring, "sync:")
	})
}

func TestMandatoryAnnotations(t *testing.T) {
	Convey("Verify mandatory annotations failing - on demand disabled", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		var semver bool
		tlsVerify := false

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			OnDemand:     false,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destClient := resty.New()

		destBaseURL := test.GetBaseURL(destPort)

		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Sync = syncConfig

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		destConfig.Log.Output = logFile.Name()

		lintEnabled := true
		destConfig.Extensions.Lint = &extconf.LintConfig{}
		destConfig.Extensions.Lint.Enabled = &lintEnabled
		destConfig.Extensions.Lint.MandatoryAnnotations = []string{"annot1", "annot2", "annot3"}

		dctlr := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := destClient.R().Get(destBaseURL)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			dctlr.Shutdown()
		}()

		// give it time to set up sync
		time.Sleep(3 * time.Second)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifest/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		data, err := os.ReadFile(logFile.Name())
		t.Logf("downstream log: %s", string(data))
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "couldn't upload manifest because of missing annotations")
	})
}

func TestBadTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, true, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		var semver bool
		tlsVerify := true

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			OnDemand:     true,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, true, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		// give it time to set up sync
		time.Sleep(3 * time.Second)

		resp, _ := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "invalid")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = destClient.R().Get(destBaseURL + "/v2/" + "invalid" + "/manifests/" + testImageTag)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, true, false)

		defer func() {
			sctlr.Shutdown()
		}()

		var srcIndex ispec.Index
		var destIndex ispec.Index

		srcBuf, err := ioutil.ReadFile(path.Join(srcDir, testImage, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		// copy upstream client certs, use them in sync config
		destClientCertDir := t.TempDir()

		destFilePath := path.Join(destClientCertDir, "ca.crt")
		err = copyFile(CACert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(destClientCertDir, "client.cert")
		err = copyFile(ClientCert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(destClientCertDir, "client.key")
		err = copyFile(ClientKey, destFilePath)
		if err != nil {
			panic(err)
		}

		regex := ".*"
		var semver bool
		tlsVerify := true

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      destClientCertDir,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, _, destDir, _ := startDownstreamServer(t, true, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		// wait till ready
		for {
			destBuf, _ := ioutil.ReadFile(path.Join(destDir, testImage, "index.json"))
			_ = json.Unmarshal(destBuf, &destIndex)
			time.Sleep(500 * time.Millisecond)
			if len(destIndex.Manifests) > 0 {
				break
			}
		}

		var found bool
		for _, manifest := range srcIndex.Manifests {
			if reflect.DeepEqual(manifest.Annotations, destIndex.Manifests[0].Annotations) {
				found = true
			}
		}

		if !found {
			panic(errSync)
		}
	})
}

func TestBasicAuth(t *testing.T) {
	Convey("Verify sync basic auth", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		Convey("Verify sync basic auth with file credentials", func() {
			sctlr, srcBaseURL, _, htpasswdPath, srcClient := startUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			defer func() {
				sctlr.Shutdown()
			}()

			registryName := sync.StripRegistryTransport(srcBaseURL)
			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "test"}}`, registryName))

			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						Prefix: testImage,
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries:      []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := srcClient.R().SetBasicAuth("test", "test").Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err := json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			for {
				resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
				if err != nil {
					panic(err)
				}

				err = json.Unmarshal(resp.Body(), &destTagsList)
				if err != nil {
					panic(err)
				}

				if len(destTagsList.Tags) > 0 {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			So(destTagsList, ShouldResemble, srcTagsList)
		})

		Convey("Verify sync basic auth with wrong file credentials", func() {
			sctlr, srcBaseURL, _, htpasswdPath, _ := startUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			defer func() {
				sctlr.Shutdown()
			}()

			destPort := test.GetFreePort()
			destBaseURL := test.GetBaseURL(destPort)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir := t.TempDir()

			destConfig.Storage.SubPaths = map[string]config.StorageConfig{
				"a": {
					RootDirectory: destDir,
					GC:            true,
					GCDelay:       storage.DefaultGCDelay,
					Dedupe:        true,
				},
			}

			destConfig.Storage.RootDirectory = destDir

			regex := ".*"
			var semver bool

			registryName := sync.StripRegistryTransport(srcBaseURL)

			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "invalid"}}`,
				registryName))

			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						Prefix: testImage,
						Tags: &sync.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
				OnDemand:     true,
			}

			destConfig.Extensions = &extconf.ExtensionConfig{}
			defaultVal := true
			destConfig.Extensions.Sync = &sync.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries:      []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr := api.NewController(destConfig)

			go func() {
				// this blocks
				if err := dctlr.Run(context.Background()); err != nil {
					return
				}
			}()

			defer func() {
				dctlr.Shutdown()
			}()

			test.WaitTillServerReady(destBaseURL)

			time.Sleep(3 * time.Second)

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Verify sync basic auth with bad file credentials", func() {
			sctlr, srcBaseURL, _, htpasswdPath, _ := startUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			defer func() {
				sctlr.Shutdown()
			}()

			registryName := sync.StripRegistryTransport(srcBaseURL)

			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "test"}}`,
				registryName))

			err := os.Chmod(credentialsFile, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				So(os.Chmod(credentialsFile, 0o755), ShouldBeNil)
				So(os.RemoveAll(credentialsFile), ShouldBeNil)
			}()

			regex := ".*"
			var semver bool
			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						Prefix: testImage,
						Tags: &sync.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries:      []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			time.Sleep(3 * time.Second)

			resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Verify on demand sync with basic auth", func() {
			sctlr, srcBaseURL, _, htpasswdPath, srcClient := startUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			defer func() {
				sctlr.Shutdown()
			}()

			registryName := sync.StripRegistryTransport(srcBaseURL)
			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "test"}}`, registryName))

			syncRegistryConfig := sync.RegistryConfig{
				URLs:     []string{srcBaseURL},
				OnDemand: true,
			}

			unreacheableSyncRegistryConfig1 := sync.RegistryConfig{
				URLs:     []string{"localhost:9999"},
				OnDemand: true,
			}

			unreacheableSyncRegistryConfig2 := sync.RegistryConfig{
				URLs:     []string{"localhost:9999"},
				OnDemand: false,
			}

			defaultVal := true
			// add file path to the credentials
			syncConfig := &sync.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{
					unreacheableSyncRegistryConfig1,
					unreacheableSyncRegistryConfig2,
					syncRegistryConfig,
				},
			}

			dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := srcClient.R().SetBasicAuth("test", "test").Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err := json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = dctlr.StoreController.DefaultStore.DeleteImageManifest(testImage, testImageTag)
			So(err, ShouldBeNil)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			So(destTagsList, ShouldResemble, srcTagsList)
		})
	})
}

func TestBadURL(t *testing.T) {
	Convey("Verify sync with bad url", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"bad-registry-url]", "%"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestNoImagesByRegex(t *testing.T) {
	Convey("Verify sync with no images on source based on regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := "9.9.9"
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex: &regex,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := destClient.R().Get(destBaseURL + constants.RoutePrefix + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = destClient.R().Get(destBaseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)
		So(resp.StatusCode(), ShouldEqual, 200)

		var catalog catalog
		err = json.Unmarshal(resp.Body(), &catalog)
		if err != nil {
			panic(err)
		}

		So(catalog.Repositories, ShouldResemble, []string{})
	})
}

func TestInvalidRegex(t *testing.T) {
	Convey("Verify sync with invalid regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := "["
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex: &regex,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, _, _, _ := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()
	})
}

func TestNotSemver(t *testing.T) {
	Convey("Verify sync feature semver compliant", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		// get manifest so we can update it with a semver non compliant tag
		resp, err := resty.R().Get(srcBaseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		manifestBlob := resp.Body()

		resp, err = resty.R().SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(srcBaseURL + "/v2/" + testImage + "/manifests/notSemverTag")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 201)

		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		var destTagsList TagsList

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}
			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(len(destTagsList.Tags), ShouldEqual, 1)
		So(destTagsList.Tags[0], ShouldEqual, testImageTag)
	})
}

func TestInvalidCerts(t *testing.T) {
	Convey("Verify sync with bad certs", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, true, false)

		defer func() {
			sctlr.Shutdown()
		}()

		// copy client certs, use them in sync config
		clientCertDir := t.TempDir()

		destFilePath := path.Join(clientCertDir, "ca.crt")
		err := copyFile(CACert, destFilePath)
		if err != nil {
			panic(err)
		}

		dstfile, err := os.OpenFile(destFilePath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			panic(err)
		}

		defer dstfile.Close()

		if _, err = dstfile.WriteString("Add Invalid Text In Cert"); err != nil {
			panic(err)
		}

		destFilePath = path.Join(clientCertDir, "client.cert")
		err = copyFile(ClientCert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(clientCertDir, "client.key")
		err = copyFile(ClientKey, destFilePath)
		if err != nil {
			panic(err)
		}

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: "",
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      clientCertDir,
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		defer func() {
			dctlr.Shutdown()
		}()
	})
}

func makeCredentialsFile(fileContent string) string {
	tmpfile, err := ioutil.TempFile("", "sync-credentials-")
	if err != nil {
		panic(err)
	}

	content := []byte(fileContent)
	if err := ioutil.WriteFile(tmpfile.Name(), content, 0o600); err != nil {
		panic(err)
	}

	return tmpfile.Name()
}

func TestInvalidUrl(t *testing.T) {
	Convey("Verify sync invalid url", t, func() {
		updateDuration, _ := time.ParseDuration("30m")
		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					// won't match any image on source registry, we will sync on demand
					Prefix: "dummy",
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"http://invalid.invalid/invalid/"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestInvalidTags(t *testing.T) {
	Convey("Verify sync invalid tags", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					// won't match any image on source registry, we will sync on demand
					Prefix: "dummy",
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "invalid:tag")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestSubPaths(t *testing.T) {
	Convey("Verify sync with storage subPaths", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		srcPort := test.GetFreePort()
		srcConfig := config.New()
		srcBaseURL := test.GetBaseURL(srcPort)

		srcConfig.HTTP.Port = srcPort

		srcDir := t.TempDir()

		subpath := "/subpath"

		err := test.CopyFiles("../../../test/data", path.Join(srcDir, subpath))
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sctlr := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(srcBaseURL)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: path.Join(subpath, testImage),
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()

		destDir := t.TempDir()

		subPathDestDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir

		destConfig.Storage.SubPaths = map[string]config.StorageConfig{
			subpath: {
				RootDirectory: subPathDestDir,
				GC:            true,
				GCDelay:       storage.DefaultGCDelay,
				Dedupe:        true,
			},
		}

		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		dctlr := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(destBaseURL)

		defer func() {
			dctlr.Shutdown()
		}()

		var destTagsList TagsList

		for {
			resp, err := resty.R().Get(destBaseURL + constants.RoutePrefix + path.Join(subpath, testImage) + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		// synced image should get into subpath instead of rootDir
		binfo, err := os.Stat(path.Join(subPathDestDir, subpath, testImage, "blobs/sha256"))
		So(binfo, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// check rootDir is not populated with any image.
		binfo, err = os.Stat(path.Join(destDir, subpath))
		So(binfo, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})
}

func TestOnDemandRepoErr(t *testing.T) {
	Convey("Verify sync on demand parseRepositoryReference error", t, func() {
		tlsVerify := false
		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					// will sync on demand, should not be filtered out
					Prefix: testImage,
				},
			},
			URLs:      []string{"docker://invalid"},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestOnDemandContentFiltering(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		Convey("Test image is filtered out by content", func() {
			regex := ".*"
			var semver bool
			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						// should be filtered out
						Prefix: "dummy",
						Tags: &sync.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  true,
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:     &defaultVal,
				Registries: []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Test image is not filtered out by content", func() {
			regex := ".*"
			semver := true
			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						// will sync on demand, should not be filtered out
						Prefix: testImage,
						Tags: &sync.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  true,
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:     &defaultVal,
				Registries: []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})
	})
}

func TestConfigRules(t *testing.T) {
	Convey("Verify sync config rules", t, func() {
		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		Convey("Test periodically sync is disabled when pollInterval is not set", func() {
			regex := ".*"
			var semver bool
			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						Prefix: testImage,
						Tags: &sync.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  false,
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:     &defaultVal,
				Registries: []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			// image should not be synced
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Test periodically sync is disabled when content is not set", func() {
			var tlsVerify bool
			updateDuration, _ := time.ParseDuration("30m")

			syncRegistryConfig := sync.RegistryConfig{
				PollInterval: updateDuration,
				URLs:         []string{srcBaseURL},
				TLSVerify:    &tlsVerify,
				CertDir:      "",
				OnDemand:     false,
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:     &defaultVal,
				Registries: []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Test ondemand sync is disabled when ondemand is false", func() {
			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  false,
			}

			defaultVal := true
			syncConfig := &sync.Config{
				Enable:     &defaultVal,
				Registries: []sync.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

			defer func() {
				dctlr.Shutdown()
			}()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})
	})
}

func TestMultipleURLs(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, srcClient := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"badURL", "http://invalid.invalid/invalid/", srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err := json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(destTagsList, ShouldResemble, srcTagsList)
	})
}

func TestPeriodicallySignaturesErr(t *testing.T) {
	Convey("Verify sync periodically signatures errors", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		err = os.Chdir(tdir)
		So(err, ShouldBeNil)
		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: repoName,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		// trigger permission denied on upstream manifest
		var srcIndex ispec.Index

		srcBuf, err := ioutil.ReadFile(path.Join(srcDir, repoName, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		imageManifestDigest := srcIndex.Manifests[0].Digest

		Convey("Trigger error on image manifest", func() {
			// trigger permission denied on image manifest
			manifestPath := path.Join(srcDir, repoName, "blobs",
				string(imageManifestDigest.Algorithm()), imageManifestDigest.Hex())
			err = os.Chmod(manifestPath, 0o000)
			So(err, ShouldBeNil)

			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)
			defer dctlr.Shutdown()

			time.Sleep(2 * time.Second)

			// should not be synced nor sync on demand
			resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Trigger error on cosign signature", func() {
			// trigger permission error on cosign signature on upstream
			cosignTag := string(imageManifestDigest.Algorithm()) + "-" + imageManifestDigest.Hex() +
				"." + remote.SignatureTagSuffix

			getCosignManifestURL := srcBaseURL + path.Join(constants.RoutePrefix, repoName, "manifests", cosignTag)
			mResp, err := resty.R().Get(getCosignManifestURL)
			So(err, ShouldBeNil)

			var cm ispec.Manifest

			err = json.Unmarshal(mResp.Body(), &cm)
			So(err, ShouldBeNil)

			for _, blob := range cm.Layers {
				blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
				err := os.Chmod(blobPath, 0o000)
				So(err, ShouldBeNil)
			}

			// start downstream server
			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)
			defer dctlr.Shutdown()

			time.Sleep(2 * time.Second)

			// should not be synced nor sync on demand
			resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + cosignTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)
		})

		Convey("Trigger error on notary signature", func() {
			// trigger permission error on cosign signature on upstream
			notaryURLPath := path.Join("/oras/artifacts/v1/", repoName, "manifests", imageManifestDigest.String(), "referrers")

			// based on image manifest digest get referrers
			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetQueryParam("artifactType", "application/vnd.cncf.notary.v2.signature").
				Get(srcBaseURL + notaryURLPath)

			So(err, ShouldBeNil)
			So(resp, ShouldNotBeEmpty)

			var referrers ReferenceList

			err = json.Unmarshal(resp.Body(), &referrers)
			So(err, ShouldBeNil)

			// read manifest
			var artifactManifest artifactspec.Manifest
			for _, ref := range referrers.References {
				refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Hex())
				body, err := ioutil.ReadFile(refPath)
				So(err, ShouldBeNil)

				err = json.Unmarshal(body, &artifactManifest)
				So(err, ShouldBeNil)

				// triggers perm denied on sig blobs
				for _, blob := range artifactManifest.Blobs {
					blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
					err := os.Chmod(blobPath, 0o000)
					So(err, ShouldBeNil)
				}
			}

			// start downstream server
			dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)
			defer dctlr.Shutdown()

			time.Sleep(2 * time.Second)

			// should not be synced nor sync on demand
			resp, err = resty.R().Get(destBaseURL + notaryURLPath)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 400)
		})
	})
}

func TestSignatures(t *testing.T) {
	Convey("Verify sync signatures", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)
		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: repoName,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		// wait for sync
		var destTagsList TagsList

		for {
			resp, err := destClient.R().Get(destBaseURL + "/v2/" + repoName + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		a := &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
		amap, err := a.AnnotationsMap()
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Second)

		// notation verify the image
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")
		cmd := exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
		out, err := cmd.CombinedOutput()
		So(err, ShouldBeNil)

		msg := string(out)
		So(msg, ShouldNotBeEmpty)
		So(strings.Contains(msg, "verification failure"), ShouldBeFalse)

		// cosign verify the image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			Annotations:     amap,
		}

		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")})
		So(err, ShouldBeNil)

		// test negative cases (trigger errors)
		// test notary signatures errors

		// based on manifest digest get referrers
		getReferrersURL := srcBaseURL + path.Join("/oras/artifacts/v1/", repoName, "manifests", digest.String(), "referrers")

		resp, err := resty.R().
			SetHeader("Content-Type", "application/json").
			SetQueryParam("artifactType", "application/vnd.cncf.notary.v2.signature").
			Get(getReferrersURL)

		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)

		var referrers ReferenceList

		err = json.Unmarshal(resp.Body(), &referrers)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		var artifactManifest artifactspec.Manifest
		for _, ref := range referrers.References {
			refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Hex())
			body, err := ioutil.ReadFile(refPath)
			So(err, ShouldBeNil)

			err = json.Unmarshal(body, &artifactManifest)
			So(err, ShouldBeNil)

			// triggers perm denied on notary sig blobs on downstream
			for _, blob := range artifactManifest.Blobs {
				blobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
				err := os.MkdirAll(blobPath, 0o755)
				So(err, ShouldBeNil)
				err = os.Chmod(blobPath, 0o000)
				So(err, ShouldBeNil)
			}
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// triggers perm denied on notary manifest on downstream
		for _, ref := range referrers.References {
			refPath := path.Join(destDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Hex())
			err := os.MkdirAll(refPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Chmod(refPath, 0o000)
			So(err, ShouldBeNil)
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// triggers perm denied on sig blobs
		for _, blob := range artifactManifest.Blobs {
			blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
			err := os.Chmod(blobPath, 0o000)
			So(err, ShouldBeNil)
		}

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// test cosign signatures errors
		// based on manifest digest get cosign manifest
		cosignEncodedDigest := strings.Replace(digest.String(), ":", "-", 1) + ".sig"
		getCosignManifestURL := srcBaseURL + path.Join(constants.RoutePrefix, repoName, "manifests", cosignEncodedDigest)

		mResp, err := resty.R().Get(getCosignManifestURL)
		So(err, ShouldBeNil)

		var imageManifest ispec.Manifest

		err = json.Unmarshal(mResp.Body(), &imageManifest)
		So(err, ShouldBeNil)

		downstreaamCosignManifest := ispec.Manifest{
			MediaType: imageManifest.MediaType,
			Config: ispec.Descriptor{
				MediaType:   imageManifest.Config.MediaType,
				Size:        imageManifest.Config.Size,
				Digest:      imageManifest.Config.Digest,
				Annotations: imageManifest.Config.Annotations,
			},
			Layers:      imageManifest.Layers,
			Versioned:   imageManifest.Versioned,
			Annotations: imageManifest.Annotations,
		}

		buf, err := json.Marshal(downstreaamCosignManifest)
		So(err, ShouldBeNil)
		cosignManifestDigest := godigest.FromBytes(buf)

		for _, blob := range imageManifest.Layers {
			blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
			err := os.Chmod(blobPath, 0o000)
			So(err, ShouldBeNil)
		}

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		for _, blob := range imageManifest.Layers {
			srcBlobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
			err := os.Chmod(srcBlobPath, 0o755)
			So(err, ShouldBeNil)

			destBlobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
			err = os.MkdirAll(destBlobPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Chmod(destBlobPath, 0o755)
			So(err, ShouldBeNil)
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		for _, blob := range imageManifest.Layers {
			destBlobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Hex())
			err = os.Chmod(destBlobPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Remove(destBlobPath)
			So(err, ShouldBeNil)
		}

		// trigger error on upstream config blob
		srcConfigBlobPath := path.Join(srcDir, repoName, "blobs", string(imageManifest.Config.Digest.Algorithm()),
			imageManifest.Config.Digest.Hex())
		err = os.Chmod(srcConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Chmod(srcConfigBlobPath, 0o755)
		So(err, ShouldBeNil)

		// trigger error on upstream config blob
		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		destConfigBlobPath := path.Join(destDir, repoName, "blobs", string(imageManifest.Config.Digest.Algorithm()),
			imageManifest.Config.Digest.Hex())

		err = os.MkdirAll(destConfigBlobPath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(destConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// trigger error on downstream manifest
		destManifestPath := path.Join(destDir, repoName, "blobs", string(cosignManifestDigest.Algorithm()),
			cosignManifestDigest.Hex())
		err = os.MkdirAll(destManifestPath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(destManifestPath, 0o000)
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestOnDemandRetryGoroutine(t *testing.T) {
	Convey("Verify ondemand sync retries in background on error", t, func() {
		srcPort := test.GetFreePort()
		srcConfig := config.New()
		srcBaseURL := test.GetBaseURL(srcPort)

		srcConfig.HTTP.Port = srcPort

		srcDir := t.TempDir()

		err := test.CopyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sctlr := api.NewController(srcConfig)

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		maxRetries := 3
		delay := 2 * time.Second
		syncRegistryConfig.MaxRetries = &maxRetries
		syncRegistryConfig.RetryDelay = &delay

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		// start upstream server
		go func() {
			// this blocks
			if err := sctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		defer func() {
			sctlr.Shutdown()
		}()

		// in the meantime ondemand should retry syncing
		time.Sleep(15 * time.Second)

		// now we should have the image synced
		binfo, err := os.Stat(path.Join(destDir, testImage, "index.json"))
		So(err, ShouldBeNil)
		So(binfo, ShouldNotBeNil)
		So(binfo.Size(), ShouldNotBeZeroValue)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestOnDemandRetryGoroutineErr(t *testing.T) {
	Convey("Verify ondemand sync retries in background on error", t, func() {
		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{"http://127.0.0.1"},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		maxRetries := 1
		delay := 1 * time.Second
		syncRegistryConfig.MaxRetries = &maxRetries
		syncRegistryConfig.RetryDelay = &delay

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		// in the meantime ondemand should retry syncing and finish with error
		time.Sleep(3 * time.Second)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestOnDemandMultipleRetries(t *testing.T) {
	Convey("Verify ondemand sync retries in background on error, multiple calls should spawn one routine", t, func() {
		srcPort := test.GetFreePort()
		srcConfig := config.New()
		srcBaseURL := test.GetBaseURL(srcPort)

		srcConfig.HTTP.Port = srcPort

		srcDir := t.TempDir()

		err := test.CopyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sctlr := api.NewController(srcConfig)

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			URLs:      []string{srcBaseURL},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		maxRetries := 5
		delay := 5 * time.Second
		syncRegistryConfig.MaxRetries = &maxRetries
		syncRegistryConfig.RetryDelay = &delay

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		callsNo := 5
		for i := 0; i < callsNo; i++ {
			_, _ = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		}

		populatedDirs := make(map[string]bool)

		done := make(chan bool)
		go func() {
			/* watch .sync local cache, make sure just one .sync/subdir is populated with image
			the channel from ondemand should prevent spawning multiple go routines for the same image*/
			for {
				time.Sleep(250 * time.Millisecond)
				select {
				case <-done:
					return
				default:
					dirs, err := os.ReadDir(path.Join(destDir, testImage, ".sync"))
					if err == nil {
						for _, dir := range dirs {
							contents, err := os.ReadDir(path.Join(destDir, testImage, ".sync", dir.Name()))
							if err == nil {
								if len(contents) > 0 {
									populatedDirs[dir.Name()] = true
								}
							}
						}
					}
				}
			}
		}()

		// start upstream server
		go func() {
			// this blocks
			if err := sctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(srcBaseURL)

		defer func() {
			sctlr.Shutdown()
		}()

		// wait sync
		for {
			_, err := os.Stat(path.Join(destDir, testImage, "index.json"))
			if err == nil {
				// stop watching /.sync/ subdirs
				done <- true

				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		waitSync(destDir, testImage)

		So(len(populatedDirs), ShouldEqual, 1)
	})
}

func TestOnDemandPullsOnce(t *testing.T) {
	Convey("Verify sync on demand pulls only one time", t, func(conv C) {
		sc, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sc.Shutdown()
		}()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, _ := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		var wg goSync.WaitGroup

		wg.Add(1)
		go func(conv C) {
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			conv.So(err, ShouldBeNil)
			conv.So(resp.StatusCode(), ShouldEqual, 200)
			wg.Done()
		}(conv)

		wg.Add(1)
		go func(conv C) {
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			conv.So(err, ShouldBeNil)
			conv.So(resp.StatusCode(), ShouldEqual, 200)
			wg.Done()
		}(conv)

		wg.Add(1)
		go func(conv C) {
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			conv.So(err, ShouldBeNil)
			conv.So(resp.StatusCode(), ShouldEqual, 200)
			wg.Done()
		}(conv)

		done := make(chan bool)

		var maxLen int
		syncBlobUploadDir := path.Join(destDir, testImage, sync.SyncBlobUploadDir)

		go func() {
			for {
				select {
				case <-done:
					return
				default:
					dirs, err := ioutil.ReadDir(syncBlobUploadDir)
					if err != nil {
						continue
					}
					// check how many .sync/uuid/ dirs are created, if just one then on demand pulled only once
					if len(dirs) > maxLen {
						maxLen = len(dirs)
					}
				}
			}
		}()

		wg.Wait()
		done <- true

		So(maxLen, ShouldEqual, 1)
	})
}

func TestError(t *testing.T) {
	Convey("Verify periodically sync pushSyncedLocalImage() error", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: testImage,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, client := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		// give permission denied on pushSyncedLocalImage()
		localRepoPath := path.Join(destDir, testImage, "blobs")
		err := os.MkdirAll(localRepoPath, 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(localRepoPath, 0o000)
		So(err, ShouldBeNil)

		resp, err := client.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestSignaturesOnDemand(t *testing.T) {
	Convey("Verify sync signatures on demand feature", t, func() {
		sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, _ := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		// sync on demand
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		a := &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
		amap, err := a.AnnotationsMap()
		if err != nil {
			panic(err)
		}

		// notation verify the synced image
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")
		cmd := exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
		out, err := cmd.CombinedOutput()
		So(err, ShouldBeNil)
		msg := string(out)
		So(msg, ShouldNotBeEmpty)
		So(strings.Contains(msg, "verification failure"), ShouldBeFalse)

		// cosign verify the synced image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			Annotations:     amap,
		}
		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")})
		So(err, ShouldBeNil)

		// test negative case
		cosignEncodedDigest := strings.Replace(digest.String(), ":", "-", 1) + ".sig"
		getCosignManifestURL := srcBaseURL + path.Join(constants.RoutePrefix, repoName, "manifests", cosignEncodedDigest)

		mResp, err := resty.R().Get(getCosignManifestURL)
		So(err, ShouldBeNil)

		var imageManifest ispec.Manifest

		err = json.Unmarshal(mResp.Body(), &imageManifest)
		So(err, ShouldBeNil)

		// trigger errors on cosign blobs
		// trigger error on cosign config blob
		srcConfigBlobPath := path.Join(srcDir, repoName, "blobs", string(imageManifest.Config.Digest.Algorithm()),
			imageManifest.Config.Digest.Hex())
		err = os.Chmod(srcConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// trigger error on cosign layer blob
		srcSignatureBlobPath := path.Join(srcDir, repoName, "blobs", string(imageManifest.Layers[0].Digest.Algorithm()),
			imageManifest.Layers[0].Digest.Hex())

		err = os.Chmod(srcConfigBlobPath, 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(srcSignatureBlobPath, 0o000)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Chmod(srcSignatureBlobPath, 0o755)
		So(err, ShouldBeNil)
	})
}

func TestOnlySignaturesOnDemand(t *testing.T) {
	Convey("Verify sync signatures on demand feature when we already have the image", t, func() {
		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		syncBadRegistryConfig := sync.RegistryConfig{
			URLs:      []string{"http://invalid.invalid:9999"},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncBadRegistryConfig, syncRegistryConfig},
		}

		dctlr, destBaseURL, _, _ := startDownstreamServer(t, false, syncConfig)

		defer func() {
			dctlr.Shutdown()
		}()

		// sync on demand
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		a := &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
		amap, err := a.AnnotationsMap()
		if err != nil {
			panic(err)
		}

		generateKeyPairs(tdir)

		// sync signature on demand when upstream doesn't have the signature
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")
		cmd := exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
		out, err := cmd.CombinedOutput()
		So(err, ShouldNotBeNil)
		msg := string(out)
		So(msg, ShouldNotBeEmpty)
		So(strings.Contains(msg, "signature failure"), ShouldBeTrue)

		// cosign verify the synced image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			Annotations:     amap,
		}

		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")})
		So(err, ShouldNotBeNil)

		// sign upstream image
		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		// now it should sync signatures on demand, even if we already have the image
		image = fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")
		cmd = exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
		out, err = cmd.CombinedOutput()
		So(err, ShouldBeNil)
		msg = string(out)
		So(msg, ShouldNotBeEmpty)
		So(strings.Contains(msg, "verification failure"), ShouldBeFalse)

		// cosign verify the synced image
		vrfy = verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			Annotations:     amap,
		}

		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")})
		So(err, ShouldBeNil)
	})
}

func TestSyncOnlyDiff(t *testing.T) {
	Convey("Verify sync only difference between local and upstream", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: "**",
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     false,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		// copy images so we have them before syncing, sync should not pull them again
		err := test.CopyFiles("../../../test/data", destDir)
		if err != nil {
			panic(err)
		}

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig
		destConfig.Log.Output = path.Join(destDir, "sync.log")

		dctlr := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		test.WaitTillServerReady(destBaseURL)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		time.Sleep(3 * time.Second)

		body, err := ioutil.ReadFile(path.Join(destDir, "sync.log"))
		if err != nil {
			log.Fatalf("unable to read file: %v", err)
		}

		So(string(body), ShouldContainSubstring, "already synced image")
	})
}

func TestSyncWithDiffDigest(t *testing.T) {
	Convey("Verify sync correctly detects changes in upstream images", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := startUpstreamServer(t, false, false)

		defer func() {
			sctlr.Shutdown()
		}()

		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: "**",
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     false,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		// copy images so we have them before syncing, sync should not pull them again
		err := test.CopyFiles("../../../test/data", destDir)
		if err != nil {
			panic(err)
		}

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		dctlr := api.NewController(destConfig)

		// before starting downstream server, let's modify an image manifest so that sync should pull it
		// change digest of the manifest so that sync should happen
		size := 5 * 1024 * 1024
		blob := make([]byte, size)
		digest := godigest.FromBytes(blob)

		resp, err := resty.R().Get(srcBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		manifestBlob := resp.Body()

		var manifest ispec.Manifest

		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().Post(srcBaseURL + "/v2/" + testImage + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		loc := resp.Header().Get("Location")

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest.String()).
			SetBody(blob).
			Put(srcBaseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)

		newLayer := ispec.Descriptor{
			MediaType: ispec.MediaTypeImageLayer,
			Digest:    digest,
			Size:      int64(size),
		}

		manifest.Layers = append(manifest.Layers, newLayer)

		manifestBody, err := json.Marshal(manifest)
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBody).
			Put(srcBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 201)

		go func() {
			// this blocks
			if err := dctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// watch .sync subdir, should be populated
		done := make(chan bool)
		var isPopulated bool
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					_, err := os.ReadDir(path.Join(destDir, testImage, ".sync"))
					if err == nil {
						isPopulated = true
					}
					time.Sleep(200 * time.Millisecond)
				}
			}
		}()

		defer func() {
			dctlr.Shutdown()
		}()

		test.WaitTillServerReady(destBaseURL)

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		waitSync(destDir, testImage)

		done <- true
		So(isPopulated, ShouldBeTrue)
	})
}

func TestSyncSignaturesDiff(t *testing.T) {
	Convey("Verify sync detects changes in the upstream signatures", t, func() {
		updateDuration, _ := time.ParseDuration("10s")

		sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			sctlr.Shutdown()
		}()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir, err := ioutil.TempDir("", "sigs")
		So(err, ShouldBeNil)

		_ = os.Chdir(tdir)
		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := sync.RegistryConfig{
			Content: []sync.Content{
				{
					Prefix: repoName,
					Tags: &sync.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     false,
		}

		defaultVal := true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := startDownstreamServer(t, false, syncConfig)
		defer func() {
			os.RemoveAll(destDir)
			dctlr.Shutdown()
		}()

		// wait for sync
		var destTagsList TagsList

		for {
			resp, err := destClient.R().Get(destBaseURL + "/v2/" + repoName + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		a := &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
		amap, err := a.AnnotationsMap()
		if err != nil {
			panic(err)
		}

		// notation verify the image
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")
		cmd := exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
		out, err := cmd.CombinedOutput()
		So(err, ShouldBeNil)

		msg := string(out)
		So(msg, ShouldNotBeEmpty)
		So(strings.Contains(msg, "verification failure"), ShouldBeFalse)

		// cosign verify the image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			Annotations:     amap,
		}
		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")})
		So(err, ShouldBeNil)

		// now add new signatures to upstream and let sync detect that upstream signatures changed and pull them
		So(os.RemoveAll(tdir), ShouldBeNil)
		tdir, err = ioutil.TempDir("", "sigs")
		So(err, ShouldBeNil)
		defer os.RemoveAll(tdir)
		_ = os.Chdir(tdir)
		generateKeyPairs(tdir)
		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		// wait for signatures
		time.Sleep(10 * time.Second)

		// notation verify the image
		image = fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")
		cmd = exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
		out, err = cmd.CombinedOutput()
		So(err, ShouldBeNil)

		msg = string(out)
		So(msg, ShouldNotBeEmpty)
		So(strings.Contains(msg, "verification failure"), ShouldBeFalse)

		// cosign verify the image
		vrfy = verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			Annotations:     amap,
		}
		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, "1.0")})
		So(err, ShouldBeNil)

		// compare signatures
		var srcIndex ispec.Index
		var destIndex ispec.Index

		srcBuf, err := ioutil.ReadFile(path.Join(srcDir, repoName, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		destBuf, err := ioutil.ReadFile(path.Join(destDir, repoName, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(destBuf, &destIndex); err != nil {
			panic(err)
		}

		// find image manifest digest (signed-repo) and upstream notary digests
		var upstreamRefsDigests []string
		var downstreamRefsDigests []string

		var manifestDigest string
		for _, manifestDesc := range srcIndex.Manifests {
			if manifestDesc.Annotations[ispec.AnnotationRefName] == "1.0" {
				manifestDigest = string(manifestDesc.Digest)
			} else if manifestDesc.MediaType == notreg.ArtifactTypeNotation {
				upstreamRefsDigests = append(upstreamRefsDigests, manifestDesc.Digest.String())
			}
		}

		for _, manifestDesc := range destIndex.Manifests {
			if manifestDesc.MediaType == notreg.ArtifactTypeNotation {
				downstreamRefsDigests = append(downstreamRefsDigests, manifestDesc.Digest.String())
			}
		}

		// compare notary signatures
		So(upstreamRefsDigests, ShouldResemble, downstreamRefsDigests)

		cosignManifestTag := strings.Replace(manifestDigest, ":", "-", 1) + ".sig"

		// get synced cosign manifest from downstream
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + cosignManifestTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var syncedCosignManifest ispec.Manifest

		err = json.Unmarshal(resp.Body(), &syncedCosignManifest)
		So(err, ShouldBeNil)

		// get cosign manifest from upstream
		resp, err = resty.R().Get(srcBaseURL + "/v2/" + repoName + "/manifests/" + cosignManifestTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var cosignManifest ispec.Manifest

		err = json.Unmarshal(resp.Body(), &cosignManifest)
		So(err, ShouldBeNil)

		// compare cosign signatures
		So(reflect.DeepEqual(cosignManifest, syncedCosignManifest), ShouldEqual, true)

		// let it sync one more time
		time.Sleep(10 * time.Second)
	})
}

func TestOnlySignedFlag(t *testing.T) {
	updateDuration, _ := time.ParseDuration("30m")

	sctlr, srcBaseURL, srcDir, _, _ := startUpstreamServer(t, false, false)
	defer os.RemoveAll(srcDir)

	defer func() {
		sctlr.Shutdown()
	}()

	regex := ".*"
	semver := true
	onlySigned := true

	var tlsVerify bool

	syncRegistryConfig := sync.RegistryConfig{
		Content: []sync.Content{
			{
				Prefix: testImage,
				Tags: &sync.Tags{
					Regex:  &regex,
					Semver: &semver,
				},
			},
		},
		URLs:         []string{srcBaseURL},
		PollInterval: updateDuration,
		TLSVerify:    &tlsVerify,
		CertDir:      "",
		OnlySigned:   &onlySigned,
	}

	defaultVal := true

	Convey("Verify sync revokes unsigned images", t, func() {
		syncRegistryConfig.OnDemand = false
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, client := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		time.Sleep(3 * time.Second)

		resp, err := client.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})

	Convey("Verify sync ondemand revokes unsigned images", t, func() {
		syncRegistryConfig.OnDemand = true
		syncConfig := &sync.Config{
			Enable:     &defaultVal,
			Registries: []sync.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, client := startDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			dctlr.Shutdown()
		}()

		resp, err := client.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func generateKeyPairs(tdir string) {
	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	if _, err := os.Stat(path.Join(tdir, "cosign.key")); err != nil {
		err := generate.GenerateKeyPairCmd(context.TODO(), "", nil)
		if err != nil {
			panic(err)
		}
	}

	// "notation" (notaryv2) doesn't yet support exported apis, so use the binary instead
	_, err := exec.LookPath("notation")
	if err != nil {
		panic(err)
	}

	os.Setenv("XDG_CONFIG_HOME", tdir)

	// generate a keypair
	cmd := exec.Command("notation", "cert", "generate-test", "--trust", "good")

	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}

func signImage(tdir, port, repoName string, digest godigest.Digest) {
	// push signatures to upstream server so that we can sync them later
	// sign the image
	err := sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.RegistryOptions{AllowInsecure: true},
		map[string]interface{}{"tag": "1.0"},
		[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())},
		"", "", true, "", "", "", false, false, "")
	if err != nil {
		panic(err)
	}

	// verify the image
	a := &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}

	amap, err := a.AnnotationsMap()
	if err != nil {
		panic(err)
	}

	vrfy := verify.VerifyCommand{
		RegistryOptions: options.RegistryOptions{AllowInsecure: true},
		CheckClaims:     true,
		KeyRef:          path.Join(tdir, "cosign.pub"),
		Annotations:     amap,
	}

	err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
	if err != nil {
		panic(err)
	}

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")
	cmd := exec.Command("notation", "sign", "--key", "good", "--plain-http", image)

	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	// verify the image
	cmd = exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
	out, err := cmd.CombinedOutput()
	So(err, ShouldBeNil)

	msg := string(out)
	So(msg, ShouldNotBeEmpty)
	So(strings.Contains(msg, "verification failure"), ShouldBeFalse)
}

func pushRepo(url, repoName string) godigest.Digest {
	// create a blob/layer
	resp, err := resty.R().Post(url + fmt.Sprintf("/v2/%s/blobs/uploads/", repoName))
	if err != nil {
		panic(err)
	}

	loc := test.Location(url, resp)

	_, err = resty.R().Get(loc)
	if err != nil {
		panic(err)
	}

	content := []byte("this is a blob")
	digest := godigest.FromBytes(content)

	_, err = resty.R().SetQueryParam("digest", digest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
	if err != nil {
		panic(err)
	}

	// upload image config blob
	resp, err = resty.R().
		Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repoName))
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusAccepted {
		panic(perr.Wrapf(errBadStatus, "invalid status code: %d", resp.StatusCode()))
	}

	loc = test.Location(url, resp)
	cblob, cdigest := test.GetRandomImageConfig()

	resp, err = resty.R().
		SetContentLength(true).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusCreated {
		panic(perr.Wrapf(errBadStatus, "invalid status code: %d", resp.StatusCode()))
	}

	// create a manifest
	manifest := ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cdigest,
			Size:      int64(len(cblob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest,
				Size:      int64(len(content)),
			},
		},
	}

	manifest.SchemaVersion = 2

	content, err = json.Marshal(manifest)
	if err != nil {
		panic(err)
	}

	digest = godigest.FromBytes(content)

	_, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).Put(url + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
	if err != nil {
		panic(err)
	}

	return digest
}

func waitSync(rootDir, repoName string) {
	// wait for .sync subdirs to be removed
	for {
		dirs, err := os.ReadDir(path.Join(rootDir, repoName, sync.SyncBlobUploadDir))
		if err == nil && len(dirs) == 0 {
			// stop watching /.sync/ subdirs
			return
		}

		time.Sleep(500 * time.Millisecond)
	}
}
