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
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/api/config"
	extconf "github.com/anuvu/zot/pkg/extensions/config"
	"github.com/anuvu/zot/pkg/extensions/sync"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/phayes/freeport"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	ServerCert    = "../../../test/data/server.cert"
	ServerKey     = "../../../test/data/server.key"
	CACert        = "../../../test/data/ca.crt"
	ClientCert    = "../../../test/data/client.cert"
	ClientKey     = "../../../test/data/client.key"

	testImage    = "zot-test"
	testImageTag = "0.0.1"
	testCveImage = "/zot-cve-test"
)

var errSync = errors.New("sync error, src oci repo differs from dest one")

type TagsList struct {
	Name string
	Tags []string
}

type catalog struct {
	Repositories []string `json:"repositories"`
}

func getFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return fmt.Sprint(port)
}

func getBaseURL(port string, secure bool) string {
	if secure {
		return fmt.Sprintf(BaseSecureURL, port)
	}

	return fmt.Sprintf(BaseURL, port)
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

func copyFiles(sourceDir string, destDir string) error {
	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return err
	}

	files, err := ioutil.ReadDir(sourceDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		sourceFilePath := path.Join(sourceDir, file.Name())
		destFilePath := path.Join(destDir, file.Name())

		if file.IsDir() {
			if err = copyFiles(sourceFilePath, destFilePath); err != nil {
				return err
			}
		} else {
			sourceFile, err := os.Open(sourceFilePath)
			if err != nil {
				return err
			}
			defer sourceFile.Close()

			destFile, err := os.Create(destFilePath)
			if err != nil {
				return err
			}
			defer destFile.Close()

			if _, err = io.Copy(destFile, sourceFile); err != nil {
				return err
			}
		}
	}

	return nil
}

func makeHtpasswdFile() string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte("test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n")
	if err := ioutil.WriteFile(f.Name(), content, 0600); err != nil {
		panic(err)
	}

	return f.Name()
}

func TestSyncOnDemand(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, false)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)

		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := resty.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(resp.Body(), &destTagsList)
		if err != nil {
			panic(err)
		}

		if eq := reflect.DeepEqual(destTagsList.Tags, srcTagsList.Tags); eq == false {
			panic(errSync)
		}
	})
}

func TestSync(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, false)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)

		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := resty.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		for {
			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
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

		if eq := reflect.DeepEqual(destTagsList.Tags, srcTagsList.Tags); eq == false {
			panic(errSync)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := resty.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Test sync with more contents", func() {
			destPort := getFreePort()
			destBaseURL := getBaseURL(destPort, false)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
			if err != nil {
				panic(err)
			}

			defer os.RemoveAll(destDir)

			destConfig.Storage.RootDirectory = destDir

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
				URL:          srcBaseURL,
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			destConfig.Extensions = &extconf.ExtensionConfig{}
			destConfig.Extensions.Search = nil
			destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

			dc := api.NewController(destConfig)

			go func() {
				// this blocks
				if err := dc.Run(); err != nil {
					return
				}
			}()

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
			}()

			// wait till ready
			for {
				_, err := resty.R().Get(destBaseURL)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := resty.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			for {
				resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
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

			if eq := reflect.DeepEqual(destTagsList.Tags, srcTagsList.Tags); eq == false {
				panic(errSync)
			}

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := resty.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)
			})
		})
	})
}

func TestSyncTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client := resty.New()

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { client.SetTLSClientConfig(nil) }()

		var srcIndex ispec.Index
		var destIndex ispec.Index

		updateDuration, _ := time.ParseDuration("1h")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, true)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		cert, err := tls.LoadX509KeyPair("../../../test/data/client.cert", "../../../test/data/client.key")
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
		// wait till ready
		for {
			_, err := client.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		srcBuf, err := ioutil.ReadFile(path.Join(srcDir, testImage, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		destPort := getFreePort()
		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

		// copy client certs, use them in sync config
		clientCertDir, err := ioutil.TempDir("", "certs")
		if err != nil {
			panic(err)
		}

		destFilePath := path.Join(clientCertDir, "ca.crt")
		err = copyFile(CACert, destFilePath)
		if err != nil {
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      clientCertDir,
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
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

func TestSyncBasicAuth(t *testing.T) {
	Convey("Verify sync basic auth", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, false)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		srcConfig.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(srcBaseURL)
			t.Logf("err %v", err)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Convey("Verify sync basic auth with file credentials", func() {
			destPort := getFreePort()
			destBaseURL := getBaseURL(destPort, false)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
			if err != nil {
				panic(err)
			}

			defer os.RemoveAll(destDir)

			destConfig.Storage.RootDirectory = destDir

			registryName := strings.Replace(strings.Replace(srcBaseURL, "http://", "", 1), "https://", "", 1)

			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "test"}}`, registryName))

			var tlsVerify bool

			syncRegistryConfig := sync.RegistryConfig{
				Content: []sync.Content{
					{
						Prefix: testImage,
					},
				},
				URL:          srcBaseURL,
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			destConfig.Extensions = &extconf.ExtensionConfig{}
			destConfig.Extensions.Search = nil
			destConfig.Extensions.Sync = &sync.Config{CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{syncRegistryConfig}}

			dc := api.NewController(destConfig)

			go func() {
				// this blocks
				if err := dc.Run(); err != nil {
					return
				}
			}()

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
			}()

			// wait till ready
			for {
				_, err := resty.R().Get(destBaseURL)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := resty.R().SetBasicAuth("test", "test").Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			for {
				resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
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

			if eq := reflect.DeepEqual(destTagsList.Tags, srcTagsList.Tags); eq == false {
				panic(errSync)
			}
		})

		Convey("Verify sync basic auth with bad file credentials", func() {
			destPort := getFreePort()
			destBaseURL := getBaseURL(destPort, false)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
			if err != nil {
				panic(err)
			}

			defer os.RemoveAll(destDir)

			destConfig.Storage.RootDirectory = destDir

			regex := ".*"
			var semver bool

			registryName := strings.Replace(strings.Replace(srcBaseURL, "http://", "", 1), "https://", "", 1)

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
				URL:          srcBaseURL,
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			destConfig.Extensions = &extconf.ExtensionConfig{}
			destConfig.Extensions.Search = nil
			destConfig.Extensions.Sync = &sync.Config{CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{syncRegistryConfig}}

			dc := api.NewController(destConfig)

			go func() {
				// this blocks
				if err := dc.Run(); err != nil {
					return
				}
			}()

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
			}()

			// wait till ready
			for {
				_, err := resty.R().Get(destBaseURL)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := resty.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(string(resp.Body()), ShouldContainSubstring, "sync: couldn't fetch upstream registry's catalog")
				So(resp.StatusCode(), ShouldEqual, 500)
			})
		})

		Convey("Verify on demand sync with basic auth", func() {
			destPort := getFreePort()
			destBaseURL := getBaseURL(destPort, false)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
			if err != nil {
				panic(err)
			}

			defer os.RemoveAll(destDir)

			destConfig.Storage.RootDirectory = destDir

			registryName := strings.Replace(strings.Replace(srcBaseURL, "http://", "", 1), "https://", "", 1)
			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "test"}}`, registryName))

			syncRegistryConfig := sync.RegistryConfig{
				URL:      srcBaseURL,
				OnDemand: true,
			}

			unreacheableSyncRegistryConfig1 := sync.RegistryConfig{
				URL:      "localhost:999999",
				OnDemand: true,
			}

			unreacheableSyncRegistryConfig2 := sync.RegistryConfig{
				URL:      "localhost:999999",
				OnDemand: false,
			}

			destConfig.Extensions = &extconf.ExtensionConfig{}
			destConfig.Extensions.Search = nil
			// add file path to the credentials
			destConfig.Extensions.Sync = &sync.Config{CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{unreacheableSyncRegistryConfig1,
					unreacheableSyncRegistryConfig2,
					syncRegistryConfig}}

			dc := api.NewController(destConfig)

			go func() {
				// this blocks
				if err := dc.Run(); err != nil {
					return
				}
			}()

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
			}()

			// wait till ready
			for {
				_, err := resty.R().Get(destBaseURL)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := resty.R().SetBasicAuth("test", "test").Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			resp, err = resty.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = dc.StoreController.DefaultStore.DeleteImageManifest(testImage, testImageTag)
			So(err, ShouldBeNil)

			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if eq := reflect.DeepEqual(destTagsList.Tags, srcTagsList.Tags); eq == false {
				panic(errSync)
			}

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := resty.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)
			})
		})
	})
}

func TestSyncBadUrl(t *testing.T) {
	Convey("Verify sync with bad url", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)

		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

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
			URL:          "bad-registry-url",
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}
		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := resty.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(string(resp.Body()), ShouldContainSubstring, "unsupported protocol scheme")
			So(resp.StatusCode(), ShouldEqual, 500)
		})
	})
}

func TestSyncNoImagesByRegex(t *testing.T) {
	Convey("Verify sync with no images on source based on regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, false)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)

		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

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
			URL:          srcBaseURL,
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := resty.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(destBaseURL + "/v2/_catalog")
			if err != nil {
				panic(err)
			}

			var c catalog
			err = json.Unmarshal(resp.Body(), &c)
			if err != nil {
				panic(err)
			}

			So(c.Repositories, ShouldResemble, []string{})
		})
	})
}

func TestSyncInvalidRegex(t *testing.T) {
	Convey("Verify sync with invalid regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, false)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)

		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

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
			URL:          srcBaseURL,
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := resty.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(string(resp.Body()), ShouldContainSubstring, "error parsing regexp")
			So(resp.StatusCode(), ShouldEqual, 500)
		})
	})
}

func TestSyncNotSemver(t *testing.T) {
	Convey("Verify sync feature semver compliant", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, false)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

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

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)

		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := resty.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(err, ShouldBeNil)

			var destTagsList TagsList

			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			So(len(destTagsList.Tags), ShouldEqual, 1)
			So(destTagsList.Tags[0], ShouldEqual, testImageTag)
		})
	})
}

func TestSyncInvalidCerts(t *testing.T) {
	Convey("Verify sync with bad certs", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client := resty.New()

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { client.SetTLSClientConfig(nil) }()
		updateDuration, _ := time.ParseDuration("1h")

		srcPort := getFreePort()
		srcBaseURL := getBaseURL(srcPort, true)

		srcConfig := config.New()
		srcConfig.HTTP.Port = srcPort

		srcConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(srcDir)

		err = copyFiles("../../../test/data", srcDir)
		if err != nil {
			panic(err)
		}

		srcConfig.Storage.RootDirectory = srcDir

		sc := api.NewController(srcConfig)

		go func() {
			// this blocks
			if err := sc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		cert, err := tls.LoadX509KeyPair("../../../test/data/client.cert", "../../../test/data/client.key")
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
		// wait till ready
		for {
			_, err := client.R().Get(srcBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		destPort := getFreePort()
		destBaseURL := getBaseURL(destPort, false)
		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		os.RemoveAll("/tmp/zot-certs-dir")

		destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

		// copy client certs, use them in sync config
		clientCertDir, err := ioutil.TempDir("", "certs")
		if err != nil {
			panic(err)
		}

		destFilePath := path.Join(clientCertDir, "ca.crt")
		err = copyFile(CACert, destFilePath)
		if err != nil {
			panic(err)
		}

		f, err := os.OpenFile(destFilePath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		if _, err = f.WriteString("Add Invalid Text In Cert"); err != nil {
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      clientCertDir,
		}

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc := api.NewController(destConfig)

		go func() {
			// this blocks
			if err := dc.Run(); err != nil {
				return
			}
		}()

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(destBaseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := resty.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(string(resp.Body()), ShouldContainSubstring, "signed by unknown authority")
			So(resp.StatusCode(), ShouldEqual, 500)
		})
	})
}

func makeCredentialsFile(fileContent string) string {
	f, err := ioutil.TempFile("", "sync-credentials-")
	if err != nil {
		panic(err)
	}

	content := []byte(fileContent)
	if err := ioutil.WriteFile(f.Name(), content, 0600); err != nil {
		panic(err)
	}

	return f.Name()
}
