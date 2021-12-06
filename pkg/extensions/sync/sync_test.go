//go:build extended
// +build extended

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

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	. "zotregistry.io/zot/test"
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
)

var errSync = errors.New("sync error, src oci repo differs from dest one")

type TagsList struct {
	Name string
	Tags []string
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

func startUpstreamServer(secure, basicAuth bool) (*api.Controller, string, string, string, *resty.Client) {
	srcPort := GetFreePort()

	srcConfig := config.New()

	client := resty.New()

	var srcBaseURL string
	if secure {
		srcBaseURL = GetSecureBaseURL(srcPort)

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

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})

		cert, err := tls.LoadX509KeyPair("../../../test/data/client.cert", "../../../test/data/client.key")
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
	} else {
		srcBaseURL = GetBaseURL(srcPort)
	}

	var htpasswdPath string
	if basicAuth {
		htpasswdPath = MakeHtpasswdFile()
		srcConfig.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
	}

	srcConfig.HTTP.Port = srcPort

	srcDir, err := ioutil.TempDir("", "oci-src-repo-test")
	if err != nil {
		panic(err)
	}

	err = CopyFiles("../../../test/data", srcDir)
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

	// wait till ready
	for {
		_, err := client.R().Get(srcBaseURL)
		if err == nil {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return sc, srcBaseURL, srcDir, htpasswdPath, client
}

func startDownstreamServer(secure bool, syncConfig *sync.Config) (*api.Controller, string, string, *resty.Client) {
	destPort := GetFreePort()

	destConfig := config.New()

	client := resty.New()

	var destBaseURL string
	if secure {
		destBaseURL = GetSecureBaseURL(destPort)

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

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})

		cert, err := tls.LoadX509KeyPair("../../../test/data/client.cert", "../../../test/data/client.key")
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
	} else {
		destBaseURL = GetBaseURL(destPort)
	}

	destConfig.HTTP.Port = destPort

	destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
	if err != nil {
		panic(err)
	}

	destConfig.Storage.RootDirectory = destDir

	destConfig.Extensions = &extconf.ExtensionConfig{}
	destConfig.Extensions.Search = nil
	destConfig.Extensions.Sync = syncConfig

	dc := api.NewController(destConfig)

	go func() {
		// this blocks
		if err := dc.Run(); err != nil {
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

	return dc, destBaseURL, destDir, client
}

func TestSyncOnDemand(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sc, srcBaseURL, srcDir, _, srcClient := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		syncConfig := &sync.Config{
			Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
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

		err = os.Chmod(path.Join(destDir, testImage), 0000)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 500)

		err = os.Chmod(path.Join(destDir, testImage), 0755)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.Chmod(path.Join(destDir, testImage, sync.SyncBlobUploadDir), 0000)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.Chmod(path.Join(destDir, testImage, sync.SyncBlobUploadDir), 0755)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(path.Join(destDir, testImage, "blobs"), 0000)
		if err != nil {
			panic(err)
		}

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		err = os.Chmod(path.Join(destDir, testImage, "blobs"), 0755)
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

func TestSync(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sc, srcBaseURL, srcDir, _, srcClient := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
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

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

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
				URL:          srcBaseURL,
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

			dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
			defer os.RemoveAll(destDir)

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
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

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := destClient.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)
			})
		})
	})
}

func TestSyncPermsDenied(t *testing.T) {
	Convey("Verify sync feature without perm on sync cache", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		err := os.Chmod(path.Join(destDir, testImage, sync.SyncBlobUploadDir), 0000)
		if err != nil {
			panic(err)
		}

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 500)
		})
	})
}

func TestSyncBadTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(true, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			OnDemand:     true,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(true, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		// give it time to set up sync
		time.Sleep(2 * time.Second)

		resp, _ := destClient.R().Post(destBaseURL + "/sync")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 500)

		resp, _ = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "invalid")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = destClient.R().Get(destBaseURL + "/v2/" + "invalid" + "/manifests/" + testImageTag)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestSyncTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(true, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
		destClientCertDir, err := ioutil.TempDir("", "destCerts")
		if err != nil {
			panic(err)
		}

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

		defer os.RemoveAll(destClientCertDir)

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
			CertDir:      destClientCertDir,
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(true, syncConfig)
		defer os.RemoveAll(destDir)

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

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().SetBasicAuth("test", "test").Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})
	})
}

func TestSyncBasicAuth(t *testing.T) {
	Convey("Verify sync basic auth", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sc, srcBaseURL, srcDir, htpasswdPath, srcClient := startUpstreamServer(false, true)
		defer os.Remove(htpasswdPath)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

		Convey("Verify sync basic auth with file credentials", func() {
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

			syncConfig := &sync.Config{CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{syncRegistryConfig}}

			dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
			defer os.RemoveAll(destDir)

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
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
			destPort := GetFreePort()
			destBaseURL := GetBaseURL(destPort)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir, err := ioutil.TempDir("", "oci-dest-repo-test")
			if err != nil {
				panic(err)
			}

			destConfig.Storage.SubPaths = map[string]config.StorageConfig{
				"a": {
					RootDirectory: destDir,
					GC:            true,
					Dedupe:        true,
				},
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
				OnDemand:     true,
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

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := resty.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(string(resp.Body()), ShouldContainSubstring, "sync: couldn't fetch upstream registry's catalog")
				So(resp.StatusCode(), ShouldEqual, 500)
			})
		})

		Convey("Verify sync basic auth with bad file credentials", func() {
			registryName := strings.Replace(strings.Replace(srcBaseURL, "http://", "", 1), "https://", "", 1)

			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "test", "password": "test"}}`,
				registryName))

			err := os.Chmod(credentialsFile, 0000)
			So(err, ShouldBeNil)

			defer func() {
				So(os.Chmod(credentialsFile, 0755), ShouldBeNil)
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
				URL:          srcBaseURL,
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			syncConfig := &sync.Config{CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{syncRegistryConfig}}

			dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
			defer os.RemoveAll(destDir)

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
			}()

			resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := destClient.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(string(resp.Body()), ShouldContainSubstring, "permission denied")
				So(resp.StatusCode(), ShouldEqual, 500)
			})
		})

		Convey("Verify on demand sync with basic auth", func() {
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

			// add file path to the credentials
			syncConfig := &sync.Config{CredentialsFile: credentialsFile,
				Registries: []sync.RegistryConfig{unreacheableSyncRegistryConfig1,
					unreacheableSyncRegistryConfig2,
					syncRegistryConfig}}

			dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
			defer os.RemoveAll(destDir)

			defer func() {
				ctx := context.Background()
				_ = dc.Server.Shutdown(ctx)
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

			err = dc.StoreController.DefaultStore.DeleteImageManifest(testImage, testImageTag)
			So(err, ShouldBeNil)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 404)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			So(destTagsList, ShouldResemble, srcTagsList)

			Convey("Test sync on POST request on /sync", func() {
				resp, _ := destClient.R().Post(destBaseURL + "/sync")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)
			})
		})
	})
}

func TestSyncBadURL(t *testing.T) {
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
			URL:          "bad-registry-url",
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(string(resp.Body()), ShouldContainSubstring, "unsupported protocol scheme")
			So(resp.StatusCode(), ShouldEqual, 500)
		})
	})
}

func TestSyncNoImagesByRegex(t *testing.T) {
	Convey("Verify sync with no images on source based on regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		Convey("Test sync on POST request on /sync", func() {
			resp, err := destClient.R().Post(destBaseURL + "/sync")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			resp, err = destClient.R().Get(destBaseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeEmpty)
			So(resp.StatusCode(), ShouldEqual, 200)

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

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(string(resp.Body()), ShouldContainSubstring, "error parsing regexp")
			So(resp.StatusCode(), ShouldEqual, 500)
		})
	})
}

func TestSyncNotSemver(t *testing.T) {
	Convey("Verify sync feature semver compliant", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			var destTagsList TagsList

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

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
		updateDuration, _ := time.ParseDuration("1h")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(true, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
		}()

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

		defer os.RemoveAll(clientCertDir)

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

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		Convey("Test sync on POST request on /sync", func() {
			resp, _ := destClient.R().Post(destBaseURL + "/sync")
			So(resp, ShouldNotBeNil)
			So(string(resp.Body()), ShouldContainSubstring, "bad certificate")
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

func TestSyncInvalidUrl(t *testing.T) {
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
			URL:          "http://invalid.invalid/invalid/",
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		syncConfig := &sync.Config{Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}

func TestSyncInvalidTags(t *testing.T) {
	Convey("Verify sync invalid tags", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sc, srcBaseURL, srcDir, _, _ := startUpstreamServer(false, false)
		defer os.RemoveAll(srcDir)

		defer func() {
			ctx := context.Background()
			_ = sc.Server.Shutdown(ctx)
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
			URL:          srcBaseURL,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		syncConfig := &sync.Config{
			Registries: []sync.RegistryConfig{syncRegistryConfig}}

		dc, destBaseURL, destDir, destClient := startDownstreamServer(false, syncConfig)
		defer os.RemoveAll(destDir)

		defer func() {
			ctx := context.Background()
			_ = dc.Server.Shutdown(ctx)
		}()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "invalid:tag")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}
