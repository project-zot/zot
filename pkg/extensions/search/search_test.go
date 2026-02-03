//go:build search

package search_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	guuid "github.com/gofrs/uuid"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	cveinfo "zotregistry.dev/zot/v2/pkg/extensions/search/cve"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
	"zotregistry.dev/zot/v2/pkg/test/signature"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

const (
	graphqlQueryPrefix = constants.FullSearchPrefix
	DBFileName         = "meta.db"
)

var (
	ErrTestError   = errors.New("test error")
	ErrPutManifest = errors.New("can't put manifest")
)

func readFileAndSearchString(filePath string, stringToMatch string, timeout time.Duration) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(filePath)
			if err != nil {
				return false, err
			}

			if strings.Contains(string(content), stringToMatch) {
				return true, nil
			}
		}
	}
}

func verifyRepoSummaryFields(t *testing.T,
	actualRepoSummary, expectedRepoSummary *zcommon.RepoSummary,
) {
	t.Helper()

	t.Logf("Verify RepoSummary \n%v \nmatches fields of \n%v",
		actualRepoSummary, expectedRepoSummary,
	)

	So(actualRepoSummary.Name, ShouldEqual, expectedRepoSummary.Name)
	So(actualRepoSummary.LastUpdated, ShouldEqual, expectedRepoSummary.LastUpdated)
	So(actualRepoSummary.Size, ShouldEqual, expectedRepoSummary.Size)
	So(len(actualRepoSummary.Vendors), ShouldEqual, len(expectedRepoSummary.Vendors))

	for index, vendor := range actualRepoSummary.Vendors {
		So(vendor, ShouldEqual, expectedRepoSummary.Vendors[index])
	}

	So(len(actualRepoSummary.Platforms), ShouldEqual, len(expectedRepoSummary.Platforms))

	for index, platform := range actualRepoSummary.Platforms {
		So(platform.Os, ShouldEqual, expectedRepoSummary.Platforms[index].Os)
		So(platform.Arch, ShouldEqual, expectedRepoSummary.Platforms[index].Arch)
	}

	So(actualRepoSummary.NewestImage.Tag, ShouldEqual, expectedRepoSummary.NewestImage.Tag)
	verifyImageSummaryFields(t, &actualRepoSummary.NewestImage, &expectedRepoSummary.NewestImage)
}

func verifyImageSummaryFields(t *testing.T,
	actualImageSummary, expectedImageSummary *zcommon.ImageSummary,
) {
	t.Helper()

	t.Logf("Verify ImageSummary \n%v \nmatches fields of \n%v",
		actualImageSummary, expectedImageSummary,
	)

	So(actualImageSummary.Tag, ShouldEqual, expectedImageSummary.Tag)
	So(actualImageSummary.LastUpdated, ShouldEqual, expectedImageSummary.LastUpdated)
	So(actualImageSummary.Size, ShouldEqual, expectedImageSummary.Size)
	So(actualImageSummary.IsSigned, ShouldEqual, expectedImageSummary.IsSigned)
	So(actualImageSummary.Vendor, ShouldEqual, expectedImageSummary.Vendor)
	So(actualImageSummary.Title, ShouldEqual, expectedImageSummary.Title)
	So(actualImageSummary.Description, ShouldEqual, expectedImageSummary.Description)
	So(actualImageSummary.Source, ShouldEqual, expectedImageSummary.Source)
	So(actualImageSummary.Documentation, ShouldEqual, expectedImageSummary.Documentation)
	So(actualImageSummary.Licenses, ShouldEqual, expectedImageSummary.Licenses)

	So(len(actualImageSummary.Manifests), ShouldEqual, len(expectedImageSummary.Manifests))

	for i := range actualImageSummary.Manifests {
		So(actualImageSummary.Manifests[i].Platform.Os, ShouldEqual, expectedImageSummary.Manifests[i].Platform.Os)
		So(actualImageSummary.Manifests[i].Platform.Arch, ShouldEqual, expectedImageSummary.Manifests[i].Platform.Arch)
		So(len(actualImageSummary.Manifests[i].History), ShouldEqual, len(expectedImageSummary.Manifests[i].History))

		expectedHistories := expectedImageSummary.Manifests[i].History

		for index, history := range actualImageSummary.Manifests[i].History {
			// Digest could be empty string if the history entry is not associated with a layer
			So(history.Layer.Digest, ShouldEqual, expectedHistories[index].Layer.Digest)
			So(history.Layer.Size, ShouldEqual, expectedHistories[index].Layer.Size)
			So(
				history.HistoryDescription.Author,
				ShouldEqual,
				expectedHistories[index].HistoryDescription.Author,
			)
			So(
				history.HistoryDescription.Created,
				ShouldEqual,
				expectedHistories[index].HistoryDescription.Created,
			)
			So(
				history.HistoryDescription.CreatedBy,
				ShouldEqual,
				expectedHistories[index].HistoryDescription.CreatedBy,
			)
			So(
				history.HistoryDescription.EmptyLayer,
				ShouldEqual,
				expectedHistories[index].HistoryDescription.EmptyLayer,
			)
			So(
				history.HistoryDescription.Comment,
				ShouldEqual,
				expectedHistories[index].HistoryDescription.Comment,
			)
		}
	}
}

func uploadNewRepoTag(tag string, repoName string, baseURL string, layers [][]byte) error {
	created := time.Now()
	config := ispec.Image{
		Created: &created,
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
	So(err, ShouldBeNil)

	configDigest := godigest.FromBytes(configBlob)

	manifest := ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
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

	err = UploadImage(
		Image{
			Manifest: manifest,
			Config:   config,
			Layers:   layers,
		}, baseURL, repoName, tag,
	)

	return err
}

func getMockCveScanner(metaDB mTypes.MetaDB) cveinfo.Scanner {
	// MetaDB loaded with initial data, mock the scanner
	// Setup test CVE data in mock scanner
	getCveResults := func(image string) map[string]cvemodel.CVE {
		if image == "zot-cve-test:0.0.1" || image == "a/zot-cve-test:0.0.1" ||
			image == "zot-test:0.0.1" || image == "a/zot-test:0.0.1" ||
			strings.Contains(image, "sha256:40d1f74918aefed733c590f798d7eafde8fc0a7ec63bb8bc52eaae133cf92495") ||
			strings.Contains(image, "sha256:db573b0146a853af339bde42256a810b911d89c9252d055e0218de53690e031e") ||
			strings.Contains(image, "sha256:0d8d7cae58478b43cde65d4fd495e1b4ab3f6404450b17e75d7e04eb2040d297") {
			return map[string]cvemodel.CVE{
				"CVE1": {
					ID:          "CVE1",
					Severity:    "MEDIUM",
					Title:       "Title CVE1",
					Description: "Description CVE1",
				},
				"CVE2": {
					ID:          "CVE2",
					Severity:    "HIGH",
					Title:       "Title CVE2",
					Description: "Description CVE2",
				},
				"CVE3": {
					ID:          "CVE3",
					Severity:    "LOW",
					Title:       "Title CVE3",
					Description: "Description CVE3",
				},
				"CVE4": {
					ID:          "CVE4",
					Severity:    "CRITICAL",
					Title:       "Title CVE4",
					Description: "Description CVE4",
				},
			}
		}

		if image == "test-repo:latest" ||
			strings.Contains(image, "sha256:9f8e1a125c4fb03a0f157d75999b73284ccc5cba18eb772e4643e3499343607e") ||
			strings.Contains(image, "sha256:5c6e8dd5dce1c488fc79d02690b11ff7a190fad21885297101dbd531f0db3597") {
			return map[string]cvemodel.CVE{
				"CVE1": {
					ID:          "CVE1",
					Severity:    "MEDIUM",
					Title:       "Title CVE1",
					Description: "Description CVE1",
				},
				"CVE2": {
					ID:          "CVE2",
					Severity:    "HIGH",
					Title:       "Title CVE2",
					Description: "Description CVE2",
				},
				"CVE3": {
					ID:          "CVE3",
					Severity:    "LOW",
					Title:       "Title CVE3",
					Description: "Description CVE3",
				},
				"CVE4": {
					ID:          "CVE4",
					Severity:    "CRITICAL",
					Title:       "Title CVE4",
					Description: "Description CVE4",
				},
			}
		}

		// By default the image has no vulnerabilities
		return map[string]cvemodel.CVE{}
	}

	scanner := mocks.CveScannerMock{
		ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
			return getCveResults(image), nil
		},
		GetCachedResultFn: func(digestStr string) map[string]cvemodel.CVE {
			return getCveResults(digestStr)
		},
		IsResultCachedFn: func(digestStr string) bool {
			return true
		},
		IsImageFormatScannableFn: func(repo string, reference string) (bool, error) {
			// Almost same logic compared to actual Trivy specific implementation
			imageDir := repo
			inputTag := reference

			repoMeta, err := metaDB.GetRepoMeta(context.Background(), imageDir)
			if err != nil {
				return false, err
			}

			manifestDigestStr := reference

			if zcommon.IsTag(reference) {
				var ok bool

				descriptor, ok := repoMeta.Tags[inputTag]
				if !ok {
					return false, zerr.ErrTagMetaNotFound
				}

				manifestDigestStr = descriptor.Digest
			}

			manifestDigest, err := godigest.Parse(manifestDigestStr)
			if err != nil {
				return false, err
			}

			manifestData, err := metaDB.GetImageMeta(manifestDigest)
			if err != nil {
				return false, err
			}

			for _, imageLayer := range manifestData.Manifests[0].Manifest.Layers {
				switch imageLayer.MediaType {
				case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):
					return true, nil
				default:
					return false, zerr.ErrScanNotSupported
				}
			}

			return false, nil
		},
	}

	return &scanner
}

func TestRepoListWithNewestImage(t *testing.T) {
	Convey("Test repoListWithNewestImage by tag with HTTP", t, func() {
		subpath := "/a"
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		rootDir := t.TempDir()
		subRootDir := t.TempDir()
		conf.Storage.RootDirectory = rootDir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		uploadedImage := CreateImageWith().RandomLayers(1, 100).DefaultConfig().Build()

		err := UploadImage(uploadedImage, baseURL, "zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "zot-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-test", "0.0.1")
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		Convey("Test repoListWithNewestImage with pagination", func() {
			query := `{
				RepoListWithNewestImage(requestedPage:{
					limit: 2
					offset: 0
					sortBy: UPDATE_TIME
				}){
					Page{
						ItemCount
						TotalCount
					}
					Results{
						Name
						NewestImage{
							Tag
						}
					}
				}
			}`

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			var responseStruct zcommon.RepoWithNewestImageResponse
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 2)
			So(responseStruct.Page.ItemCount, ShouldEqual, 2)
			So(responseStruct.Page.TotalCount, ShouldEqual, 4)
		})

		Convey("Test repoListWithNewestImage with pagination, no limit or offset", func() {
			query := `{
				RepoListWithNewestImage(requestedPage:{
					limit: 0
					offset: 0
					sortBy: UPDATE_TIME
				}){
					Page{
						ItemCount
						TotalCount
					}
					Results{
						Name
						NewestImage{
							Tag
						}
					}
				}
			}`

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			var responseStruct zcommon.RepoWithNewestImageResponse
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 4)
			So(responseStruct.Page.ItemCount, ShouldEqual, 4)
			So(responseStruct.Page.TotalCount, ShouldEqual, 4)
		})

		Convey("Test repoListWithNewestImage multiple", func() {
			query := `{RepoListWithNewestImage{
							Results{
								Name
								NewestImage{
									Tag
								}
							}
						}}`
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			var responseStruct zcommon.RepoWithNewestImageResponse
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 4)

			images := responseStruct.Results
			So(images[0].NewestImage.Tag, ShouldEqual, "0.0.1")

			query = `{
				RepoListWithNewestImage(requestedPage: {
					limit: 1
					offset: 0
					sortBy: UPDATE_TIME
				}){
					Results{
						Name
						NewestImage{
							Tag
						}
					}
				}
			}`
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 1)

			repos := responseStruct.Results
			So(repos[0].NewestImage.Tag, ShouldEqual, "0.0.1")

			query = `{
				RepoListWithNewestImage{
					Results{
						Name
						NewestImage{
							Tag
							Vulnerabilities{
								MaxSeverity
								UnknownCount
								LowCount
								MediumCount
								HighCount
								CriticalCount
								Count
							}
						}
					}
				}
			}`

			// Verify we don't return any vulnerabilities if CVE scanning is disabled
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 4)

			images = responseStruct.Results
			So(images[0].NewestImage.Tag, ShouldEqual, "0.0.1")
			So(images[0].NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
			So(images[0].NewestImage.Vulnerabilities.UnknownCount, ShouldEqual, 0)
			So(images[0].NewestImage.Vulnerabilities.LowCount, ShouldEqual, 0)
			So(images[0].NewestImage.Vulnerabilities.MediumCount, ShouldEqual, 0)
			So(images[0].NewestImage.Vulnerabilities.HighCount, ShouldEqual, 0)
			So(images[0].NewestImage.Vulnerabilities.CriticalCount, ShouldEqual, 0)
			So(images[0].NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "")

			query = `{
				RepoListWithNewestImage{
					Results{
						Name
						NewestImage{
							Tag
						}
					}
				}
			}`
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)

			err = os.Chmod(rootDir, 0o000)
			if err != nil {
				panic(err)
			}

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(responseStruct.Errors, ShouldBeNil) // Even if permissions fail data is coming from the DB

			err = os.Chmod(rootDir, 0o755)
			if err != nil {
				panic(err)
			}

			manifestDigest := uploadedImage.ManifestDescriptor.Digest
			configDigest := uploadedImage.ConfigDescriptor.Digest

			// Delete config blob and try.
			err = os.Remove(path.Join(subRootDir, "a/zot-test/blobs/sha256", configDigest.Encoded()))
			if err != nil && !os.IsNotExist(err) {
				panic(err)
			}

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = os.Remove(path.Join(subRootDir, "a/zot-test/blobs/sha256",
				manifestDigest.Encoded()))
			if err != nil && !os.IsNotExist(err) {
				panic(err)
			}

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", configDigest.Encoded()))
			if err != nil && !os.IsNotExist(err) {
				panic(err)
			}

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			// Delete manifest blob also and try
			err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", manifestDigest.Encoded()))
			if err != nil && !os.IsNotExist(err) {
				panic(err)
			}

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
				"?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})
	})

	Convey("Test repoListWithNewestImage with vulnerability scan enabled", t, func() {
		subpath := "/a"
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		rootDir := t.TempDir()
		subRootDir := t.TempDir()
		conf.Storage.RootDirectory = rootDir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true

		updateDuration, _ := time.ParseDuration("1h")
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
			Trivy:          trivyConfig,
		}
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		// we won't use the logging config feature as we want logs in both
		// stdout and a file
		logFile := MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		logPath := logFile.Name()

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log = log.NewLoggerWithWriter("debug", writers)

		if err := ctlr.Init(); err != nil {
			panic(err)
		}

		ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		substring := "{\"Search\":{\"Enable\":true,\"CVE\":{\"UpdateInterval\":3600000000000," +
			"\"Trivy\":{\"DBRepository\":\"ghcr.io/project-zot/trivy-db\",\"JavaDBRepository\":\"\"}}}"
		found, err := readFileAndSearchString(logPath, substring, 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "updating cve-db", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath,
			"cve-db update completed, next update scheduled after interval", 4*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		WaitTillServerReady(baseURL)

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		uploadedImage := CreateDefaultImage()

		err = UploadImage(uploadedImage, baseURL, "zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "zot-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-test", "0.0.1")
		So(err, ShouldBeNil)

		query := `{
			RepoListWithNewestImage{
				Results{
					Name
					NewestImage{
						Tag
						Digest
						Vulnerabilities{
							MaxSeverity
							UnknownCount
							LowCount
							MediumCount
							HighCount
							CriticalCount
							Count
						}
					}
				}
			}
		}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.RepoWithNewestImageResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 4)

		repos := responseStruct.Results
		So(repos[0].NewestImage.Tag, ShouldEqual, "0.0.1")

		for _, repo := range repos {
			vulnerabilities := repo.NewestImage.Vulnerabilities
			So(vulnerabilities, ShouldNotBeNil)
			t.Logf("Found vulnerability summary %v", vulnerabilities)
			// Depends on test data, but current tested images contain hundreds
			So(vulnerabilities.Count, ShouldEqual, 4)
			So(vulnerabilities.UnknownCount, ShouldEqual, 0)
			So(vulnerabilities.LowCount, ShouldEqual, 1)
			So(vulnerabilities.MediumCount, ShouldEqual, 1)
			So(vulnerabilities.HighCount, ShouldEqual, 1)
			So(vulnerabilities.CriticalCount, ShouldEqual, 1)
			So(vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")
		}
	})
}

func TestGetReferrersGQL(t *testing.T) {
	Convey("get referrers", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
			Lint: &extconf.LintConfig{
				BaseConfig: extconf.BaseConfig{
					Enable: &defaultVal,
				},
			},
		}

		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, graphqlQueryPrefix)

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)

		defer ctlrManager.StopServer()

		// =======================

		uploadedImage := CreateImageWith().RandomLayers(1, 1000).DefaultConfig().Build()

		repo := "artifact-ref"

		err := UploadImage(uploadedImage, baseURL, repo, "1.0")
		So(err, ShouldBeNil)

		manifestDigest := uploadedImage.ManifestDescriptor.Digest
		manifestSize := uploadedImage.ManifestDescriptor.Size

		subjectDescriptor := &ispec.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Size:      manifestSize,
			Digest:    manifestDigest,
		}

		artifactContentBlob := []byte("test artifact")
		artifactContentBlobSize := int64(len(artifactContentBlob))
		artifactContentType := "application/octet-stream"
		artifactContentBlobDigest := godigest.FromBytes(artifactContentBlob)
		artifactType := "com.artifact.test/type1"

		artifactImg := Image{
			Manifest: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						MediaType: artifactContentType,
						Digest:    artifactContentBlobDigest,
						Size:      artifactContentBlobSize,
					},
				},
				Subject:      subjectDescriptor,
				ArtifactType: artifactType,
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeEmptyJSON,
					Digest:    ispec.DescriptorEmptyJSON.Digest,
					Data:      ispec.DescriptorEmptyJSON.Data,
				},
				MediaType: ispec.MediaTypeImageManifest,
				Annotations: map[string]string{
					"com.artifact.format": "test",
				},
			},
			Config: ispec.Image{},
			Layers: [][]byte{artifactContentBlob},
		}

		artifactImg.Manifest.SchemaVersion = 2

		artifactManifestBlob, err := json.Marshal(artifactImg.Manifest)
		So(err, ShouldBeNil)
		artifactManifestDigest := godigest.FromBytes(artifactManifestBlob)

		err = UploadImage(artifactImg, baseURL, repo, artifactManifestDigest.String())
		So(err, ShouldBeNil)

		gqlQuery := `
			{
				Referrers(
					repo: "%s", digest: "%s", type: ""){
					ArtifactType,
					Digest,
					MediaType,
					Size,
					Annotations{
						Key
						Value
					}
		   		}
			}`

		strQuery := fmt.Sprintf(gqlQuery, repo, manifestDigest.String())

		targetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err := resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		referrersResp := &zcommon.ReferrersResp{}

		err = json.Unmarshal(resp.Body(), referrersResp)
		So(err, ShouldBeNil)
		So(referrersResp.Errors, ShouldBeNil)
		So(referrersResp.Referrers[0].ArtifactType, ShouldEqual, artifactType)
		So(referrersResp.Referrers[0].MediaType, ShouldEqual, ispec.MediaTypeImageManifest)

		So(referrersResp.Referrers[0].Annotations[0].Key, ShouldEqual, "com.artifact.format")
		So(referrersResp.Referrers[0].Annotations[0].Value, ShouldEqual, "test")

		So(referrersResp.Referrers[0].Digest, ShouldEqual, artifactManifestDigest.String())
	})

	Convey("referrers for image index", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = false

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
			Lint: &extconf.LintConfig{
				BaseConfig: extconf.BaseConfig{
					Enable: &defaultVal,
				},
			},
		}

		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, graphqlQueryPrefix)

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)

		defer ctlrManager.StopServer()

		// =======================

		multiarch := CreateRandomMultiarch()

		repo := "artifact-ref"

		err := UploadMultiarchImage(multiarch, baseURL, repo, "multiarch")
		So(err, ShouldBeNil)

		indexBlob, err := json.Marshal(multiarch.Index)
		So(err, ShouldBeNil)
		indexDigest := godigest.FromBytes(indexBlob)
		indexSize := int64(len(indexBlob))

		subjectDescriptor := &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Size:      indexSize,
			Digest:    indexDigest,
		}

		artifactContentBlob := []byte("test artifact")
		artifactContentBlobSize := int64(len(artifactContentBlob))
		artifactContentType := "application/octet-stream"
		artifactContentBlobDigest := godigest.FromBytes(artifactContentBlob)
		artifactType := "com.artifact.test/type2"

		configBlob, err := json.Marshal(ispec.Image{})
		So(err, ShouldBeNil)

		artifactManifest := ispec.Manifest{
			Layers: []ispec.Descriptor{
				{
					MediaType: artifactContentType,
					Digest:    artifactContentBlobDigest,
					Size:      artifactContentBlobSize,
				},
			},
			Subject: subjectDescriptor,
			Config: ispec.Descriptor{
				MediaType: artifactType,
				Digest:    godigest.FromBytes(configBlob),
			},
			MediaType: ispec.MediaTypeImageManifest,
			Annotations: map[string]string{
				"com.artifact.format": "test",
			},
		}

		artifactManifest.SchemaVersion = 2

		artifactManifestBlob, err := json.Marshal(artifactManifest)
		So(err, ShouldBeNil)
		artifactManifestDigest := godigest.FromBytes(artifactManifestBlob)

		err = UploadImage(
			Image{
				Manifest: artifactManifest,
				Config:   ispec.Image{},
				Layers:   [][]byte{artifactContentBlob},
			}, baseURL, repo, artifactManifestDigest.String())
		So(err, ShouldBeNil)

		gqlQuery := `
			{
				Referrers( repo: "%s", digest: "%s", type: "" ){
					ArtifactType,
					Digest,
					MediaType,
					Size,
					Annotations{
						Key
						Value
					}
		   		}
			}`

		strQuery := fmt.Sprintf(gqlQuery, repo, indexDigest.String())

		targetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err := resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		referrersResp := &zcommon.ReferrersResp{}

		err = json.Unmarshal(resp.Body(), referrersResp)
		So(err, ShouldBeNil)
		So(referrersResp.Errors, ShouldBeNil)
		So(len(referrersResp.Referrers), ShouldEqual, 1)
		So(referrersResp.Referrers[0].ArtifactType, ShouldEqual, artifactType)
		So(referrersResp.Referrers[0].MediaType, ShouldEqual, ispec.MediaTypeImageManifest)

		So(referrersResp.Referrers[0].Annotations[0].Key, ShouldEqual, "com.artifact.format")
		So(referrersResp.Referrers[0].Annotations[0].Value, ShouldEqual, "test")

		So(referrersResp.Referrers[0].Digest, ShouldEqual, artifactManifestDigest.String())
	})

	Convey("Get referrers with index as referrer", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = false

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
			Lint: &extconf.LintConfig{
				BaseConfig: extconf.BaseConfig{
					Enable: &defaultVal,
				},
			},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// Upload the index referrer
		targetImg := CreateRandomImage()
		targetDigest := targetImg.Digest()

		err := UploadImage(targetImg, baseURL, "repo", targetImg.DigestStr())
		So(err, ShouldBeNil)

		artifactType := "com.artifact.art/type"
		indexReferrer := CreateMultiarchWith().RandomImages(2).
			ArtifactType(artifactType).
			Subject(targetImg.DescriptorRef()).
			Build()
		indexReferrerDigest := indexReferrer.Digest()

		err = UploadMultiarchImage(indexReferrer, baseURL, "repo", "ref")
		So(err, ShouldBeNil)

		// Call Referrers GQL

		referrersQuery := `
			{
				Referrers( repo: "%s", digest: "%s"){
					ArtifactType,
					Digest,
					MediaType,
					Size,
					Annotations{
						Key
						Value
					}
		   		}
			}`

		referrersQuery = fmt.Sprintf(referrersQuery, "repo", targetDigest.String())

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(referrersQuery))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)
		So(err, ShouldBeNil)

		referrersResp := &zcommon.ReferrersResp{}

		err = json.Unmarshal(resp.Body(), referrersResp)
		So(err, ShouldBeNil)
		So(len(referrersResp.Referrers), ShouldEqual, 1)
		So(referrersResp.Referrers[0].ArtifactType, ShouldResemble, artifactType)
		So(referrersResp.Referrers[0].Digest, ShouldResemble, indexReferrerDigest.String())
		So(referrersResp.Referrers[0].MediaType, ShouldResemble, ispec.MediaTypeImageIndex)

		// Make REST call

		resp, err = resty.R().Get(baseURL + "/v2/repo/referrers/" + targetDigest.String())
		So(err, ShouldBeNil)

		var index ispec.Index

		err = json.Unmarshal(resp.Body(), &index)
		So(err, ShouldBeNil)
		So(len(index.Manifests), ShouldEqual, 1)
		So(index.Manifests[0].ArtifactType, ShouldEqual, artifactType)
		So(index.Manifests[0].Digest.String(), ShouldResemble, indexReferrerDigest.String())
		So(index.Manifests[0].MediaType, ShouldResemble, ispec.MediaTypeImageIndex)
	})
}

func TestExpandedRepoInfo(t *testing.T) {
	Convey("Filter out manifests with no tag", t, func() {
		tagToBeRemoved := "3.0"
		repo1 := "test1"
		tempDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		imageStore := local.NewImageStore(tempDir, false, false,
			log.NewTestLogger(), monitoring.NewMetricsServer(false, log.NewTestLogger()), nil, nil, nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		// init storage layout with 3 images
		for i := 1; i <= 3; i++ {
			image := CreateImageWith().RandomLayers(1, 100).DefaultConfig().Build()

			err := WriteImageToFileSystem(image, repo1, fmt.Sprintf("%d.0", i), storeController)
			So(err, ShouldBeNil)
		}

		// remote a tag from index.json
		indexPath := path.Join(tempDir, repo1, "index.json")
		indexFile, err := os.Open(indexPath)
		So(err, ShouldBeNil)
		buf, err := io.ReadAll(indexFile)
		So(err, ShouldBeNil)

		var index ispec.Index
		if err = json.Unmarshal(buf, &index); err == nil {
			for _, manifest := range index.Manifests {
				if val, ok := manifest.Annotations[ispec.AnnotationRefName]; ok && val == tagToBeRemoved {
					delete(manifest.Annotations, ispec.AnnotationRefName)

					break
				}
			}
		}
		buf, err = json.Marshal(index)
		So(err, ShouldBeNil)

		err = os.WriteFile(indexPath, buf, 0o600)
		So(err, ShouldBeNil)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		query := `{
				ExpandedRepoInfo(repo:"test1"){
					Summary {
						Name LastUpdated Size
						Platforms {Os Arch}
						Vendors
					}
					Images {
						Tag
						Manifests {
							Digest
							Layers {Size Digest}
						}
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		responseStruct := &zcommon.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.Summary, ShouldNotBeEmpty)
		So(responseStruct.Summary.Name, ShouldEqual, "test1")
		So(len(responseStruct.ImageSummaries), ShouldEqual, 2)
	})

	Convey("Test expanded repo info", t, func() {
		subpath := "/a"
		rootDir := t.TempDir()
		subRootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.GC = false
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)

		defer ctlrManager.StopServer()

		annotations := make(map[string]string)
		annotations["org.opencontainers.image.vendor"] = "zot"

		uploadedImage := CreateImageWith().RandomLayers(1, 100).DefaultConfig().
			Annotations(annotations).Build()

		err := UploadImage(uploadedImage, baseURL, "zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "zot-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-test", "0.0.1")
		So(err, ShouldBeNil)

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		testStorage := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		query := `{
			ExpandedRepoInfo(repo:"zot-cve-test"){
				Summary {
					Name LastUpdated Size
					}
				}
			}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.Summary, ShouldNotBeEmpty)
		So(responseStruct.Summary.Name, ShouldEqual, "zot-cve-test")

		query = `{
			ExpandedRepoInfo(repo:"zot-cve-test"){
				Images {
					Tag
					Manifests {
						Digest
						Layers {Size Digest}
					}
					IsSigned
				}
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err := testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		found := false

		for _, m := range responseStruct.ImageSummaries {
			if m.Manifests[0].Digest == testManifestDigest.String() {
				found = true

				So(m.IsSigned, ShouldEqual, false)
			}
		}

		So(found, ShouldEqual, true)

		err = signature.SignImageUsingCosign("zot-cve-test:0.0.1", port, false)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err = testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		found = false

		for _, m := range responseStruct.ImageSummaries {
			if m.Manifests[0].Digest == testManifestDigest.String() {
				found = true
				So(m.IsSigned, ShouldEqual, true)
			}
		}

		So(found, ShouldEqual, true)

		query = `{
			ExpandedRepoInfo(repo:""){
				Images {
					Tag
					}
				}
			}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		query = `{
			ExpandedRepoInfo(repo:"zot-test"){
				Images {
					RepoName
					Tag IsSigned
					Manifests{
						Digest
						Layers {Size Digest}
					}
				}
			}
		}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)

		found = false

		for _, m := range responseStruct.ImageSummaries {
			if m.Manifests[0].Digest == testManifestDigest.String() {
				found = true

				So(m.IsSigned, ShouldEqual, false)
			}
		}

		So(found, ShouldEqual, true)

		err = signature.SignImageUsingCosign("zot-test@"+testManifestDigest.String(), port, false)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "/query?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)

		found = false

		for _, m := range responseStruct.ImageSummaries {
			if m.Manifests[0].Digest == testManifestDigest.String() {
				found = true
				So(m.IsSigned, ShouldEqual, true)
			}
		}

		So(found, ShouldEqual, true)

		manifestDigest := uploadedImage.ManifestDescriptor.Digest

		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", manifestDigest.Encoded()))
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
	})

	Convey("Test expanded repo info with tagged referrers", t, func() {
		const testTag = "test"
		rootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)

		defer ctlrManager.StopServer()

		image := CreateImageWith().RandomLayers(1, 20).DefaultConfig().Build()

		err := UploadImage(image, baseURL, "repo", testTag)
		So(err, ShouldBeNil)

		referrer := CreateImageWith().RandomLayers(1, 100).DefaultConfig().Subject(&ispec.Descriptor{
			Digest:    image.ManifestDescriptor.Digest,
			MediaType: ispec.MediaTypeImageManifest,
		}).Build()

		tag := "test-ref-tag"
		err = UploadImage(referrer, baseURL, "repo", tag)
		So(err, ShouldBeNil)

		// ------- Make the call to GQL and see that it doesn't crash
		responseStruct := &zcommon.ExpandedRepoInfoResp{}
		query := `
		{
			ExpandedRepoInfo(repo:"repo"){
				Images {
					RepoName
					Tag
					Manifests {
						Digest
						Layers {Size Digest}
					}
				}
			}
		}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldEqual, 2)

		repoInfo := responseStruct.RepoInfo

		foundTagTest := false
		foundTagRefTag := false

		for _, imgSum := range repoInfo.ImageSummaries {
			switch imgSum.Tag {
			case testTag:
				foundTagTest = true
			case "test-ref-tag":
				foundTagRefTag = true
			}
		}

		So(foundTagTest || foundTagRefTag, ShouldEqual, true)
	})

	Convey("Test image tags order", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		// create test images
		repoName := "test-repo" //nolint:goconst
		layers := [][]byte{
			{10, 11, 10, 11},
		}

		err = uploadNewRepoTag("1.0", repoName, baseURL, layers)
		So(err, ShouldBeNil)

		err = uploadNewRepoTag("2.0", repoName, baseURL, layers)
		So(err, ShouldBeNil)

		err = uploadNewRepoTag("3.0", repoName, baseURL, layers)
		So(err, ShouldBeNil)

		responseStruct := &zcommon.ExpandedRepoInfoResp{}
		query := `
		{
			ExpandedRepoInfo(repo:"test-repo"){
				Images {
					RepoName
					Tag
					Manifests {
						Digest
						Layers {Size Digest}
					}
				}
			}
		}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		So(responseStruct.ImageSummaries[0].Tag, ShouldEqual, "3.0")
		So(responseStruct.ImageSummaries[1].Tag, ShouldEqual, "2.0")
		So(responseStruct.ImageSummaries[2].Tag, ShouldEqual, "1.0")
	})

	Convey("With Multiarch Images", t, func() {
		conf := config.New()
		conf.HTTP.Port = GetFreePort()
		baseURL := GetBaseURL(conf.HTTP.Port)
		conf.Storage.RootDirectory = t.TempDir()

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil
		ctlr := api.NewController(conf)

		imageStore := local.NewImageStore(conf.Storage.RootDirectory, false, false,
			log.NewTestLogger(), monitoring.NewMetricsServer(false, log.NewTestLogger()), nil, nil, nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		// ------- Create test images
		indexSubImage11 := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os11",
				Architecture: "arch11",
			},
		}).Build()

		indexSubImage12 := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os12",
				Architecture: "arch12",
			},
		}).Build()

		multiImage1 := CreateMultiarchWith().Images([]Image{
			indexSubImage11, indexSubImage12,
		}).Build()

		indexSubImage21 := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os21",
				Architecture: "arch21",
			},
		}).Build()

		indexSubImage22 := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os22",
				Architecture: "arch22",
			},
		}).Build()

		indexSubImage23 := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os23",
				Architecture: "arch23",
			},
		}).Build()

		multiImage2 := CreateMultiarchWith().Images([]Image{
			indexSubImage21, indexSubImage22, indexSubImage23,
		}).Build()

		// ------- Write test Images
		err := WriteMultiArchImageToFileSystem(multiImage1, "repo", "1.0.0", storeController)
		So(err, ShouldBeNil)

		err = WriteMultiArchImageToFileSystem(multiImage2, "repo", "2.0.0", storeController)
		So(err, ShouldBeNil)
		// ------- Start Server /tmp/TestExpandedRepoInfo4021254039/005

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(conf.HTTP.Port)
		defer ctlrManager.StopServer()

		// ------- Test ExpandedRepoInfo
		responseStruct := &zcommon.ExpandedRepoInfoResp{}

		query := `
		{
			ExpandedRepoInfo(repo:"repo"){
				Images {
					RepoName
					Tag
					Manifests {
						Digest
						Layers {Size Digest}
					}
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Summary.Platforms), ShouldNotEqual, 5)

		found := false

		for _, is := range responseStruct.ImageSummaries {
			if is.Tag == "1.0.0" {
				found = true

				So(len(is.Manifests), ShouldEqual, 2)
			}
		}

		So(found, ShouldBeTrue)

		found = false

		for _, is := range responseStruct.ImageSummaries {
			if is.Tag == "2.0.0" {
				found = true

				So(len(is.Manifests), ShouldEqual, 3)
			}
		}

		So(found, ShouldBeTrue)
	})

	Convey("Test expanded repo info for docker media type", t, func() {
		subpath := "/a"
		rootDir := t.TempDir()
		subRootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.GC = false
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)

		defer ctlrManager.StopServer()

		annotations := make(map[string]string)
		annotations["org.opencontainers.image.vendor"] = "zot"

		configBlob, err := json.Marshal(GetDefaultConfig())
		So(err, ShouldBeNil)

		uploadedImage := CreateImageWith().RandomLayers(1, 100).
			CustomConfigBlob(configBlob, "application/vnd.docker.container.image.v1+json").
			Annotations(annotations).Build()

		err = UploadImage(uploadedImage, baseURL, "zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "zot-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(uploadedImage, baseURL, "a/zot-test", "0.0.1")
		So(err, ShouldBeNil)

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		testStorage := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		query := `{
			ExpandedRepoInfo(repo:"zot-cve-test"){
				Summary {
					Name LastUpdated Size
					}
				}
			}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.Summary, ShouldNotBeEmpty)
		So(responseStruct.Summary.Name, ShouldEqual, "zot-cve-test")

		query = `{
			ExpandedRepoInfo(repo:"zot-cve-test"){
				Images {
					Tag
					Manifests {
						Digest
						Layers {Size Digest}
						Platform {Os Arch}
					}
					IsSigned
				}
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err := testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		found := false

		for _, imageSummary := range responseStruct.ImageSummaries {
			if imageSummary.Manifests[0].Digest == testManifestDigest.String() {
				found = true

				So(imageSummary.IsSigned, ShouldEqual, false)
				So(imageSummary.Manifests[0].Platform.Os, ShouldEqual, "linux")
				So(imageSummary.Manifests[0].Platform.Arch, ShouldEqual, "amd64")
			}
		}

		So(found, ShouldEqual, true)

		err = signature.SignImageUsingCosign("zot-cve-test:0.0.1", port, false)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err = testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		found = false

		for _, imageSummary := range responseStruct.ImageSummaries {
			if imageSummary.Manifests[0].Digest == testManifestDigest.String() {
				found = true

				So(imageSummary.IsSigned, ShouldEqual, true)
				So(imageSummary.Manifests[0].Platform.Os, ShouldEqual, "linux")
				So(imageSummary.Manifests[0].Platform.Arch, ShouldEqual, "amd64")
			}
		}

		So(found, ShouldEqual, true)

		query = `{
			ExpandedRepoInfo(repo:""){
				Images {
					Tag
					}
				}
			}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		query = `{
			ExpandedRepoInfo(repo:"zot-test"){
				Images {
					RepoName
					Tag IsSigned
					Manifests{
						Digest
						Layers {Size Digest}
						Platform {Os Arch}
					}
				}
			}
		}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)

		found = false

		for _, imageSummary := range responseStruct.ImageSummaries {
			if imageSummary.Manifests[0].Digest == testManifestDigest.String() {
				found = true

				So(imageSummary.IsSigned, ShouldEqual, false)
				So(imageSummary.Manifests[0].Platform.Os, ShouldEqual, "linux")
				So(imageSummary.Manifests[0].Platform.Arch, ShouldEqual, "amd64")
			}
		}

		So(found, ShouldEqual, true)

		err = signature.SignImageUsingCosign("zot-test@"+testManifestDigest.String(), port, false)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "/query?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ImageSummaries[0].Manifests[0].Layers), ShouldNotEqual, 0)

		_, testManifestDigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)

		found = false

		for _, imageSummary := range responseStruct.ImageSummaries {
			if imageSummary.Manifests[0].Digest == testManifestDigest.String() {
				found = true

				So(imageSummary.IsSigned, ShouldEqual, true)
				So(imageSummary.Manifests[0].Platform.Os, ShouldEqual, "linux")
				So(imageSummary.Manifests[0].Platform.Arch, ShouldEqual, "amd64")
			}
		}

		So(found, ShouldEqual, true)

		manifestDigest := uploadedImage.ManifestDescriptor.Digest

		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", manifestDigest.Encoded()))
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
	})
}

func TestDerivedImageList(t *testing.T) {
	rootDir := t.TempDir()

	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = rootDir
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}

	conf.Extensions.Search.CVE = nil

	ctlr := api.NewController(conf)
	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)
	defer ctlrManager.StopServer()

	Convey("Test dependency list for image working", t, func() {
		// create test images
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
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
		}

		manifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		}

		repoName := "test-repo" //nolint:goconst

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with the same layers
		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		}

		repoName = "same-layers" //nolint:goconst

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with missing layer
		layers = [][]byte{
			{10, 11, 10, 11},
			{10, 10, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
			},
		}

		repoName = "missing-layer"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with more layers than the original
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
			{10, 10, 10, 10},
			{11, 11, 10, 10},
			{11, 10, 10, 10},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[4]),
					Size:      int64(len(layers[4])),
				},
			},
		}

		repoName = "more-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[4]),
					Size:      int64(len(layers[4])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[5]),
					Size:      int64(len(layers[5])),
				},
			},
		}

		repoName = "all-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		Convey("non paginated query", func() {
			query := `
				{
					DerivedImageList(image:"test-repo:latest"){
						Results{
							RepoName
							Tag
							Manifests {
								Digest
								ConfigDigest
								LastUpdated
								Size
							}
							Size
						}
					}
				}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeFalse) //nolint:goconst
			So(strings.Contains(string(resp.Body()), "missing-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeTrue)
			So(strings.Contains(string(resp.Body()), "all-layers"), ShouldBeTrue)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("paginated query", func() {
			query := `
				{
					DerivedImageList(image:"test-repo:latest", requestedPage:{limit: 1, offset: 0, sortBy:ALPHABETIC_ASC}){
						Results{
							RepoName
							Tag
							Manifests {
								Digest
								ConfigDigest
								LastUpdated
								Size
							}
							Size
						}
					}
				}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeFalse) //nolint:goconst
			So(strings.Contains(string(resp.Body()), "missing-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "all-layers"), ShouldBeTrue)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})
	})

	Convey("Inexistent repository", t, func() {
		query := `
			{
				DerivedImageList(image:"inexistent-image:latest"){
					Results{
						RepoName
						Tag
						Manifests {
							Digest
							ConfigDigest
							LastUpdated
							Size
						}
						Size
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(string(resp.Body()), ShouldContainSubstring, "repository not found")
		So(err, ShouldBeNil)
	})

	Convey("Invalid query, no reference provided", t, func() {
		query := `
			{
				DerivedImageList(image:"inexistent-image"){
					Results{
						RepoName
						Tag
						Manifests {
							Digest
							ConfigDigest
							LastUpdated
							Size
						}
						Size
					}
				}
			}`

		responseStruct := &zcommon.DerivedImageListResponse{}
		contains := false
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		for _, err := range responseStruct.Errors {
			result := strings.Contains(err.Message, "no reference provided")
			if result {
				contains = result
			}
		}

		So(contains, ShouldBeTrue)
	})
}

//nolint:dupl
func TestDerivedImageListNoRepos(t *testing.T) {
	Convey("No repositories found", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		query := `
			{
				DerivedImageList(image:"test-image:latest"){
					Results{
						RepoName
						Tag
						Manifests {
							Digest
							ConfigDigest
							LastUpdated
							Size
						}
						Size
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		So(string(resp.Body()), ShouldContainSubstring, "repository not found")
		So(err, ShouldBeNil)
	})
}

func TestGetImageManifest(t *testing.T) {
	Convey("Test nonexistent image", t, func() {
		mockImageStore := mocks.MockedImageStore{}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
		}
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewTestLogger())

		_, _, err := olu.GetImageManifest("nonexistent-repo", "latest")
		So(err, ShouldNotBeNil)
	})

	Convey("Test nonexistent image", t, func() {
		mockImageStore := mocks.MockedImageStore{
			GetImageManifestFn: func(repo string, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "", "", ErrTestError
			},
		}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
		}
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewTestLogger())

		_, _, err := olu.GetImageManifest("test-repo", "latest") //nolint:goconst
		So(err, ShouldNotBeNil)
	})
}

func TestBaseImageList(t *testing.T) {
	rootDir := t.TempDir()

	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = rootDir
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}

	conf.Extensions.Search.CVE = nil

	ctlr := api.NewController(conf)
	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)
	defer ctlrManager.StopServer()

	Convey("Test base image list for image working", t, func() {
		// create test images
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
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
			{10, 10, 10, 10},
		}

		manifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
			},
		}

		repoName := "test-repo" //nolint:goconst

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with the same layers
		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
			},
		}

		repoName = "same-layers" //nolint:goconst

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with less layers than the given image, but which are in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
			},
		}

		repoName = "less-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with one layer, which is also present in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, "one-layer", "latest",
		)
		So(err, ShouldBeNil)

		// create image with one layer, which is also present in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, "one-layer", "latest",
		)
		So(err, ShouldBeNil)

		// create image with one layer, which is also present in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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

		repoName = "one-layer"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with one layer, which is also present in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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

		repoName = "one-layer"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with less layers than the given image, but one layer isn't in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 10, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
			},
		}

		repoName = "less-layers-false"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with more layers than the original
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 10},
			{10, 10, 10, 11},
			{11, 11, 10, 10},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[4]),
					Size:      int64(len(layers[4])),
				},
			},
		}

		repoName = "more-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		// create image with no shared layers with the given image
		layers = [][]byte{
			{12, 12, 12, 12},
			{12, 10, 10, 12},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
			},
		}

		repoName = "diff-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, repoName, "latest",
		)
		So(err, ShouldBeNil)

		Convey("non paginated query", func() {
			query := `
				{
					BaseImageList(image:"test-repo:latest"){
						Results{
							RepoName
							Tag IsSigned
							Manifests {
								Digest
								ConfigDigest
								LastUpdated
								Size
							}
							Size
						}
					}
				}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(strings.Contains(string(resp.Body()), "less-layers"), ShouldBeTrue)
			So(strings.Contains(string(resp.Body()), "one-layer"), ShouldBeTrue)
			So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeFalse) //nolint:goconst
			So(strings.Contains(string(resp.Body()), "less-layers-false"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "diff-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "test-repo"), ShouldBeFalse) //nolint:goconst // should not list given image
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("paginated query", func() {
			query := `
				{
					BaseImageList(image:"test-repo:latest", requestedPage:{limit: 1, offset: 0, sortBy:RELEVANCE}){
						Results{
							RepoName
							Tag
							Manifests {
								Digest
								ConfigDigest
								LastUpdated
								Size
							}
							Size
						}
					}
				}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(strings.Contains(string(resp.Body()), "less-layers"), ShouldBeTrue)
			So(strings.Contains(string(resp.Body()), "one-layer"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeFalse) //nolint:goconst
			So(strings.Contains(string(resp.Body()), "less-layers-false"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "diff-layers"), ShouldBeFalse)
			So(strings.Contains(string(resp.Body()), "test-repo"), ShouldBeFalse) //nolint:goconst // should not list given image
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})
	})

	Convey("Nonexistent repository", t, func() {
		query := `
			{
				BaseImageList(image:"nonexistent-image:latest"){
					Results{
						RepoName
						Tag
						Manifests {
							Digest
							ConfigDigest
							LastUpdated
							Size
						}
						Size
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(string(resp.Body()), ShouldContainSubstring, "repository not found")
		So(err, ShouldBeNil)
	})

	Convey("Invalid query, no reference provided", t, func() {
		query := `
		{
			BaseImageList(image:"nonexistent-image"){
				Results{
					RepoName
					Tag
					Manifests {
						Digest
						ConfigDigest
						LastUpdated
						Size
					}
					Size
				}
			}
		}`

		responseStruct := &zcommon.BaseImageListResponse{}
		contains := false
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		for _, err := range responseStruct.Errors {
			result := strings.Contains(err.Message, "no reference provided")
			if result {
				contains = result
			}
		}

		So(contains, ShouldBeTrue)
	})
}

//nolint:dupl
func TestBaseImageListNoRepos(t *testing.T) {
	Convey("No repositories found", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		query := `
			{
				BaseImageList(image:"test-image"){
					Results{
						RepoName
						Tag
						Manifests {
							Digest
							ConfigDigest
							LastUpdated
							Size
						}
						IsSigned
						Size
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(strings.Contains(string(resp.Body()), "no reference provided"), ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestGetRepositories(t *testing.T) {
	Convey("Test getting the repositories list", t, func() {
		mockImageStore := mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{}, ErrTestError
			},
		}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
			SubStore:     map[string]storageTypes.ImageStore{"test": mockImageStore},
		}
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewTestLogger())

		repoList, err := olu.GetRepositories()
		So(repoList, ShouldBeEmpty)
		So(err, ShouldNotBeNil)

		storeController = storage.StoreController{
			DefaultStore: mocks.MockedImageStore{},
			SubStore:     map[string]storageTypes.ImageStore{"test": mockImageStore},
		}
		olu = ociutils.NewBaseOciLayoutUtils(storeController, log.NewTestLogger())

		repoList, err = olu.GetRepositories()
		So(repoList, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
	})
}

func TestGlobalSearchImageAuthor(t *testing.T) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	tempDir := t.TempDir()
	conf.Storage.RootDirectory = tempDir

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}

	conf.Extensions.Search.CVE = nil

	ctlr := api.NewController(conf)
	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)
	defer ctlrManager.StopServer()

	Convey("Test global search with author in manifest's annotations", t, func() {
		annotations := make(map[string]string)
		annotations["org.opencontainers.image.authors"] = "author name"

		image := CreateImageWith().RandomLayers(1, 10000).DefaultConfig().
			Annotations(annotations).Build()

		err := UploadImage(image, baseURL, "repowithauthor", "latest")
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"repowithauthor:latest"){
					Images {
						RepoName Tag LastUpdated Size IsSigned
						Authors
					}
				}
			}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStructImages := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStructImages)
		So(err, ShouldBeNil)

		So(responseStructImages.Images[0].Authors, ShouldEqual, "author name")

		query = `
		{
			GlobalSearch(query:"repowithauthor"){
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned
						Authors
					}
				}
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStructRepos := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStructRepos)
		So(err, ShouldBeNil)

		So(responseStructRepos.Repos[0].NewestImage.Authors, ShouldEqual, "author name")
	})

	Convey("Test global search with author in manifest's config", t, func() {
		image := CreateImageWith().RandomLayers(1, 10000).DefaultConfig().Build()

		err := UploadImage(image, baseURL, "repowithauthorconfig", "latest")
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"repowithauthorconfig:latest"){
					Images {
						RepoName Tag LastUpdated Size IsSigned
						Authors
					}
				}
			}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStructImages := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStructImages)
		So(err, ShouldBeNil)

		So(responseStructImages.Images[0].Authors, ShouldEqual, "ZotUser")

		query = `
		{
			GlobalSearch(query:"repowithauthorconfig"){
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned
						Authors
					}
				}
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStructRepos := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStructRepos)
		So(err, ShouldBeNil)

		So(responseStructRepos.Repos[0].NewestImage.Authors, ShouldEqual, "ZotUser")
	})
}

func TestGlobalSearch(t *testing.T) { //nolint: gocyclo
	Convey("Test searching for repos with vulnerabitity scanning disabled", t, func() {
		subpath := "/a"

		dir := t.TempDir()
		subRootDir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test images to repo 1 image 1
		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		createdTimeL2 := time.Date(2010, 2, 1, 12, 0, 0, 0, time.UTC)
		config1 := ispec.Image{
			Created: &createdTimeL2,
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author: "ZotUser",
			History: []ispec.History{
				{
					Created:    &createdTime,
					CreatedBy:  "go test data",
					Author:     "ZotUser",
					Comment:    "Test history comment",
					EmptyLayer: true,
				},
				{
					Created:    &createdTimeL2,
					CreatedBy:  "go test data 2",
					Author:     "ZotUser",
					Comment:    "Test history comment2",
					EmptyLayer: false,
				},
			},
		}

		image1 := CreateImageWith().LayerBlobs([][]byte{make([]byte, 100)}).
			ImageConfig(config1).Build()

		layersSize1 := 0
		for _, l := range image1.Layers {
			layersSize1 += len(l)
		}

		err := UploadImage(image1, baseURL, "repo1", "1.0.1")
		So(err, ShouldBeNil)

		// push test images to repo 1 image 2
		createdTime2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		createdTimeL2 = time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC)

		config2 := ispec.Image{
			Created: &createdTimeL2,
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author: "ZotUser",
			History: []ispec.History{
				{
					Created:    &createdTime2,
					CreatedBy:  "go test data",
					Author:     "ZotUser",
					Comment:    "Test history comment",
					EmptyLayer: true,
				},
				{
					Created:    &createdTimeL2,
					CreatedBy:  "go test data 2",
					Author:     "ZotUser",
					Comment:    "Test history comment2",
					EmptyLayer: false,
				},
			},
		}

		image2 := CreateImageWith().LayerBlobs([][]byte{make([]byte, 200)}).
			ImageConfig(config2).Build()

		layersSize2 := 0
		for _, l := range image2.Layers {
			layersSize2 += len(l)
		}

		err = UploadImage(image2, baseURL, "repo1", "1.0.2")
		So(err, ShouldBeNil)

		// push test images to repo 2 image 1
		createdTime3 := time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC)
		config3 := ispec.Image{
			Created: &createdTime3,
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author:  "ZotUser",
			History: []ispec.History{{Created: &createdTime3}},
		}

		image3 := CreateImageWith().LayerBlobs([][]byte{make([]byte, 300)}).
			ImageConfig(config3).Build()

		layersSize3 := 0
		for _, l := range image3.Layers {
			layersSize3 += len(l)
		}

		err = UploadImage(image3, baseURL, "repo2", "1.0.0")
		So(err, ShouldBeNil)

		olu := ociutils.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewTestLogger())

		// Initialize the objects containing the expected data
		repos, err := olu.GetRepositories()
		So(err, ShouldBeNil)

		allExpectedRepoInfoMap := make(map[string]zcommon.RepoInfo)
		allExpectedImageSummaryMap := make(map[string]zcommon.ImageSummary)
		expectedLastUpdatedMap := make(map[string]time.Time)

		for _, repo := range repos {
			repoInfo, err := olu.GetExpandedRepoInfo(repo)
			So(err, ShouldBeNil)
			allExpectedRepoInfoMap[repo] = repoInfo

			for _, image := range repoInfo.ImageSummaries {
				imageName := fmt.Sprintf("%s:%s", repo, image.Tag)
				allExpectedImageSummaryMap[imageName] = image
			}

			// Compute expected LastUpdated as the maximum of:
			// 1. NewestImage.LastUpdated (from the last updated image)
			// 2. All TaggedTimestamp values from all tags in the repository
			repoMeta, err := ctlr.MetaDB.GetRepoMeta(context.Background(), repo)
			So(err, ShouldBeNil)

			expectedLastUpdated := repoInfo.Summary.NewestImage.LastUpdated

			// Check all TaggedTimestamp values from all tags
			for _, descriptor := range repoMeta.Tags {
				if !descriptor.TaggedTimestamp.IsZero() && descriptor.TaggedTimestamp.After(expectedLastUpdated) {
					expectedLastUpdated = descriptor.TaggedTimestamp
				}
			}

			expectedLastUpdatedMap[repo] = expectedLastUpdated
		}

		query := `
			{
				GlobalSearch(query:"repo"){
					Images {
						RepoName Tag LastUpdated Size IsSigned
						Manifests {
							LastUpdated
							Size
							Platform { Os Arch }
							History {
								Layer { Size Digest }
								HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
							}
							Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
						}
						Vendor
						Vulnerabilities { Count MaxSeverity }
					}
					Repos {
						Name LastUpdated Size
						Platforms { Os Arch }
						Vendors
						NewestImage {
							RepoName Tag LastUpdated Size
							Digest
							Manifests{
								Digest ConfigDigest
								LastUpdated Size
								Platform { Os Arch }
								History {
									Layer { Size Digest }
									HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
								}
							}
							Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
						}
					}
					Layers { Digest Size }
				}
			}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		// Make sure the repo/image counts match before comparing actual content
		So(responseStruct.Images, ShouldNotBeNil)
		t.Logf("returned images: %v", responseStruct.Images)
		So(responseStruct.Images, ShouldBeEmpty)
		t.Logf("returned repos: %v", responseStruct.Repos)
		So(len(responseStruct.Repos), ShouldEqual, 2)
		t.Logf("returned layers: %v", responseStruct.GlobalSearch.Layers)
		So(responseStruct.Layers, ShouldBeEmpty)

		newestImageMap := make(map[string]zcommon.ImageSummary)
		actualRepoMap := make(map[string]zcommon.RepoSummary)

		for _, repo := range responseStruct.Repos {
			newestImageMap[repo.Name] = repo.NewestImage
			actualRepoMap[repo.Name] = repo
		}

		// Tag 1.0.2 has a history entry which is older compare to 1.0.1
		So(newestImageMap["repo1"].Tag, ShouldEqual, "1.0.1")
		So(newestImageMap["repo1"].LastUpdated, ShouldEqual, time.Date(2010, 2, 1, 12, 0, 0, 0, time.UTC))

		So(newestImageMap["repo2"].Tag, ShouldEqual, "1.0.0")
		So(newestImageMap["repo2"].LastUpdated, ShouldEqual, time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC))

		for repoName, repoSummary := range actualRepoMap {
			// Check if data in NewestImage is consistent with the data in RepoSummary
			So(repoName, ShouldEqual, repoSummary.NewestImage.RepoName)
			So(repoSummary.Name, ShouldEqual, repoSummary.NewestImage.RepoName)

			// Verify the actual LastUpdated matches the computed expected value
			expectedLastUpdated, exists := expectedLastUpdatedMap[repoName]
			So(exists, ShouldBeTrue)
			So(repoSummary.LastUpdated, ShouldEqual, expectedLastUpdated)

			// The data in the RepoSummary returned from the request matches the data returned from the disk
			repoInfo := allExpectedRepoInfoMap[repoName]
			// Update the expected LastUpdated to account for TaggedTimestamp (which is not available from disk)
			repoInfo.Summary.LastUpdated = expectedLastUpdated

			t.Logf("Validate repo summary returned by global search with vulnerability scanning disabled")
			verifyRepoSummaryFields(t, &repoSummary, &repoInfo.Summary)

			// RepoInfo object does not provide vulnerability information so we need to check differently
			// No vulnerabilities should be detected since trivy is disabled
			t.Logf("Found vulnerability summary %v", repoSummary.NewestImage.Vulnerabilities)
			So(repoSummary.NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.UnknownCount, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.LowCount, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.MediumCount, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.HighCount, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.CriticalCount, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "")
		}

		query = `
		{
			GlobalSearch(query:"repo1:1.0.1"){
				Images {
					RepoName Tag LastUpdated Size
					Manifests {
						LastUpdated Size
						Platform { Os Arch }
						History {
							Layer { Size Digest }
							HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
						}
					}
					Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors
					NewestImage {
						RepoName Tag LastUpdated Size
						Manifests {
							LastUpdated Size
							Platform { Os Arch }
							History {
								Layer { Size Digest }
								HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
							}
						}
						Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
					}
				}
				Layers { Digest Size }
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Images, ShouldNotBeEmpty)
		So(responseStruct.Repos, ShouldBeEmpty)
		So(responseStruct.Layers, ShouldBeEmpty)

		So(len(responseStruct.Images), ShouldEqual, 1)
		actualImageSummary := responseStruct.Images[0]
		So(actualImageSummary.Tag, ShouldEqual, "1.0.1")

		expectedImageSummary, ok := allExpectedImageSummaryMap["repo1:1.0.1"]
		So(ok, ShouldEqual, true)

		t.Logf("Validate image summary returned by global search with vulnerability scanning disabled")
		verifyImageSummaryFields(t, &actualImageSummary, &expectedImageSummary)

		// RepoInfo object does not provide vulnerability information so we need to check differently
		// 0 vulnerabilities should be detected since trivy is disabled
		t.Logf("Found vulnerability summary %v", actualImageSummary.Vulnerabilities)
		So(actualImageSummary.Vulnerabilities.Count, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.UnknownCount, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.LowCount, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.MediumCount, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.HighCount, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.CriticalCount, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")
	})

	Convey("Test global search with real images and vulnerabitity scanning enabled", t, func() {
		subpath := "/a"

		dir := t.TempDir()
		subRootDir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true

		updateDuration, _ := time.ParseDuration("1h")
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
			Trivy:          trivyConfig,
		}
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		// we won't use the logging config feature as we want logs in both
		// stdout and a file
		logFile := MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		logPath := logFile.Name()

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log = log.NewLoggerWithWriter("debug", writers)

		if err := ctlr.Init(); err != nil {
			panic(err)
		}

		ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		// Wait for trivy db to download
		substring := "{\"Search\":{\"Enable\":true,\"CVE\":{\"UpdateInterval\":3600000000000," +
			"\"Trivy\":{\"DBRepository\":\"ghcr.io/project-zot/trivy-db\",\"JavaDBRepository\":\"\"}}}"
		found, err := readFileAndSearchString(logPath, substring, 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "updating cve-db", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "cve-db update completed, next update scheduled after interval",
			4*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		WaitTillServerReady(baseURL)

		// push test images to repo 1 image 1
		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		config1 := ispec.Image{
			Created: &createdTime,
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author:  "ZotUser",
			History: []ispec.History{{Created: &createdTime}},
		}

		image1 := CreateImageWith().LayerBlobs([][]byte{make([]byte, 100)}).
			ImageConfig(config1).Build()

		layersSize1 := 0
		for _, l := range image1.Layers {
			layersSize1 += len(l)
		}

		err = UploadImage(image1, baseURL, "repo1", "1.0.1")
		So(err, ShouldBeNil)

		// push test images to repo 1 image 2
		createdTime2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		config2 := ispec.Image{
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author:  "ZotUser",
			History: []ispec.History{{Created: &createdTime2}},
		}

		image2 := CreateImageWith().LayerBlobs([][]byte{make([]byte, 200)}).
			ImageConfig(config2).Build()

		layersSize2 := 0
		for _, l := range image2.Layers {
			layersSize2 += len(l)
		}

		err = UploadImage(image2, baseURL, "repo1", "1.0.2")
		So(err, ShouldBeNil)

		// push test images to repo 2 image 1
		createdTime3 := time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC)
		config3 := ispec.Image{
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author:  "ZotUser",
			History: []ispec.History{{Created: &createdTime3}},
		}

		image3 := CreateImageWith().LayerBlobs([][]byte{make([]byte, 300)}).
			ImageConfig(config3).Build()

		layersSize3 := 0
		for _, l := range image3.Layers {
			layersSize3 += len(l)
		}

		err = UploadImage(image3, baseURL, "repo2", "1.0.0")
		So(err, ShouldBeNil)

		olu := ociutils.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewTestLogger())

		// Initialize the objects containing the expected data
		repos, err := olu.GetRepositories()
		So(err, ShouldBeNil)

		allExpectedRepoInfoMap := make(map[string]zcommon.RepoInfo)
		allExpectedImageSummaryMap := make(map[string]zcommon.ImageSummary)
		expectedLastUpdatedMap := make(map[string]time.Time)

		for _, repo := range repos {
			repoInfo, err := olu.GetExpandedRepoInfo(repo)
			So(err, ShouldBeNil)
			allExpectedRepoInfoMap[repo] = repoInfo

			for _, image := range repoInfo.ImageSummaries {
				imageName := fmt.Sprintf("%s:%s", repo, image.Tag)
				allExpectedImageSummaryMap[imageName] = image
			}

			// Compute expected LastUpdated as the maximum of:
			// 1. NewestImage.LastUpdated (from the last updated image)
			// 2. All TaggedTimestamp values from all tags in the repository
			repoMeta, err := ctlr.MetaDB.GetRepoMeta(context.Background(), repo)
			So(err, ShouldBeNil)

			expectedLastUpdated := repoInfo.Summary.NewestImage.LastUpdated

			// Check all TaggedTimestamp values from all tags
			for _, descriptor := range repoMeta.Tags {
				if !descriptor.TaggedTimestamp.IsZero() && descriptor.TaggedTimestamp.After(expectedLastUpdated) {
					expectedLastUpdated = descriptor.TaggedTimestamp
				}
			}

			expectedLastUpdatedMap[repo] = expectedLastUpdated
		}

		query := `
			{
				GlobalSearch(query:"repo"){
					Images {
						RepoName Tag LastUpdated Size
						Manifests {
							LastUpdated Size
							Platform { Os Arch }
							History {
								Layer { Size Digest }
								HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
							}
						}
						Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
					}
					Repos {
						Name LastUpdated Size
						Platforms { Os Arch }
						Vendors
						NewestImage {
							RepoName Tag LastUpdated Size
							Manifests {
								LastUpdated Size
								Platform { Os Arch }
								History {
									Layer { Size Digest }
									HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
								}
							}
							Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
						}
					}
					Layers { Digest Size }
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		// Make sure the repo/image counts match before comparing actual content
		So(responseStruct.Images, ShouldNotBeNil)
		t.Logf("returned images: %v", responseStruct.Images)
		So(responseStruct.Images, ShouldBeEmpty)
		t.Logf("returned repos: %v", responseStruct.Repos)
		So(len(responseStruct.Repos), ShouldEqual, 2)
		t.Logf("returned layers: %v", responseStruct.Layers)
		So(responseStruct.Layers, ShouldBeEmpty)

		newestImageMap := make(map[string]zcommon.ImageSummary)
		actualRepoMap := make(map[string]zcommon.RepoSummary)

		for _, repo := range responseStruct.Repos {
			newestImageMap[repo.Name] = repo.NewestImage
			actualRepoMap[repo.Name] = repo
		}

		// Tag 1.0.2 has a history entry which is older compare to 1.0.1
		So(newestImageMap["repo1"].Tag, ShouldEqual, "1.0.1")
		So(newestImageMap["repo1"].LastUpdated, ShouldEqual, time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC))

		So(newestImageMap["repo2"].Tag, ShouldEqual, "1.0.0")
		So(newestImageMap["repo2"].LastUpdated, ShouldEqual, time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC))

		for repoName, repoSummary := range actualRepoMap {
			// Check if data in NewestImage is consistent with the data in RepoSummary
			So(repoName, ShouldEqual, repoSummary.NewestImage.RepoName)
			So(repoSummary.Name, ShouldEqual, repoSummary.NewestImage.RepoName)

			// Verify the actual LastUpdated matches the computed expected value
			expectedLastUpdated, exists := expectedLastUpdatedMap[repoName]
			So(exists, ShouldBeTrue)
			So(repoSummary.LastUpdated, ShouldEqual, expectedLastUpdated)

			// The data in the RepoSummary returned from the request matches the data returned from the disk
			repoInfo := allExpectedRepoInfoMap[repoName]
			// Update the expected LastUpdated to account for TaggedTimestamp (which is not available from disk)
			repoInfo.Summary.LastUpdated = expectedLastUpdated

			t.Logf("Validate repo summary returned by global search with vulnerability scanning enabled")
			verifyRepoSummaryFields(t, &repoSummary, &repoInfo.Summary)

			// RepoInfo object does not provide vulnerability information so we need to check differently
			t.Logf("Found vulnerability summary %v", repoSummary.NewestImage.Vulnerabilities)

			if repoName == "repo1" { //nolint:goconst
				So(repoSummary.NewestImage.Vulnerabilities.Count, ShouldEqual, 4)
				// There are 4 vulnerabilities in the data used in tests
				So(repoSummary.NewestImage.Vulnerabilities.UnknownCount, ShouldEqual, 0)
				So(repoSummary.NewestImage.Vulnerabilities.LowCount, ShouldEqual, 1)
				So(repoSummary.NewestImage.Vulnerabilities.MediumCount, ShouldEqual, 1)
				So(repoSummary.NewestImage.Vulnerabilities.HighCount, ShouldEqual, 1)
				So(repoSummary.NewestImage.Vulnerabilities.CriticalCount, ShouldEqual, 1)
				So(repoSummary.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")
			} else {
				So(repoSummary.NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
				// There are 0 vulnerabilities this data used in tests
				So(repoSummary.NewestImage.Vulnerabilities.UnknownCount, ShouldEqual, 0)
				So(repoSummary.NewestImage.Vulnerabilities.LowCount, ShouldEqual, 0)
				So(repoSummary.NewestImage.Vulnerabilities.MediumCount, ShouldEqual, 0)
				So(repoSummary.NewestImage.Vulnerabilities.HighCount, ShouldEqual, 0)
				So(repoSummary.NewestImage.Vulnerabilities.CriticalCount, ShouldEqual, 0)
				So(repoSummary.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "NONE")
			}
		}

		query = `
		{
			GlobalSearch(query:"repo1:1.0.1"){
				Images {
					RepoName Tag LastUpdated Size
					Manifests {
						LastUpdated Size
						Platform { Os Arch }
						History {
							Layer { Size Digest }
							HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
						}
					}
					Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount  MaxSeverity }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors
					NewestImage {
						RepoName Tag LastUpdated Size
						Manifests {
							LastUpdated Size
							Platform { Os Arch }
							History {
								Layer { Size Digest }
								HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
							}
						}
						Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
					}
				}
				Layers { Digest Size }
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Images, ShouldNotBeEmpty)
		So(responseStruct.Repos, ShouldBeEmpty)
		So(responseStruct.Layers, ShouldBeEmpty)

		So(len(responseStruct.Images), ShouldEqual, 1)
		actualImageSummary := responseStruct.Images[0]
		So(actualImageSummary.Tag, ShouldEqual, "1.0.1")

		expectedImageSummary, ok := allExpectedImageSummaryMap["repo1:1.0.1"]
		So(ok, ShouldEqual, true)

		t.Logf("Validate image summary returned by global search with vulnerability scanning enable")
		verifyImageSummaryFields(t, &actualImageSummary, &expectedImageSummary)

		// RepoInfo object does not provide vulnerability information so we need to check differently
		t.Logf("Found vulnerability summary %v", actualImageSummary.Vulnerabilities)
		// There are 4 vulnerabilities in the data used in tests
		So(actualImageSummary.Vulnerabilities.Count, ShouldEqual, 4)
		So(actualImageSummary.Vulnerabilities.UnknownCount, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.LowCount, ShouldEqual, 1)
		So(actualImageSummary.Vulnerabilities.MediumCount, ShouldEqual, 1)
		So(actualImageSummary.Vulnerabilities.HighCount, ShouldEqual, 1)
		So(actualImageSummary.Vulnerabilities.CriticalCount, ShouldEqual, 1)
		So(actualImageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")
	})

	Convey("global searching by digest", t, func() {
		log := log.NewTestLogger()
		rootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)

		storeCtlr := ociutils.GetDefaultStoreController(rootDir, log)

		image1 := CreateRandomImage()
		image2 := CreateRandomImage()
		multiArch := CreateRandomMultiarch()

		err := WriteImageToFileSystem(image1, "repo1", "tag1", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image2, "repo1", "tag2", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteMultiArchImageToFileSystem(multiArch, "repo1", "tag-multi", storeCtlr)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(image2, "repo2", "tag2", storeCtlr)
		So(err, ShouldBeNil)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// simple image
		results := GlobalSearchGQL(image1.DigestStr(), baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 1)
		So(results.Images[0].Digest, ShouldResemble, image1.DigestStr())
		So(results.Images[0].RepoName, ShouldResemble, "repo1")

		results = GlobalSearchGQL(image2.DigestStr(), baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 2)

		repos := AccumulateField(results.Images,
			func(is zcommon.ImageSummary) string { return is.RepoName })
		So(repos, ShouldContain, "repo1")
		So(repos, ShouldContain, "repo2")

		// multiarch
		results = GlobalSearchGQL(multiArch.DigestStr(), baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 1)
		So(results.Images[0].Digest, ShouldResemble, multiArch.DigestStr())
		So(len(results.Images[0].Manifests), ShouldEqual, len(multiArch.Images))
		So(results.Images[0].RepoName, ShouldResemble, "repo1")

		results = GlobalSearchGQL(multiArch.Images[0].DigestStr(), baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 1)
		So(results.Images[0].Digest, ShouldResemble, multiArch.DigestStr())
		So(len(results.Images[0].Manifests), ShouldEqual, 1)
		So(results.Images[0].Manifests[0].Digest, ShouldResemble, multiArch.Images[0].DigestStr())
		So(results.Images[0].RepoName, ShouldResemble, "repo1")
	})

	Convey("global searching by tag cross repo", t, func() {
		log := log.NewTestLogger()
		rootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)

		storeCtlr := ociutils.GetDefaultStoreController(rootDir, log)

		image11 := CreateRandomImage()
		image12 := CreateRandomImage()
		err := WriteImageToFileSystem(image11, "repo1", "tag1", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image12, "repo1", "tag2", storeCtlr)
		So(err, ShouldBeNil)

		image21 := CreateRandomImage()
		image22 := CreateRandomImage()
		multiArch2 := CreateRandomMultiarch()
		err = WriteImageToFileSystem(image21, "repo2", "tag1", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image22, "repo2", "tag2", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteMultiArchImageToFileSystem(multiArch2, "repo2", "tag-multi", storeCtlr)
		So(err, ShouldBeNil)

		image31 := CreateRandomImage()
		image32 := CreateRandomImage()
		err = WriteImageToFileSystem(image31, "repo3", "tag1", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image32, "repo3", "tag2", storeCtlr)
		So(err, ShouldBeNil)

		image41 := CreateRandomImage()
		image42 := CreateRandomImage()
		multiArch4 := CreateRandomMultiarch()
		err = WriteImageToFileSystem(image41, "repo4", "tag1", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image42, "repo4", "tag2", storeCtlr)
		So(err, ShouldBeNil)
		err = WriteMultiArchImageToFileSystem(multiArch4, "repo4", "tag-multi", storeCtlr)
		So(err, ShouldBeNil)

		image51 := CreateRandomImage()
		err = WriteImageToFileSystem(image51, "repo5", "tag1", storeCtlr)
		So(err, ShouldBeNil)

		multiArch62 := CreateRandomMultiarch()
		err = WriteMultiArchImageToFileSystem(multiArch62, "repo6", "tag2", storeCtlr)
		So(err, ShouldBeNil)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// Search for a specific tag cross-repo and return single arch images
		results := GlobalSearchGQL(":tag1", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 5)
		So(len(results.Repos), ShouldEqual, 0)

		expectedRepos := []string{"repo1", "repo2", "repo3", "repo4", "repo5"}

		for _, image := range results.Images {
			So(image.Tag, ShouldEqual, "tag1")
			So(image.RepoName, ShouldBeIn, expectedRepos)
			So(len(image.Manifests), ShouldEqual, 1)
		}

		// Search for a specific tag cross-repo and return multi arch images
		results = GlobalSearchGQL(":tag-multi", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 2)
		So(len(results.Repos), ShouldEqual, 0)

		expectedRepos = []string{"repo2", "repo4"}

		for _, image := range results.Images {
			So(image.Tag, ShouldEqual, "tag-multi")
			So(image.RepoName, ShouldBeIn, expectedRepos)
			So(len(image.Manifests), ShouldEqual, 3)
		}

		// Search for a specific tag cross-repo and return mixed single and multiarch images
		results = GlobalSearchGQL(":tag2", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 5)
		So(len(results.Repos), ShouldEqual, 0)

		expectedRepos = []string{"repo1", "repo2", "repo3", "repo4", "repo6"}

		for _, image := range results.Images {
			So(image.Tag, ShouldEqual, "tag2")
			So(image.RepoName, ShouldBeIn, expectedRepos)

			if image.RepoName == "repo6" {
				So(len(image.Manifests), ShouldEqual, 3)
			} else {
				So(len(image.Manifests), ShouldEqual, 1)
			}
		}

		// Search for multiple tags using a partial match cross-repo and return multiarch images
		results = GlobalSearchGQL(":multi", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 2)
		So(len(results.Repos), ShouldEqual, 0)

		expectedRepos = []string{"repo2", "repo4"}

		for _, image := range results.Images {
			So(image.Tag, ShouldContainSubstring, "multi")
			So(image.RepoName, ShouldBeIn, expectedRepos)
			So(len(image.Manifests), ShouldEqual, 3)
		}

		// Search for multiple tags using a partial match cross-repo and return mixed single and multiarch images
		results = GlobalSearchGQL(":tag", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 12)
		So(len(results.Repos), ShouldEqual, 0)

		expectedRepos = []string{"repo1", "repo2", "repo3", "repo4", "repo5", "repo6"}

		for _, image := range results.Images {
			So(image.Tag, ShouldContainSubstring, "tag")
			So(image.RepoName, ShouldBeIn, expectedRepos)
		}

		// Search for a specific tag cross-repo and return mixt single and multiarch images
		result := GlobalSearchGQL(":", baseURL)
		errors := result.Errors
		So(len(errors), ShouldEqual, 1)

		results = result.GlobalSearch
		So(len(results.Images), ShouldEqual, 0)
		So(len(results.Repos), ShouldEqual, 0)
	})

	Convey("test nested indexes CVE scanning disabled", t, func() {
		log := log.NewTestLogger()
		rootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir

		Convey("test with boltdb", func() {
			conf.Storage.CacheDriver = nil
		})

		Convey("test with redis", func() {
			miniRedis := miniredis.RunT(t)

			conf.Storage.CacheDriver = map[string]any{
				"name": "redis",
				"url":  "redis://" + miniRedis.Addr(),
			}
		})

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)
		ctlrManager := NewControllerManager(ctlr)

		storeCtlr := ociutils.GetDefaultStoreController(rootDir, log)

		// nested manifest/indexes:
		// image111 -> multiArchBottom11 -> multiArchMiddle1 -> multiArchTop
		// image112 -> multiArchBottom11 -> multiArchMiddle1 -> multiArchTop
		// image121 -> multiArchBottom12 -> multiArchMiddle1 -> multiArchTop
		// image122 -> multiArchBottom12 -> multiArchMiddle1 -> multiArchTop
		// image211 -> multiArchBottom21 -> multiArchMiddle2 -> multiArchTop
		// image212 -> multiArchBottom21 -> multiArchMiddle2 -> multiArchTop
		// image31 -> multiArchMiddle3 -> multiArchTop
		// image32 -> multiArchMiddle3 -> multiArchTop

		repoName := "nested"

		image111 := CreateRandomImage()
		image112 := CreateRandomImage()
		multiArchBottom11 := CreateMultiarchWith().Images([]Image{image111, image112}).Build()
		err := WriteMultiArchImageToFileSystem(multiArchBottom11, repoName, multiArchBottom11.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		image121 := CreateRandomImage()
		image122 := CreateRandomImage()
		multiArchBottom12 := CreateMultiarchWith().Images([]Image{image121, image122}).Build()
		err = WriteMultiArchImageToFileSystem(multiArchBottom12, repoName, multiArchBottom12.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		indexMultiArchMiddle1 := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    multiArchBottom11.IndexDescriptor.Digest,
					Size:      multiArchBottom11.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
				{
					Digest:    multiArchBottom12.IndexDescriptor.Digest,
					Size:      multiArchBottom12.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
			},
		}

		indexMultiArchMiddle1Blob, err := json.Marshal(indexMultiArchMiddle1)
		So(err, ShouldBeNil)

		indexMultiArchMiddle1Digest, _, err := storeCtlr.GetDefaultImageStore().PutImageManifest(repoName,
			"multiArchMiddle1", ispec.MediaTypeImageIndex, indexMultiArchMiddle1Blob)
		So(err, ShouldBeNil)

		image211 := CreateRandomImage()
		image212 := CreateRandomImage()
		multiArchBottom21 := CreateMultiarchWith().Images([]Image{image211, image212}).Build()
		err = WriteMultiArchImageToFileSystem(multiArchBottom21, repoName, multiArchBottom21.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		indexMultiArchMiddle2 := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    multiArchBottom21.IndexDescriptor.Digest,
					Size:      multiArchBottom21.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
			},
		}

		indexMultiArchMiddle2Blob, err := json.Marshal(indexMultiArchMiddle2)
		So(err, ShouldBeNil)

		indexMultiArchMiddle2Digest, _, err := storeCtlr.GetDefaultImageStore().PutImageManifest(repoName,
			"multiArchMiddle2", ispec.MediaTypeImageIndex, indexMultiArchMiddle2Blob)
		So(err, ShouldBeNil)

		image31 := CreateRandomImage()
		image32 := CreateRandomImage()
		multiArchBottom3 := CreateMultiarchWith().Images([]Image{image31, image32}).Build()
		err = WriteMultiArchImageToFileSystem(multiArchBottom3, repoName, multiArchBottom3.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		indexMultiArchTop := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    indexMultiArchMiddle1Digest,
					Size:      int64(len(indexMultiArchMiddle1Blob)),
					MediaType: ispec.MediaTypeImageIndex,
				},
				{
					Digest:    indexMultiArchMiddle2Digest,
					Size:      int64(len(indexMultiArchMiddle2Blob)),
					MediaType: ispec.MediaTypeImageIndex,
				},
				{
					Digest:    multiArchBottom3.IndexDescriptor.Digest,
					Size:      multiArchBottom3.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
			},
		}

		indexMultiArchTopBlob, err := json.Marshal(indexMultiArchTop)
		So(err, ShouldBeNil)

		_, _, err = storeCtlr.GetDefaultImageStore().PutImageManifest(repoName, "multiArchTop", ispec.MediaTypeImageIndex,
			indexMultiArchTopBlob)
		So(err, ShouldBeNil)

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// Search for a specific tag cross-repo and return single arch images
		results := GlobalSearchGQL(":multiArch", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 3)
		So(len(results.Repos), ShouldEqual, 0)

		for _, image := range results.Images {
			So(image.RepoName, ShouldEqual, repoName)

			switch image.Tag {
			case "multiArchMiddle1":
				So(len(image.Manifests), ShouldEqual, 4)
			case "multiArchMiddle2":
				So(len(image.Manifests), ShouldEqual, 2)
			case "multiArchTop":
				So(len(image.Manifests), ShouldEqual, 8)
			}
		}
	})

	Convey("test nested indexes CVE scanning enabled", t, func() {
		log := log.NewTestLogger()
		rootDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir

		Convey("test with boltdb", func() {
			conf.Storage.CacheDriver = nil
		})

		Convey("test with redis", func() {
			miniRedis := miniredis.RunT(t)

			conf.Storage.CacheDriver = map[string]any{
				"name": "redis",
				"url":  "redis://" + miniRedis.Addr(),
			}
		})

		defaultVal := true

		updateDuration, _ := time.ParseDuration("1h")
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
			Trivy:          trivyConfig,
		}
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		storeCtlr := ociutils.GetDefaultStoreController(rootDir, log)

		// nested manifest/indexes:
		// image111 -> multiArchBottom11 -> multiArchMiddle1 -> multiArchTop
		// image112 -> multiArchBottom11 -> multiArchMiddle1 -> multiArchTop
		// image121 -> multiArchBottom12 -> multiArchMiddle1 -> multiArchTop
		// image122 -> multiArchBottom12 -> multiArchMiddle1 -> multiArchTop
		// image211 -> multiArchBottom21 -> multiArchMiddle2 -> multiArchTop
		// image212 -> multiArchBottom21 -> multiArchMiddle2 -> multiArchTop
		// image31 -> multiArchMiddle3 -> multiArchTop
		// image32 -> multiArchMiddle3 -> multiArchTop

		repoName := "nested"

		image111 := CreateRandomImage()
		image112 := CreateRandomImage()
		multiArchBottom11 := CreateMultiarchWith().Images([]Image{image111, image112}).Build()
		err := WriteMultiArchImageToFileSystem(multiArchBottom11, repoName, multiArchBottom11.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		image121 := CreateRandomImage()
		image122 := CreateRandomImage()
		multiArchBottom12 := CreateMultiarchWith().Images([]Image{image121, image122}).Build()
		err = WriteMultiArchImageToFileSystem(multiArchBottom12, repoName, multiArchBottom12.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		indexMultiArchMiddle1 := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    multiArchBottom11.IndexDescriptor.Digest,
					Size:      multiArchBottom11.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
				{
					Digest:    multiArchBottom12.IndexDescriptor.Digest,
					Size:      multiArchBottom12.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
			},
		}

		indexMultiArchMiddle1Blob, err := json.Marshal(indexMultiArchMiddle1)
		So(err, ShouldBeNil)

		indexMultiArchMiddle1Digest, _, err := storeCtlr.GetDefaultImageStore().PutImageManifest(repoName,
			"multiArchMiddle1", ispec.MediaTypeImageIndex, indexMultiArchMiddle1Blob)
		So(err, ShouldBeNil)

		image211 := CreateRandomImage()
		image212 := CreateRandomImage()
		multiArchBottom21 := CreateMultiarchWith().Images([]Image{image211, image212}).Build()
		err = WriteMultiArchImageToFileSystem(multiArchBottom21, repoName, multiArchBottom21.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		indexMultiArchMiddle2 := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    multiArchBottom21.IndexDescriptor.Digest,
					Size:      multiArchBottom21.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
			},
		}

		indexMultiArchMiddle2Blob, err := json.Marshal(indexMultiArchMiddle2)
		So(err, ShouldBeNil)

		indexMultiArchMiddle2Digest, _, err := storeCtlr.GetDefaultImageStore().PutImageManifest(repoName,
			"multiArchMiddle2", ispec.MediaTypeImageIndex, indexMultiArchMiddle2Blob)
		So(err, ShouldBeNil)

		image31 := CreateRandomImage()
		image32 := CreateRandomImage()
		multiArchBottom3 := CreateMultiarchWith().Images([]Image{image31, image32}).Build()
		err = WriteMultiArchImageToFileSystem(multiArchBottom3, repoName, multiArchBottom3.Digest().String(), storeCtlr)
		So(err, ShouldBeNil)

		indexMultiArchTop := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    indexMultiArchMiddle1Digest,
					Size:      int64(len(indexMultiArchMiddle1Blob)),
					MediaType: ispec.MediaTypeImageIndex,
				},
				{
					Digest:    indexMultiArchMiddle2Digest,
					Size:      int64(len(indexMultiArchMiddle2Blob)),
					MediaType: ispec.MediaTypeImageIndex,
				},
				{
					Digest:    multiArchBottom3.IndexDescriptor.Digest,
					Size:      multiArchBottom3.IndexDescriptor.Size,
					MediaType: ispec.MediaTypeImageIndex,
				},
			},
		}

		indexMultiArchTopBlob, err := json.Marshal(indexMultiArchTop)
		So(err, ShouldBeNil)

		_, _, err = storeCtlr.GetDefaultImageStore().PutImageManifest(repoName, "multiArchTop", ispec.MediaTypeImageIndex,
			indexMultiArchTopBlob)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)

		if err := ctlr.Init(); err != nil {
			panic(err)
		}

		ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		WaitTillServerReady(baseURL)

		// Search for a specific tag cross-repo and return single arch images
		results := GlobalSearchGQL(":multiArch", baseURL).GlobalSearch
		So(len(results.Images), ShouldEqual, 3)
		So(len(results.Repos), ShouldEqual, 0)

		for _, image := range results.Images {
			So(image.RepoName, ShouldEqual, repoName)

			switch image.Tag {
			case "multiArchMiddle1":
				So(len(image.Manifests), ShouldEqual, 4)
			case "multiArchMiddle2":
				So(len(image.Manifests), ShouldEqual, 2)
			case "multiArchTop":
				So(len(image.Manifests), ShouldEqual, 8)
			}
		}
	})
}

func TestCleaningFilteringParamsGlobalSearch(t *testing.T) {
	Convey("Test cleaning filtering parameters for global search", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		image := CreateImageWith().RandomLayers(1, 100).
			ImageConfig(ispec.Image{Platform: ispec.Platform{
				OS:           "windows",
				Architecture: "amd64",
			}}).Build()

		err := UploadImage(image, baseURL, "repo1", image.DigestStr())
		So(err, ShouldBeNil)

		image = CreateImageWith().RandomLayers(1, 100).
			ImageConfig(ispec.Image{Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			}}).Build()

		err = UploadImage(image, baseURL, "repo2", image.DigestStr())
		So(err, ShouldBeNil)

		query := `
		{
			GlobalSearch(query:"repo", requestedPage:{limit: 3, offset: 0, sortBy:RELEVANCE},
			filter:{Os:["  linux", "Windows ", "  "], Arch:["","aMd64  "]}) {
				Repos {
					Name
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
	})
}

func TestGlobalSearchFiltering(t *testing.T) {
	Convey("Global search HasToBeSigned filtering", t, func() {
		dir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		image := CreateRandomImage()

		err := UploadImage(image, baseURL, "unsigned-repo", "test")
		So(err, ShouldBeNil)

		image = CreateRandomImage()

		err = UploadImage(image, baseURL, "signed-repo", "test")
		So(err, ShouldBeNil)

		err = signature.SignImageUsingCosign("signed-repo:test", port, false)
		So(err, ShouldBeNil)

		query := `{
			GlobalSearch(query:"repo",
			filter:{HasToBeSigned:true}) {
				Repos {
					Name
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Repos, ShouldNotBeEmpty)
		So(responseStruct.Repos[0].Name, ShouldResemble, "signed-repo")
	})
}

func TestGlobalSearchWithInvalidInput(t *testing.T) {
	Convey("Global search with invalid input", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		longString := RandomString(1000)

		query := fmt.Sprintf(`
		{
			GlobalSearch(query:"%s", requestedPage:{limit: 3, offset: 4, sortBy:RELEVANCE},
			filter:{Os:["linux", "Windows", ""], Arch:["","amd64"]}) {
				Repos {
					Name
				}
			}
		}`, longString)

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Errors, ShouldNotBeEmpty)

		query = fmt.Sprintf(`
		{
			GlobalSearch(query:"repo", requestedPage:{limit: 3, offset: 4, sortBy:RELEVANCE},
			filter:{Os:["%s", "Windows", ""], Arch:["","amd64"]}) {
				Repos {
					Name
				}
			}
		}`, longString)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Errors, ShouldNotBeEmpty)

		query = fmt.Sprintf(`
		{
			GlobalSearch(query:"repo", requestedPage:{limit: 3, offset: 4, sortBy:RELEVANCE},
			filter:{Os:["", "Windows", ""], Arch:["","%s"]}) {
				Repos {
					Name
				}
			}
		}`, longString)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Errors, ShouldNotBeEmpty)
	})
}

func TestImageList(t *testing.T) {
	Convey("Test ImageList", t, func() {
		rootDir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		createdTimeL2 := time.Date(2010, 2, 1, 12, 0, 0, 0, time.UTC)
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
			History: []ispec.History{
				{
					Created:    &createdTime,
					CreatedBy:  "go test data",
					Author:     "ZotUser",
					Comment:    "Test history comment",
					EmptyLayer: true,
				},
				{
					Created:    &createdTimeL2,
					CreatedBy:  "go test data 2",
					Author:     "ZotUser",
					Comment:    "Test history comment2",
					EmptyLayer: false,
				},
			},
		}

		image := CreateImageWith().RandomLayers(1, 100).ImageConfig(config).Build()

		err := UploadImage(image, baseURL, "zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(image, baseURL, "a/zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(image, baseURL, "zot-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(image, baseURL, "a/zot-test", "0.0.1")
		So(err, ShouldBeNil)

		imageStore := ctlr.StoreController.DefaultStore

		repos, err := imageStore.GetRepositories()
		So(err, ShouldBeNil)

		tags, err := imageStore.GetImageTags(repos[0])
		So(err, ShouldBeNil)

		buf, _, _, err := imageStore.GetImageManifest(repos[0], tags[0])
		So(err, ShouldBeNil)

		var imageManifest ispec.Manifest

		err = json.Unmarshal(buf, &imageManifest)
		So(err, ShouldBeNil)

		var imageConfigInfo ispec.Image

		imageConfigBuf, err := imageStore.GetBlobContent(repos[0], imageManifest.Config.Digest)
		So(err, ShouldBeNil)
		err = json.Unmarshal(imageConfigBuf, &imageConfigInfo)
		So(err, ShouldBeNil)

		Convey("without pagination, valid response", func() {
			query := fmt.Sprintf(`{
				ImageList(repo:"%s"){
					Results {
						Manifests {
							History{
								HistoryDescription{
									Author
									Comment
									Created
									CreatedBy
									EmptyLayer
								},
								Layer{
									Digest
									Size
								}
							}
						}
					}
				}
			}`, repos[0])

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp, ShouldNotBeNil)

			var responseStruct zcommon.ImageListResponse
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)

			So(len(responseStruct.Results), ShouldEqual, len(tags))
			So(len(responseStruct.Results[0].Manifests[0].History), ShouldEqual, len(imageConfigInfo.History))
		})

		Convey("Pagination with valid params", func() {
			limit := 1
			query := fmt.Sprintf(`{
				ImageList(repo:"%s", requestedPage:{limit: %d, offset: 0, sortBy:RELEVANCE}){
					Results{
						Manifests {
							History{
								HistoryDescription{
									Author
									Comment
									Created
									CreatedBy
									EmptyLayer
								},
								Layer{
									Digest
									Size
								}
							}
						}
					}
				}
			}`, repos[0], limit)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(resp, ShouldNotBeNil)

			var responseStruct zcommon.ImageListResponse
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)

			So(len(responseStruct.Results), ShouldEqual, limit)
		})
	})
}

func TestGlobalSearchPagination(t *testing.T) {
	Convey("Test global search pagination", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		for i := range 3 {
			image := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := UploadImage(image, baseURL, fmt.Sprintf("repo%d", i), "0.0.1")
			So(err, ShouldBeNil)
		}

		Convey("Limit is bigger than the repo count", func() {
			query := `
			{
				GlobalSearch(query:"repo", requestedPage:{limit: 9, offset: 0, sortBy:RELEVANCE}){
					Repos {
						Name
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images, ShouldBeEmpty)
			So(responseStruct.Repos, ShouldNotBeEmpty)
			So(responseStruct.Layers, ShouldBeEmpty)

			So(len(responseStruct.Repos), ShouldEqual, 3)
		})

		Convey("Limit is lower than the repo count", func() {
			query := `
			{
				GlobalSearch(query:"repo", requestedPage:{limit: 2, offset: 0, sortBy:RELEVANCE}){
					Repos {
						Name
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images, ShouldBeEmpty)
			So(responseStruct.Repos, ShouldNotBeEmpty)
			So(responseStruct.Layers, ShouldBeEmpty)

			So(len(responseStruct.Repos), ShouldEqual, 2)
		})

		Convey("PageInfo returned proper response", func() {
			query := `
			{
				GlobalSearch(query:"repo", requestedPage:{limit: 2, offset: 0, sortBy:RELEVANCE}){
					Repos {
						Name
					}
					Page{
						ItemCount
						TotalCount
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images, ShouldBeEmpty)
			So(responseStruct.Repos, ShouldNotBeEmpty)
			So(responseStruct.Layers, ShouldBeEmpty)

			So(len(responseStruct.Repos), ShouldEqual, 2)
			So(responseStruct.Page.TotalCount, ShouldEqual, 3)
			So(responseStruct.Page.ItemCount, ShouldEqual, 2)
		})

		Convey("PageInfo when limit is bigger than the repo count", func() {
			query := `
			{
				GlobalSearch(query:"repo", requestedPage:{limit: 9, offset: 0, sortBy:RELEVANCE}){
					Repos {
						Name
					}
					Page{
						ItemCount
						TotalCount
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images, ShouldBeEmpty)
			So(responseStruct.Repos, ShouldNotBeEmpty)
			So(responseStruct.Layers, ShouldBeEmpty)

			So(len(responseStruct.Repos), ShouldEqual, 3)
			So(responseStruct.Page.TotalCount, ShouldEqual, 3)
			So(responseStruct.Page.ItemCount, ShouldEqual, 3)
		})

		Convey("PageInfo when limit and offset have 0 value", func() {
			query := `
			{
				GlobalSearch(query:"repo", requestedPage:{limit: 0, offset: 0, sortBy:RELEVANCE}){
					Repos {
						Name
					}
					Page{
						ItemCount
						TotalCount
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images, ShouldBeEmpty)
			So(responseStruct.Repos, ShouldNotBeEmpty)
			So(responseStruct.Layers, ShouldBeEmpty)

			So(len(responseStruct.Repos), ShouldEqual, 3)
			So(responseStruct.Page.TotalCount, ShouldEqual, 3)
			So(responseStruct.Page.ItemCount, ShouldEqual, 3)
		})
	})
}

func TestMetaDBWhenSigningImages(t *testing.T) {
	Convey("SigningImages", t, func() {
		subpath := "/a"

		dir := t.TempDir()
		subRootDir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test images to repo 1 image 1
		image1 := CreateDefaultImage()

		err := UploadImage(image1, baseURL, "repo1", "1.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(image1, baseURL, "repo1", "2.0.2")
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(image1.Manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBlob)

		multiArch := CreateRandomMultiarch()

		err = UploadMultiarchImage(multiArch, baseURL, "repo1", "index")
		So(err, ShouldBeNil)

		queryImage1 := `
		{
			GlobalSearch(query:"repo1:1.0"){
				Images {
					RepoName Tag LastUpdated Size IsSigned
					Manifests{
						LastUpdated Size
					}
				}
			}
		}`

		queryImage2 := `
		{
			GlobalSearch(query:"repo1:2.0"){
				Images {
					RepoName Tag LastUpdated Size IsSigned
					Manifests { LastUpdated Size  Platform { Os Arch } }
				}
			}
		}`

		queryIndex := `
		{
			GlobalSearch(query:"repo1:index"){
				Images {
					RepoName Tag LastUpdated Size IsSigned
					Manifests { LastUpdated Size  Platform { Os Arch } }
				}
			}
		}
		`

		Convey("Sign with cosign", func() {
			err = signature.SignImageUsingCosign("repo1:1.0.1", port, false)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryImage1))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)

			// check image 2 is signed also because it has the same manifest
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryImage2))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)

			// delete the signature
			resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" +
				fmt.Sprintf("sha256-%s.sig", manifestDigest.Encoded()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// check image 2 is not signed anymore
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryImage2))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeFalse)
		})

		Convey("Cover errors when signing with cosign", func() {
			Convey("imageIsSignature fails", func() {
				// make image store ignore the wrong format of the input
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", nil
					},
					DeleteImageManifestFn: func(repo, reference string, dc bool) error {
						return ErrTestError
					},
				}

				// push bad manifest blob
				resp, err := resty.R().
					SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
					SetBody([]byte("unmashable manifest blob")).
					Put(baseURL + "/v2/" + "repo" + "/manifests/" + "tag")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("image is a signature, AddManifestSignature fails", func() {
				ctlr.MetaDB = mocks.MetaDBMock{
					AddManifestSignatureFn: func(repo string, signedManifestDigest godigest.Digest,
						sm mTypes.SignatureMetadata,
					) error {
						return ErrTestError
					},
				}

				err := signature.SignImageUsingCosign("repo1:1.0.1", port, false)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Sign with notation", func() {
			err = signature.SignImageUsingNotary("repo1:1.0.1", port, true)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryImage1))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)
		})

		Convey("Sign with notation index", func() {
			err = signature.SignImageUsingNotary("repo1:index", port, false)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryIndex))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)
		})

		Convey("Sign with cosign index", func() {
			err = signature.SignImageUsingCosign("repo1:index", port, false)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryIndex))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)

			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)
		})
	})
}

func TestMetaDBWhenPushingImages(t *testing.T) {
	Convey("Cover errors when pushing", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		Convey("SetManifestMeta succeeds but SetRepoReference fails", func() {
			ctlr.MetaDB = mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					return ErrTestError
				},
			}

			image := CreateRandomImage()

			ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
				NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
				PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return image.ConfigDescriptor.Data, nil
				},
			}

			err := UploadImage(image, baseURL, "repo1", "1.0.1")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestMetaDBIndexOperations(t *testing.T) {
	Convey("Idex Operations BoltDB", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Compat = []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2}
		conf.Storage.RootDirectory = dir
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		RunMetaDBIndexTests(baseURL, port)
	})
}

func RunMetaDBIndexTests(baseURL, port string) {
	Convey("Push test index", func() {
		const repo = "repo"

		multiarchImage := CreateRandomMultiarch()

		err := UploadMultiarchImage(multiarchImage, baseURL, repo, "tag1")
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"repo:tag1"){
					Images {
						RepoName Tag DownloadCount
						IsSigned
						Manifests {
							Digest
							ConfigDigest
							Platform {Os Arch}
							Layers {Size Digest}
							LastUpdated
							Size
						}
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		responseImages := responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage := responseImages[0]
		So(len(responseImage.Manifests), ShouldEqual, 3)

		err = signature.SignImageUsingCosign("repo@"+multiarchImage.DigestStr(), port, false)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		responseImages = responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage = responseImages[0]

		So(responseImage.IsSigned, ShouldBeTrue)

		// remove signature
		cosignTag := "sha256-" + multiarchImage.Digest().Encoded() + ".sig"
		_, err = resty.R().Delete(baseURL + "/v2/" + "repo" + "/manifests/" + cosignTag)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		responseImages = responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage = responseImages[0]

		So(responseImage.IsSigned, ShouldBeFalse)
		// Download count is 1 because SignImageUsingCosign fetches the manifest to sign it
		So(responseImage.DownloadCount, ShouldEqual, 1)

		// Get initial repository download count - query repository separately
		repoQuery := `
			{
				GlobalSearch(query:"repo"){
					Repos {
						Name DownloadCount
					}
				}
			}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(repoQuery))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		repoResponseStruct := &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), repoResponseStruct)
		So(err, ShouldBeNil)
		repos := repoResponseStruct.GlobalSearchResult.GlobalSearch.Repos
		So(repos, ShouldNotBeEmpty)
		initialRepoDownloadCount := repos[0].DownloadCount

		// Test download count - download the index manifest 3 times
		resp, err = resty.R().Get(baseURL + "/v2/" + repo + "/manifests/" + "tag1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/v2/" + repo + "/manifests/" + "tag1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/v2/" + repo + "/manifests/" + "tag1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// Verify download count increased at both image and repository level
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		responseImages = responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage = responseImages[0]
		// Started with 1 (from cosign signing), added 3 more downloads = 4 total
		So(responseImage.DownloadCount, ShouldEqual, 4)

		// Verify repository-level download count also increased - query repository separately
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(repoQuery))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		repoResponseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), repoResponseStruct)
		So(err, ShouldBeNil)
		repos = repoResponseStruct.GlobalSearchResult.GlobalSearch.Repos
		So(repos, ShouldNotBeEmpty)
		So(repos[0].DownloadCount, ShouldEqual, initialRepoDownloadCount+3)
	})

	Convey("Push test index with Docker media types", func() {
		const repo = "repo-docker"

		multiarchImage := CreateRandomMultiarch().AsDockerImage()

		err := UploadMultiarchImage(multiarchImage, baseURL, repo, "tag1")
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"repo-docker:tag1"){
					Images {
						RepoName Tag DownloadCount
						IsSigned
						Manifests {
							Digest
							ConfigDigest
							Platform {Os Arch}
							Layers {Size Digest}
							LastUpdated
							Size
						}
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		responseImages := responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage := responseImages[0]
		So(len(responseImage.Manifests), ShouldEqual, 3)

		err = signature.SignImageUsingCosign("repo-docker@"+multiarchImage.DigestStr(), port, false)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		responseImages = responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage = responseImages[0]

		So(responseImage.IsSigned, ShouldBeTrue)

		// remove signature
		cosignTag := "sha256-" + multiarchImage.Digest().Encoded() + ".sig"
		_, err = resty.R().Delete(baseURL + "/v2/" + repo + "/manifests/" + cosignTag)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct = &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		responseImages = responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage = responseImages[0]

		So(responseImage.IsSigned, ShouldBeFalse)
		// Download count is 1 because SignImageUsingCosign fetches the manifest to sign it
		initialDownloadCount := responseImage.DownloadCount
		So(initialDownloadCount, ShouldEqual, 1)

		// Get initial repository download count - query repository separately
		repoQuery := `
			{
				GlobalSearch(query:"repo-docker"){
					Repos {
						Name DownloadCount
					}
				}
			}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(repoQuery))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		repoResponseStruct := &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), repoResponseStruct)
		So(err, ShouldBeNil)
		repos := repoResponseStruct.GlobalSearchResult.GlobalSearch.Repos
		So(repos, ShouldNotBeEmpty)
		initialRepoDownloadCount := repos[0].DownloadCount

		// Test download count - download the index manifest 3 times
		resp, err = resty.R().Get(baseURL + "/v2/" + repo + "/manifests/" + "tag1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/v2/" + repo + "/manifests/" + "tag1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/v2/" + repo + "/manifests/" + "tag1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// Verify download count increased at both image and repository level
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		responseImages = responseStruct.GlobalSearchResult.GlobalSearch.Images
		So(responseImages, ShouldNotBeEmpty)
		responseImage = responseImages[0]
		// Started with initialDownloadCount of 1 (from SignImageUsingCosign), added 3 more downloads
		So(responseImage.DownloadCount, ShouldEqual, initialDownloadCount+3)

		// Verify repository-level download count also increased - query repository separately
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(repoQuery))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		repoResponseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), repoResponseStruct)
		So(err, ShouldBeNil)
		repos = repoResponseStruct.GlobalSearchResult.GlobalSearch.Repos
		So(repos, ShouldNotBeEmpty)
		So(repos[0].DownloadCount, ShouldEqual, initialRepoDownloadCount+3)
	})

	Convey("Index base images", func() {
		// ---------------- BASE IMAGE -------------------
		imageAMD64 := CreateImageWith().LayerBlobs([][]byte{
			{10, 20, 30},
			{11, 21, 31},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		}).Build()

		imageSomeArch := CreateImageWith().LayerBlobs([][]byte{
			{18, 28, 38},
			{12, 22, 32},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "someArch",
			},
		}).Build()

		multiImage := CreateMultiarchWith().Images([]Image{imageAMD64, imageSomeArch}).Build()

		err := UploadMultiarchImage(multiImage, baseURL, "test-repo", "latest")
		So(err, ShouldBeNil)
		// ---------------- BASE IMAGE -------------------

		//  ---------------- SAME LAYERS -------------------
		image1 := CreateImageWith().LayerBlobs([][]byte{{0, 0, 2}}).ImageConfig(imageSomeArch.Config).Build()

		image2 := CreateImageWith().LayerBlobs(imageAMD64.Layers).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-same-layers", "index-one-arch-same-layers")
		So(err, ShouldBeNil)
		//  ---------------- SAME LAYERS -------------------

		//  ---------------- LESS LAYERS -------------------
		image1 = CreateImageWith().LayerBlobs([][]byte{
			{3, 2, 2},
			{5, 2, 5},
		}).ImageConfig(imageSomeArch.Config).Build()

		image2 = CreateImageWith().LayerBlobs([][]byte{
			imageAMD64.Layers[0],
		}).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-less-layers", "index-one-arch-less-layers")
		So(err, ShouldBeNil)
		//  ---------------- LESS LAYERS -------------------

		//  ---------------- LESS LAYERS FALSE -------------------
		image1 = CreateImageWith().LayerBlobs([][]byte{
			{3, 2, 2},
			{5, 2, 5},
		}).ImageConfig(imageSomeArch.Config).Build()

		auxLayer := imageAMD64.Layers[0]
		auxLayer[0] = 20

		image2 = CreateImageWith().LayerBlobs([][]byte{
			auxLayer,
		}).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-less-layers-false",
			"index-one-arch-less-layers-false")
		So(err, ShouldBeNil)
		//  ---------------- LESS LAYERS FALSE -------------------

		//  ---------------- MORE LAYERS -------------------
		image1 = CreateImageWith().LayerBlobs([][]byte{
			{0, 0, 2},
			{3, 0, 2},
		}).ImageConfig(imageSomeArch.Config).Build()

		image2 = CreateImageWith().LayerBlobs(
			append(imageAMD64.Layers, []byte{1, 3, 55}),
		).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-more-layers", "index-one-arch-more-layers")
		So(err, ShouldBeNil)
		//  ---------------- MORE LAYERS -------------------

		query := `
				{
					BaseImageList(image:"test-repo:latest"){
						Results{
							RepoName
							Tag
							Manifests {
								Digest
								ConfigDigest
								LastUpdated
								Size
							}
							Size
						}
					}
				}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(strings.Contains(string(resp.Body()), "index-one-arch-less-layers"), ShouldBeTrue)
		So(strings.Contains(string(resp.Body()), "index-one-arch-same-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "index-one-arch-less-layers-false"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "index-one-arch-more-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "test-repo"), ShouldBeFalse)
	})

	Convey("Index base images for digest", func() {
		// ---------------- BASE IMAGE -------------------
		imageAMD64 := CreateImageWith().LayerBlobs([][]byte{
			{10, 20, 30},
			{11, 21, 31},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		}).Build()

		baseLinuxAMD64Digest := imageAMD64.ManifestDescriptor.Digest

		imageSomeArch := CreateImageWith().LayerBlobs([][]byte{
			{18, 28, 38},
			{12, 22, 32},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "someArch",
			},
		}).Build()

		baseLinuxSomeArchDigest := imageSomeArch.ManifestDescriptor.Digest

		multiImage := CreateMultiarchWith().Images([]Image{imageAMD64, imageSomeArch}).Build()

		err := UploadMultiarchImage(multiImage, baseURL, "test-repo", "index")
		So(err, ShouldBeNil)
		// ---------------- BASE IMAGE FOR LINUX AMD64 -------------------

		image := CreateImageWith().LayerBlobs([][]byte{
			imageAMD64.Layers[0],
		}).ImageConfig(imageAMD64.Config).Build()

		err = UploadImage(image, baseURL, "test-repo", "less-layers-linux-amd64")
		So(err, ShouldBeNil)

		// ---------------- BASE IMAGE FOR LINUX SOMEARCH -------------------

		image = CreateImageWith().LayerBlobs([][]byte{
			imageSomeArch.Layers[0],
		}).ImageConfig(imageAMD64.Config).Build()

		err = UploadImage(image, baseURL, "test-repo", "less-layers-linux-somearch")
		So(err, ShouldBeNil)

		// ------- TEST

		query := `
		{
			BaseImageList(image:"test-repo:index", digest:"%s"){
				Results{
					RepoName
					Tag
					Manifests {
						Digest
						ConfigDigest
						LastUpdated
						Size
					}
					Size
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" +
			url.QueryEscape(
				fmt.Sprintf(query, baseLinuxAMD64Digest.String()),
			),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(strings.Contains(string(resp.Body()), "less-layers-linux-amd64"), ShouldEqual, true)
		So(strings.Contains(string(resp.Body()), "less-layers-linux-somearch"), ShouldEqual, false)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" +
			url.QueryEscape(
				fmt.Sprintf(query, baseLinuxSomeArchDigest.String()),
			),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(strings.Contains(string(resp.Body()), "less-layers-linux-amd64"), ShouldEqual, false)
		So(strings.Contains(string(resp.Body()), "less-layers-linux-somearch"), ShouldEqual, true)
	})

	Convey("Index derived images", func() {
		// ---------------- BASE IMAGE -------------------
		imageAMD64 := CreateImageWith().LayerBlobs([][]byte{
			{10, 20, 30},
			{11, 21, 31},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		}).Build()

		imageSomeArch := CreateImageWith().LayerBlobs([][]byte{
			{18, 28, 38},
			{12, 22, 32},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "someArch",
			},
		}).Build()

		multiImage := CreateMultiarchWith().Images([]Image{imageAMD64, imageSomeArch}).Build()

		err := UploadMultiarchImage(multiImage, baseURL, "test-repo", "latest")
		So(err, ShouldBeNil)
		// ---------------- BASE IMAGE -------------------

		//  ---------------- SAME LAYERS -------------------
		image1 := CreateImageWith().LayerBlobs([][]byte{
			{0, 0, 2},
		}).ImageConfig(imageSomeArch.Config).Build()

		image2 := CreateImageWith().LayerBlobs(
			imageAMD64.Layers,
		).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-same-layers", "index-one-arch-same-layers")
		So(err, ShouldBeNil)
		//  ---------------- SAME LAYERS -------------------

		//  ---------------- LESS LAYERS -------------------
		image1 = CreateImageWith().LayerBlobs([][]byte{
			{3, 2, 2},
			{5, 2, 5},
		}).ImageConfig(imageSomeArch.Config).Build()

		image2 = CreateImageWith().LayerBlobs([][]byte{
			imageAMD64.Layers[0],
		}).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-less-layers", "index-one-arch-less-layers")
		So(err, ShouldBeNil)
		//  ---------------- LESS LAYERS -------------------

		//  ---------------- LESS LAYERS FALSE -------------------
		image1 = CreateImageWith().LayerBlobs([][]byte{
			{3, 2, 2},
			{5, 2, 5},
		}).ImageConfig(imageSomeArch.Config).Build()

		image2 = CreateImageWith().LayerBlobs([][]byte{
			{99, 100, 102},
		}).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-less-layers-false",
			"index-one-arch-less-layers-false")
		So(err, ShouldBeNil)
		//  ---------------- LESS LAYERS FALSE -------------------

		//  ---------------- MORE LAYERS -------------------
		image1 = CreateImageWith().LayerBlobs([][]byte{
			{0, 0, 2},
			{3, 0, 2},
		}).ImageConfig(imageSomeArch.Config).Build()

		image2 = CreateImageWith().LayerBlobs([][]byte{
			imageAMD64.Layers[0],
			imageAMD64.Layers[1],
			{1, 3, 55},
		}).ImageConfig(imageAMD64.Config).Build()

		multiImage = CreateMultiarchWith().Images([]Image{image1, image2}).Build()

		err = UploadMultiarchImage(multiImage, baseURL, "index-one-arch-more-layers", "index-one-arch-more-layers")
		So(err, ShouldBeNil)
		//  ---------------- MORE LAYERS -------------------

		query := `
				{
					DerivedImageList(image:"test-repo:latest"){
						Results{
							RepoName
							Tag
							Manifests {
								Digest
								ConfigDigest
								LastUpdated
								Size
							}
							Size
						}
					}
				}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(strings.Contains(string(resp.Body()), "index-one-arch-less-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "index-one-arch-same-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "index-one-arch-less-layers-false"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "index-one-arch-more-layers"), ShouldBeTrue)
		So(strings.Contains(string(resp.Body()), "test-repo"), ShouldBeFalse)
	})

	Convey("Index derived images for digest", func() {
		// ---------------- BASE IMAGE -------------------
		imageAMD64 := CreateImageWith().LayerBlobs([][]byte{
			{10, 20, 30},
			{11, 21, 31},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		}).Build()

		baseLinuxAMD64Digest := imageAMD64.ManifestDescriptor.Digest

		imageSomeArch := CreateImageWith().LayerBlobs([][]byte{
			{18, 28, 38},
			{12, 22, 32},
		}).ImageConfig(ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "someArch",
			},
		}).Build()

		baseLinuxSomeArchDigest := imageSomeArch.ManifestDescriptor.Digest

		multiImage := CreateMultiarchWith().Images([]Image{imageAMD64, imageSomeArch}).Build()

		err := UploadMultiarchImage(multiImage, baseURL, "test-repo", "index")
		So(err, ShouldBeNil)
		// ---------------- BASE IMAGE FOR LINUX AMD64 -------------------
		image := CreateImageWith().LayerBlobs([][]byte{
			imageAMD64.Layers[0],
			imageAMD64.Layers[1],
			{0, 0, 0, 0},
			{1, 1, 1, 1},
		}).ImageConfig(imageAMD64.Config).Build()

		err = UploadImage(image, baseURL, "test-repo", "more-layers-linux-amd64")
		So(err, ShouldBeNil)

		// ---------------- BASE IMAGE FOR LINUX SOMEARCH -------------------
		image = CreateImageWith().LayerBlobs([][]byte{
			imageSomeArch.Layers[0],
			imageSomeArch.Layers[1],
			{3, 3, 3, 3},
			{2, 2, 2, 2},
		}).ImageConfig(imageAMD64.Config).Build()

		err = UploadImage(image, baseURL, "test-repo", "more-layers-linux-somearch")
		So(err, ShouldBeNil)

		// ------- TEST

		query := `
		{
			DerivedImageList(image:"test-repo:index", digest:"%s"){
				Results{
					RepoName
					Tag
					Manifests {
						Digest
						ConfigDigest
						LastUpdated
						Size
					}
					Size
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" +
			url.QueryEscape(
				fmt.Sprintf(query, baseLinuxAMD64Digest.String()),
			),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(strings.Contains(string(resp.Body()), "more-layers-linux-amd64"), ShouldEqual, true)
		So(strings.Contains(string(resp.Body()), "more-layers-linux-somearch"), ShouldEqual, false)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" +
			url.QueryEscape(
				fmt.Sprintf(query, baseLinuxSomeArchDigest.String()),
			),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		So(strings.Contains(string(resp.Body()), "more-layers-linux-amd64"), ShouldEqual, false)
		So(strings.Contains(string(resp.Body()), "more-layers-linux-somearch"), ShouldEqual, true)
	})
}

func TestMetaDBWhenReadingImages(t *testing.T) {
	Convey("Push test image", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		image := CreateImageWith().RandomLayers(1, 100).DefaultConfig().Build()

		err := UploadImage(image, baseURL, "repo1", "1.0.1")
		So(err, ShouldBeNil)

		Convey("Download 3 times", func() {
			resp, err := resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			query := `
			{
				GlobalSearch(query:"repo1:1.0"){
					Images {
						RepoName Tag DownloadCount
					}
				}
			}`

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)
			So(responseStruct.Images, ShouldNotBeEmpty)
			So(responseStruct.Images[0].DownloadCount, ShouldEqual, 3)

			// Verify repository-level download count also increased - query repository separately
			repoQuery := `
			{
				GlobalSearch(query:"repo1"){
					Repos {
						Name DownloadCount
					}
				}
			}`
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(repoQuery))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			repoResponseStruct := &zcommon.GlobalSearchResultResp{}
			err = json.Unmarshal(resp.Body(), repoResponseStruct)
			So(err, ShouldBeNil)
			So(repoResponseStruct.Repos, ShouldNotBeEmpty)
			So(repoResponseStruct.Repos[0].DownloadCount, ShouldEqual, 3)
		})

		Convey("Error when incrementing", func() {
			ctlr.MetaDB = mocks.MetaDBMock{
				UpdateStatsOnDownloadFn: func(repo string, tag string) error {
					return ErrTestError
				},
			}

			resp, err := resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
	})

	Convey("Push test image with Docker media types", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Compat = []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2}
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		image := CreateImageWith().RandomLayers(1, 100).DefaultConfig().Build().AsDockerImage()

		err := UploadImage(image, baseURL, "repo2", "2.0.1")
		So(err, ShouldBeNil)

		Convey("Download 3 times", func() {
			resp, err := resty.R().Get(baseURL + "/v2/" + "repo2" + "/manifests/" + "2.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/" + "repo2" + "/manifests/" + "2.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/" + "repo2" + "/manifests/" + "2.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			query := `
			{
				GlobalSearch(query:"repo2:2.0"){
					Images {
						RepoName Tag DownloadCount
					}
				}
			}`

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)
			So(responseStruct.Images, ShouldNotBeEmpty)
			So(responseStruct.Images[0].DownloadCount, ShouldEqual, 3)

			// Verify repository-level download count also increased - query repository separately
			repoQuery := `
			{
				GlobalSearch(query:"repo2"){
					Repos {
						Name DownloadCount
					}
				}
			}`
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(repoQuery))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			repoResponseStruct := &zcommon.GlobalSearchResultResp{}
			err = json.Unmarshal(resp.Body(), repoResponseStruct)
			So(err, ShouldBeNil)
			So(repoResponseStruct.Repos, ShouldNotBeEmpty)
			So(repoResponseStruct.Repos[0].DownloadCount, ShouldEqual, 3)
		})
	})
}

func TestMetaDBWhenDeletingImages(t *testing.T) {
	Convey("Setting up zot repo with test images", t, func() {
		dir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.GC = false

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test images to repo 1 image 1
		image1 := CreateRandomImage()

		err := UploadImage(image1, baseURL, "repo1", "1.0.1")
		So(err, ShouldBeNil)

		// push test images to repo 1 image 2
		createdTime2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		image2 := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			Created: &createdTime2,
			History: []ispec.History{
				{
					Created: &createdTime2,
				},
			},
		}).Build()

		err = UploadImage(image2, baseURL, "repo1", "1.0.2")
		So(err, ShouldBeNil)

		query := `
		{
			GlobalSearch(query:"repo1:1.0"){
				Images {
					RepoName Tag LastUpdated Size IsSigned
					Manifests{
						Platform { Os Arch }
						LastUpdated Size
					}
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.Images), ShouldEqual, 2)

		Convey("Delete a normal tag", func() {
			resp, err := resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(len(responseStruct.Images), ShouldEqual, 1)
			So(responseStruct.Images[0].Tag, ShouldEqual, "1.0.2")
		})

		Convey("Delete a cosign signature", func() {
			repo := "repo1"
			err := signature.SignImageUsingCosign("repo1:1.0.1", port, false)
			So(err, ShouldBeNil)

			query := `
			{
				GlobalSearch(query:"repo1:1.0.1"){
					Images {
						RepoName Tag LastUpdated Size IsSigned
						Manifests{
							Platform { Os Arch }
							LastUpdated Size
						}
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)

			// get signatur digest
			log := log.NewTestLogger()
			metrics := monitoring.NewMetricsServer(false, log)
			storage := local.NewImageStore(dir, false, false, log, metrics, nil, nil, nil, nil)

			indexBlob, err := storage.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var indexContent ispec.Index

			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			signatureTag := ""

			for _, manifest := range indexContent.Manifests {
				tag := manifest.Annotations[ispec.AnnotationRefName]

				if zcommon.IsCosignSignature(tag) {
					signatureTag = tag
				}
			}

			// delete the signature using the digest
			resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + signatureTag)
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// verify isSigned again and it should be false
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeFalse)
		})

		Convey("Delete a notary signature", func() {
			repo := "repo1"
			err := signature.SignImageUsingNotary("repo1:1.0.1", port, true)
			So(err, ShouldBeNil)

			query := `
			{
				GlobalSearch(query:"repo1:1.0.1"){
					Images {
						RepoName Tag LastUpdated Size IsSigned
						Manifests{
							Platform { Os Arch }
							LastUpdated Size
						}
					}
				}
			}`

			// test if it's signed
			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeTrue)

			// get signatur digest
			log := log.NewTestLogger()
			metrics := monitoring.NewMetricsServer(false, log)
			storage := local.NewImageStore(dir, false, false, log, metrics, nil, nil, nil, nil)

			indexBlob, err := storage.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var indexContent ispec.Index

			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			signatureReference := ""

			var sigManifestContent ispec.Manifest

			for _, manifest := range indexContent.Manifests {
				manifestBlob, _, _, err := storage.GetImageManifest(repo, manifest.Digest.String())
				So(err, ShouldBeNil)

				var manifestContent ispec.Manifest

				err = json.Unmarshal(manifestBlob, &manifestContent)
				So(err, ShouldBeNil)

				if zcommon.GetManifestArtifactType(manifestContent) == notreg.ArtifactTypeNotation {
					signatureReference = manifest.Digest.String()
					manifestBlob, _, _, err := storage.GetImageManifest(repo, signatureReference)
					So(err, ShouldBeNil)
					err = json.Unmarshal(manifestBlob, &sigManifestContent)
					So(err, ShouldBeNil)
				}
			}

			So(sigManifestContent, ShouldNotBeZeroValue)
			// check notation signature
			manifest1Blob, err := json.Marshal(image1.Manifest)
			So(err, ShouldBeNil)

			manifest1Digest := godigest.FromBytes(manifest1Blob)

			So(sigManifestContent.Subject, ShouldNotBeNil)
			So(sigManifestContent.Subject.Digest.String(), ShouldEqual, manifest1Digest.String())

			// delete the signature using the digest
			resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + signatureReference)
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// verify isSigned again and it should be false
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &zcommon.GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.Images[0].IsSigned, ShouldBeFalse)
		})

		Convey("Delete a referrer", func() {
			referredImageDescriptor := &ispec.Descriptor{
				Digest:    image1.ManifestDescriptor.Digest,
				MediaType: ispec.MediaTypeImageManifest,
			}

			referrerImage := CreateImageWith().RandomLayers(1, 100).DefaultConfig().
				Subject(referredImageDescriptor).Build()

			err = UploadImage(referrerImage, baseURL, "repo1", referrerImage.DigestStr())
			So(err, ShouldBeNil)

			// ------- check referrers for this image

			query := fmt.Sprintf(`
			{
				Referrers(repo:"repo1", digest:"%s"){
					MediaType
					Digest
				}
			}`, image1.ManifestDescriptor.Digest.String())

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &zcommon.ReferrersResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(len(responseStruct.Referrers), ShouldEqual, 1)
			So(responseStruct.Referrers[0].Digest, ShouldResemble, referrerImage.DigestStr())

			statusCode, err := DeleteImage("repo1", referrerImage.DigestStr(), "badURL")
			So(err, ShouldNotBeNil)
			So(statusCode, ShouldEqual, -1)

			// ------- Delete the referrer and see if it disappears from metaDB also
			statusCode, err = DeleteImage("repo1", referrerImage.DigestStr(), baseURL)
			So(err, ShouldBeNil)
			So(statusCode, ShouldEqual, http.StatusAccepted)

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &zcommon.ReferrersResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(len(responseStruct.Referrers), ShouldEqual, 0)
		})

		Convey("Deleting causes errors", func() {
			Convey("error while backing up the manifest", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
						return []byte{}, "", "", zerr.ErrRepoNotFound
					},
				}
				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureReference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
						return []byte{}, "", "", zerr.ErrBadManifest
					},
				}
				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureReference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)

				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
						return []byte{}, "", "", zerr.ErrRepoNotFound
					},
				}
				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureReference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("imageIsSignature fails", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", nil
					},
					DeleteImageManifestFn: func(repo, reference string, dc bool) error {
						return nil
					},
				}

				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureReference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("image is a signature, DeleteSignature fails", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
					PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
					GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
						configBlob, err := json.Marshal(ispec.Image{})
						So(err, ShouldBeNil)

						return configBlob, nil
					},
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", nil
					},
					DeleteImageManifestFn: func(repo, reference string, dc bool) error {
						return nil
					},
					GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
						return []byte("{}"), "1", "1", nil
					},
				}

				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" +
					"sha256-343ebab94a7674da181c6ea3da013aee4f8cbe357870f8dcaf6268d5343c3474.sig")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("image is a signature, PutImageManifest fails", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
					PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
					GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
						configBlob, err := json.Marshal(ispec.Image{})
						So(err, ShouldBeNil)

						return configBlob, nil
					},
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", ErrTestError
					},
					DeleteImageManifestFn: func(repo, reference string, dc bool) error {
						return nil
					},
					GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
						return []byte("{}"), "1", "1", nil
					},
				}

				ctlr.MetaDB = mocks.MetaDBMock{
					RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest,
					) error {
						return ErrTestError
					},
				}

				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" +
					"343ebab94a7674da181c6ea3da013aee4f8cbe357870f8dcaf6268d5343c3474.sig")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func TestSearchSize(t *testing.T) {
	Convey("Repo sizes", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		tr := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &tr}},
		}

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		repoName := "testrepo"
		uploadedImage := CreateImageWith().RandomLayers(1, 10000).DefaultConfig().Build()

		configSize := uploadedImage.ConfigDescriptor.Size
		manifestSize := uploadedImage.ManifestDescriptor.Size
		layersSize := int64(0)

		for _, l := range uploadedImage.Layers {
			layersSize += int64(len(l))
		}

		err := UploadImage(uploadedImage, baseURL, repoName, "latest")
		So(err, ShouldBeNil)

		query := `
		{
			GlobalSearch(query:"testrepo:"){
				Images {
					RepoName Tag LastUpdated Size Vendor
					Manifests{
						Platform { Os Arch }
						LastUpdated Size
					}
				}
				Repos {
					Name LastUpdated Size
					NewestImage {
						Manifests{
							Platform { Os Arch }
							LastUpdated Size
						}
					}
				}
			}
		}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct := &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		image := responseStruct.GlobalSearchResult.GlobalSearch.Images[0]
		So(image.Tag, ShouldResemble, "latest")

		size, err := strconv.Atoi(image.Size)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, configSize+layersSize+manifestSize)

		query = `
		{
			GlobalSearch(query:"testrepo"){
				Images {
					RepoName Tag LastUpdated Size
					Manifests{
						Platform { Os Arch }
						LastUpdated Size
					}
				}
				Repos {
					Name LastUpdated Size
					NewestImage {
						Manifests{
							Platform { Os Arch }
							LastUpdated Size
						}
					}
				}
			}
		}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		repo := responseStruct.GlobalSearchResult.GlobalSearch.Repos[0]
		size, err = strconv.Atoi(repo.Size)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, configSize+layersSize+manifestSize)

		// add the same image with different tag
		err = UploadImage(uploadedImage, baseURL, repoName, "10.2.14")
		So(err, ShouldBeNil)

		// query for images
		query = `
		{
			GlobalSearch(query:"testrepo:"){
				Images {
					RepoName Tag LastUpdated Size
					Manifests{
						Platform { Os Arch }
						LastUpdated Size
					}
				}
				Repos {
					Name LastUpdated Size
					NewestImage {
						Manifests{
							Platform { Os Arch }
							LastUpdated Size
						}
					}
				}
				Layers { Digest Size }
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.Images), ShouldEqual, 2)
		// check that the repo size is the same
		// query for repos
		query = `
		{
			GlobalSearch(query:"testrepo"){
				Images {
					RepoName Tag LastUpdated Size
					Manifests{
						Platform { Os Arch }
						LastUpdated Size
					}
				}
				Repos {
					Name LastUpdated Size
					NewestImage {
						Manifests{
							Platform { Os Arch }
							LastUpdated Size
						}
					}
				}
				Layers { Digest Size }
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		repo = responseStruct.GlobalSearchResult.GlobalSearch.Repos[0]
		size, err = strconv.Atoi(repo.Size)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, configSize+layersSize+manifestSize)
	})
}

func TestImageSummary(t *testing.T) {
	Convey("GraphQL query ImageSummary", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = false

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		gqlQuery := `
			{
				Image(image:"%s:%s"){
					RepoName
					Tag
					Digest
					MediaType
					Manifests {
						Digest
						ConfigDigest
						LastUpdated
						Size
						Platform { Os Arch }
						Layers { Digest Size }
						Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
						History {
							HistoryDescription { Created }
							Layer { Digest Size }
						}
					}
					LastUpdated
					Size
					Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
					Referrers {MediaType ArtifactType Digest Annotations {Key Value}}
				}
			}`

		noTagQuery := `
			{
				Image(image:"%s"){
					RepoName,
					Tag,
					Digest,
					MediaType,
					Manifests {
						Digest
						ConfigDigest
						LastUpdated
						Size
						Platform { Os Arch }
						Layers { Digest Size }
						Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
						History {
							HistoryDescription { Created }
							Layer { Digest Size }
						}
					},
					Size
				}
			}`

		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, graphqlQueryPrefix)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		repoName := "test-repo" //nolint:goconst
		tagTarget := "latest"

		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)

		image := CreateImageWith().RandomLayers(1, 100).ImageConfig(ispec.Image{
			History: []ispec.History{{Created: &createdTime}},
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		}).Build()

		manifestDigest := image.ManifestDescriptor.Digest

		err := UploadImage(image, baseURL, repoName, tagTarget)
		So(err, ShouldBeNil)

		// ------ Add a referrer
		referrerImage := CreateImageWith().RandomLayers(1, 100).
			CustomConfigBlob(
				[]byte{},
				"application/test.artifact.type",
			).
			Subject(&ispec.Descriptor{
				Digest:    manifestDigest,
				MediaType: ispec.MediaTypeImageManifest,
			}).Annotations(map[string]string{"testAnnotationKey": "testAnnotationValue"}).
			Build()

		referrerManifestDigest := referrerImage.Digest()

		err = UploadImage(referrerImage, baseURL, repoName, referrerManifestDigest.String())
		So(err, ShouldBeNil)

		var (
			imgSummaryResponse zcommon.ImageSummaryResult
			strQuery           string
			targetURL          string
			resp               *resty.Response
		)

		t.Log("starting test to retrieve image without reference")
		strQuery = fmt.Sprintf(noTagQuery, repoName)
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))
		contains := false

		resp, err = resty.R().Get(targetURL)

		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)

		for _, err := range imgSummaryResponse.Errors {
			result := strings.Contains(err.Message, "no reference provided")
			if result {
				contains = result
			}
		}

		So(contains, ShouldBeTrue)

		t.Log("starting Test retrieve image based on image identifier")
		// gql is parametrized with the repo.
		strQuery = fmt.Sprintf(gqlQuery, repoName, tagTarget)
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repoName)
		So(imgSummary.Tag, ShouldContainSubstring, tagTarget)
		So(imgSummary.Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.MediaType, ShouldContainSubstring, ispec.MediaTypeImageManifest)
		So(imgSummary.Manifests[0].ConfigDigest, ShouldContainSubstring, image.Manifest.Config.Digest.Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(len(imgSummary.Manifests[0].Layers), ShouldEqual, 1)
		So(imgSummary.Manifests[0].Layers[0].Digest, ShouldContainSubstring,
			image.Manifest.Layers[0].Digest.Encoded())
		So(imgSummary.LastUpdated, ShouldEqual, createdTime)
		So(imgSummary.IsSigned, ShouldEqual, false)
		So(imgSummary.Manifests[0].Platform.Os, ShouldEqual, "linux")
		So(imgSummary.Manifests[0].Platform.Arch, ShouldEqual, "amd64")
		So(len(imgSummary.Manifests[0].History), ShouldEqual, 1)
		So(imgSummary.Manifests[0].History[0].HistoryDescription.Created, ShouldEqual, createdTime)
		// No vulnerabilities should be detected since trivy is disabled
		So(imgSummary.Vulnerabilities.Count, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.UnknownCount, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.LowCount, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.MediumCount, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.HighCount, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.CriticalCount, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")
		So(len(imgSummary.Referrers), ShouldEqual, 1)
		So(imgSummary.Referrers[0], ShouldResemble, zcommon.Referrer{
			MediaType:    ispec.MediaTypeImageManifest,
			ArtifactType: "application/test.artifact.type",
			Digest:       referrerManifestDigest.String(),
			Annotations:  []zcommon.Annotation{{Key: "testAnnotationKey", Value: "testAnnotationValue"}},
		})

		t.Log("starting Test retrieve duplicated image same layers based on image identifier")
		// gqlEndpoint
		strQuery = fmt.Sprintf(gqlQuery, "wrong-repo-does-not-exist", "latest")
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)

		So(len(imgSummaryResponse.Errors), ShouldEqual, 1)
		So(imgSummaryResponse.Errors[0].Message,
			ShouldContainSubstring, "repo metadata not found for given repo name")

		t.Log("starting Test retrieve image with bad tag")
		// gql is parametrized with the repo.
		strQuery = fmt.Sprintf(gqlQuery, repoName, "nonexisttag")
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)

		So(len(imgSummaryResponse.Errors), ShouldEqual, 1)
		So(imgSummaryResponse.Errors[0].Message,
			ShouldContainSubstring, "can't find image: test-repo:nonexisttag")
	})

	Convey("GraphQL query ImageSummary with Vulnerability scan enabled", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		defaultVal := true
		updateDuration, _ := time.ParseDuration("1h")
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
			Trivy:          trivyConfig,
		}
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		ctlr := api.NewController(conf)

		gqlQuery := `
			{
				Image(image:"%s:%s"){
					RepoName
					Tag
					Manifests {
						Digest
						ConfigDigest
						LastUpdated
						Size
						Platform { Os Arch }
						Layers { Digest Size }
						Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
						History {
							HistoryDescription { Created }
							Layer { Digest Size }
						}
					}
					LastUpdated
					Size
					Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
				}
			}`

		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, graphqlQueryPrefix)

		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)

		image := CreateImageWith().DefaultLayers().ImageConfig(ispec.Image{
			History: []ispec.History{{Created: &createdTime}},
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		}).Build()

		manifestDigest := image.ManifestDescriptor.Digest
		configDigest := image.ConfigDescriptor.Digest

		if err := ctlr.Init(); err != nil {
			panic(err)
		}

		ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		WaitTillServerReady(baseURL)

		repoName := "test-repo" //nolint:goconst
		tagTarget := "latest"
		err := UploadImage(image, baseURL, repoName, tagTarget)
		So(err, ShouldBeNil)

		var (
			imgSummaryResponse zcommon.ImageSummaryResult
			strQuery           string
			targetURL          string
			resp               *resty.Response
		)

		t.Log("starting Test retrieve image based on image identifier")
		// gql is parametrized with the repo.
		strQuery = fmt.Sprintf(gqlQuery, repoName, tagTarget)
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)

		imgSummary := imgSummaryResponse.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repoName)
		So(imgSummary.Tag, ShouldContainSubstring, tagTarget)
		So(imgSummary.Manifests[0].ConfigDigest, ShouldContainSubstring, configDigest.Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(len(imgSummary.Manifests[0].Layers), ShouldEqual, 3)
		So(imgSummary.Manifests[0].Layers[0].Digest, ShouldContainSubstring,
			godigest.FromBytes(image.Layers[0]).Encoded())
		So(imgSummary.LastUpdated, ShouldEqual, createdTime)
		So(imgSummary.IsSigned, ShouldEqual, false)
		So(imgSummary.Manifests[0].Platform.Os, ShouldEqual, "linux")
		So(imgSummary.Manifests[0].Platform.Arch, ShouldEqual, "amd64")
		So(len(imgSummary.Manifests[0].History), ShouldEqual, 1)
		So(imgSummary.Manifests[0].History[0].HistoryDescription.Created, ShouldEqual, createdTime)
		So(imgSummary.Vulnerabilities.Count, ShouldEqual, 4)
		So(imgSummary.Vulnerabilities.UnknownCount, ShouldEqual, 0)
		So(imgSummary.Vulnerabilities.LowCount, ShouldEqual, 1)
		So(imgSummary.Vulnerabilities.MediumCount, ShouldEqual, 1)
		So(imgSummary.Vulnerabilities.HighCount, ShouldEqual, 1)
		So(imgSummary.Vulnerabilities.CriticalCount, ShouldEqual, 1)
		// There are 0 vulnerabilities this data used in tests
		So(imgSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")
	})

	Convey("GraphQL query for Artifact Type", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = false

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		query := `
			{
				Image(image:"repo:art%d"){
					RepoName
					Tag
					Manifests {
						Digest
						ArtifactType
					}
					Size
				}
			}`

		queryImg1 := fmt.Sprintf(query, 1)
		queryImg2 := fmt.Sprintf(query, 2)

		var imgSummaryResponse zcommon.ImageSummaryResult

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// upload the images
		artType1 := "application/test.signature.v1"
		artType2 := "application/test.signature.v2"

		img1 := CreateImageWith().RandomLayers(1, 20).EmptyConfig().ArtifactType(artType1).Build()

		err := UploadImage(img1, baseURL, "repo", "art1")
		So(err, ShouldBeNil)

		img2 := CreateImageWith().RandomLayers(1, 20).DefaultConfig().ArtifactType(artType2).Build()

		err = UploadImage(img2, baseURL, "repo", "art2")
		So(err, ShouldBeNil)

		// GET image 1
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryImg1))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)

		imgSum := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(len(imgSum.Manifests), ShouldEqual, 1)
		So(imgSum.Manifests[0].ArtifactType, ShouldResemble, artType1)

		// GET image 2
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryImg2))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)

		imgSum = imgSummaryResponse.SingleImageSummary.ImageSummary
		So(len(imgSum.Manifests), ShouldEqual, 1)
		So(imgSum.Manifests[0].ArtifactType, ShouldResemble, artType2)

		// Expanded repo info test

		queryExpRepoInfo := `{
			ExpandedRepoInfo(repo:"test1"){
				Images {
					Tag
					Manifests {
						Digest
						ArtifactType
					}
				}
			}
		}`

		var expandedRepoInfoResp zcommon.ExpandedRepoInfoResp

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" +
			url.QueryEscape(queryExpRepoInfo))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &expandedRepoInfoResp)
		So(err, ShouldBeNil)

		imgSums := expandedRepoInfoResp.ExpandedRepoInfo.RepoInfo.ImageSummaries

		for _, imgSum := range imgSums {
			switch imgSum.Digest {
			case img1.ManifestDescriptor.Digest.String():
				So(imgSum.Manifests[0].ArtifactType, ShouldResemble, artType1)
			case img2.ManifestDescriptor.Digest.String():
				So(imgSum.Manifests[0].ArtifactType, ShouldResemble, artType2)
			}
		}
	})
}

func TestUploadingArtifactsWithDifferentMediaType(t *testing.T) {
	Convey("", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = false

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}, CVE: nil},
		}
		conf.Log = &config.LogConfig{Level: "debug", Output: "/dev/null"}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		const customMediaType = "application/custom.media.type+json"

		imageWithIncompatibleConfig := CreateImageWith().DefaultLayers().
			CustomConfigBlob([]byte(`{"author": {"key": "val"}}`), customMediaType).Build()

		defaultImage := CreateDefaultImage()

		var configContent ispec.Image
		err := json.Unmarshal(imageWithIncompatibleConfig.ConfigDescriptor.Data, &configContent)
		So(err, ShouldNotBeNil)

		err = UploadImage(imageWithIncompatibleConfig, baseURL, "repo", "incompatible-image")
		So(err, ShouldBeNil)

		err = UploadImage(defaultImage, baseURL, "repo", "default-image")
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"repo:incompatible-image"){
					Images {
						RepoName Tag
						Manifests {
							Digest ConfigDigest
						}
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &zcommon.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.Images), ShouldEqual, 1)
		So(responseStruct.Images[0].Manifests[0].Digest, ShouldResemble,
			imageWithIncompatibleConfig.ManifestDescriptor.Digest.String())
		So(responseStruct.Images[0].Manifests[0].ConfigDigest, ShouldResemble,
			imageWithIncompatibleConfig.ConfigDescriptor.Digest.String())
	})
}

func TestReadUploadDeleteDynamoDB(t *testing.T) {
	tskip.SkipDynamo(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	cacheTablename := "BlobTable" + uuid.String()
	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	imageMetaTablename := "ImageMeta" + uuid.String()
	repoBlobsTablename := "RepoBlobs" + uuid.String()

	cacheDriverParams := map[string]any{
		"name":                   "dynamodb",
		"endpoint":               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
		"region":                 "us-east-2",
		"cachetablename":         cacheTablename,
		"repometatablename":      repoMetaTablename,
		"imagemetatablename":     imageMetaTablename,
		"repoblobsinfotablename": repoBlobsTablename,
		"userdatatablename":      userDataTablename,
		"apikeytablename":        apiKeyTablename,
		"versiontablename":       versionTablename,
	}

	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = t.TempDir()
	conf.Storage.GC = false
	conf.Storage.CacheDriver = cacheDriverParams
	conf.Storage.RemoteCache = true
	conf.Log = &config.LogConfig{Level: "debug", Output: "/dev/null"}

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}, CVE: nil},
	}

	ctlr := api.NewController(conf)
	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)
	defer ctlrManager.StopServer()

	RunReadUploadDeleteTests(t, baseURL)
}

func TestReadUploadDeleteBoltDB(t *testing.T) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = t.TempDir()
	conf.Storage.GC = false
	conf.Log = &config.LogConfig{Level: "debug", Output: "/dev/null"}

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}, CVE: nil},
	}

	ctlr := api.NewController(conf)
	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)
	defer ctlrManager.StopServer()

	RunReadUploadDeleteTests(t, baseURL)
}

func RunReadUploadDeleteTests(t *testing.T, baseURL string) {
	t.Helper()

	repo1 := "repo1"
	image := CreateRandomImage()
	tag1 := "tag1"

	imageWithoutTag := CreateRandomImage()

	usedImages := []repoRef{
		{repo1, tag1},
		{repo1, imageWithoutTag.DigestStr()},
	}

	Convey("Push-Read-Delete", t, func() {
		results := GlobalSearchGQL("", baseURL)
		So(len(results.Images), ShouldEqual, 0)
		So(len(results.Repos), ShouldEqual, 0)

		Convey("Push an image without tag", func() {
			err := UploadImage(imageWithoutTag, baseURL, repo1, imageWithoutTag.DigestStr())
			So(err, ShouldBeNil)

			results := GlobalSearchGQL("", baseURL)
			So(len(results.Repos), ShouldEqual, 0)

			Convey("Add tag and delete it", func() {
				err := UploadImage(image, baseURL, repo1, tag1)
				So(err, ShouldBeNil)

				results := GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 1)

				status, err := DeleteImage(repo1, tag1, baseURL)
				So(status, ShouldEqual, http.StatusAccepted)
				So(err, ShouldBeNil)

				results = GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 0)
			})
		})
		Convey("Push a random image", func() {
			err := UploadImage(image, baseURL, repo1, tag1)
			So(err, ShouldBeNil)

			results := GlobalSearchGQL("", baseURL)
			So(len(results.Repos), ShouldEqual, 1)

			Convey("Delete the image pushed", func() {
				status, err := DeleteImage(repo1, tag1, baseURL)
				So(status, ShouldEqual, http.StatusAccepted)
				So(err, ShouldBeNil)

				results := GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 0)

				Convey("Push an image without tag", func() {
					err := UploadImage(imageWithoutTag, baseURL, repo1, imageWithoutTag.DigestStr())
					So(err, ShouldBeNil)

					results := GlobalSearchGQL("", baseURL)
					So(len(results.Repos), ShouldEqual, 0)
				})
			})
			Convey("Delete the image pushed multiple times", func() {
				for range 3 {
					status, err := DeleteImage(repo1, tag1, baseURL)
					So(status, ShouldBeIn, []int{http.StatusAccepted, http.StatusNotFound, http.StatusBadRequest})
					So(err, ShouldBeNil)

					results := GlobalSearchGQL("", baseURL)
					So(len(results.Repos), ShouldEqual, 0)
				}
			})
			Convey("Upload same image multiple times", func() {
				for range 3 {
					err := UploadImage(image, baseURL, repo1, tag1)
					So(err, ShouldBeNil)
				}

				results := GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 1)
			})
		})

		deleteUsedImages(usedImages, baseURL)
	})

	// Images with create time
	repoLatest := "repo-latest"

	afterImage := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2010, 1, 1, 1, 1, 1, 0, time.UTC)}).Build()
	tagAfter := "after"

	middleImage := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2005, 1, 1, 1, 1, 1, 0, time.UTC)}).Build()
	tagMiddle := "middle"

	beforeImage := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2000, 1, 1, 1, 1, 1, 0, time.UTC)}).Build()
	tagBefore := "before"

	imageWithoutTag = CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2020, 1, 1, 1, 1, 1, 0, time.UTC)}).Build()

	imageWithoutCreateTime := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: nil}).Build()
	tagWithoutTime := "without-time"

	usedImages = []repoRef{
		{repoLatest, tagAfter},
		{repoLatest, tagMiddle},
		{repoLatest, tagBefore},
		{repoLatest, tagWithoutTime},
		{repoLatest, imageWithoutTag.DigestStr()},
	}

	Convey("Last Updated Image", t, func() {
		results := GlobalSearchGQL("", baseURL)
		So(len(results.Images), ShouldEqual, 0)
		So(len(results.Repos), ShouldEqual, 0)

		Convey("Without time", func() {
			err := UploadImage(imageWithoutCreateTime, baseURL, repoLatest, tagWithoutTime)
			So(err, ShouldBeNil)

			results := GlobalSearchGQL("", baseURL)
			So(len(results.Repos), ShouldEqual, 1)
			So(results.Repos[0].NewestImage.Digest, ShouldResemble, imageWithoutCreateTime.DigestStr())

			Convey("Add an image with create time and delete it", func() {
				err := UploadImage(beforeImage, baseURL, repoLatest, tagBefore)
				So(err, ShouldBeNil)

				results := GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 1)
				So(results.Repos[0].NewestImage.Digest, ShouldResemble, beforeImage.DigestStr())

				status, err := DeleteImage(repoLatest, tagBefore, baseURL)
				So(status, ShouldEqual, http.StatusAccepted)
				So(err, ShouldBeNil)

				results = GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 1)
				So(results.Repos[0].NewestImage.Digest, ShouldResemble, imageWithoutCreateTime.DigestStr())
			})
		})
		Convey("Upload middle image", func() {
			err := UploadImage(middleImage, baseURL, repoLatest, tagMiddle)
			So(err, ShouldBeNil)

			results := GlobalSearchGQL("", baseURL)
			So(len(results.Repos), ShouldEqual, 1)
			So(results.Repos[0].NewestImage.Digest, ShouldResemble, middleImage.DigestStr())

			Convey("Upload an image created before", func() {
				err := UploadImage(beforeImage, baseURL, repoLatest, tagBefore)
				So(err, ShouldBeNil)

				results := GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 1)
				So(results.Repos[0].NewestImage.Digest, ShouldResemble, middleImage.DigestStr())

				Convey("Upload an image created after", func() {
					err := UploadImage(afterImage, baseURL, repoLatest, tagAfter)
					So(err, ShouldBeNil)

					results := GlobalSearchGQL("", baseURL)
					So(len(results.Repos), ShouldEqual, 1)
					So(results.Repos[0].NewestImage.Digest, ShouldResemble, afterImage.DigestStr())

					Convey("Delete middle then after", func() {
						status, err := DeleteImage(repoLatest, tagMiddle, baseURL)
						So(status, ShouldEqual, http.StatusAccepted)
						So(err, ShouldBeNil)

						results := GlobalSearchGQL("", baseURL)
						So(len(results.Repos), ShouldEqual, 1)
						So(results.Repos[0].NewestImage.Digest, ShouldResemble, afterImage.DigestStr())

						status, err = DeleteImage(repoLatest, tagAfter, baseURL)
						So(status, ShouldEqual, http.StatusAccepted)
						So(err, ShouldBeNil)

						results = GlobalSearchGQL("", baseURL)
						So(len(results.Repos), ShouldEqual, 1)
						So(results.Repos[0].NewestImage.Digest, ShouldResemble, beforeImage.DigestStr())
					})
				})
			})
			Convey("Upload an image created after", func() {
				err := UploadImage(afterImage, baseURL, repoLatest, tagAfter)
				So(err, ShouldBeNil)

				results := GlobalSearchGQL("", baseURL)
				So(len(results.Repos), ShouldEqual, 1)
				So(results.Repos[0].NewestImage.Digest, ShouldResemble, afterImage.DigestStr())

				Convey("Add newer image without tag", func() {
					err := UploadImage(imageWithoutTag, baseURL, repoLatest, imageWithoutTag.DigestStr())
					So(err, ShouldBeNil)

					results := GlobalSearchGQL("", baseURL)
					So(len(results.Repos), ShouldEqual, 1)
					So(results.Repos[0].NewestImage.Digest, ShouldResemble, afterImage.DigestStr())
				})

				Convey("Delete afterImage", func() {
					status, err := DeleteImage(repoLatest, tagAfter, baseURL)
					So(status, ShouldEqual, http.StatusAccepted)
					So(err, ShouldBeNil)

					results := GlobalSearchGQL("", baseURL)
					So(len(results.Repos), ShouldEqual, 1)
					So(results.Repos[0].NewestImage.Digest, ShouldResemble, middleImage.DigestStr())
				})
			})
		})

		deleteUsedImages(usedImages, baseURL)
	})
}

type repoRef struct {
	Repo string
	Tag  string
}

func TestSearchWithMissingManifest(t *testing.T) {
	Convey("Search with missing manifest", t, func() {
		dir := t.TempDir()

		// 1. Write the image to the disk
		log := log.NewTestLogger()
		storeCtlr := ociutils.GetDefaultStoreController(dir, log)

		// Create a multiarch image with exactly 2 manifests
		multiarchImage := CreateMultiarchWith().RandomImages(2).Build()

		// Write the multiarch image to filesystem
		err := WriteMultiArchImageToFileSystem(multiarchImage, "testrepo", "latest", storeCtlr)
		So(err, ShouldBeNil)

		// Get the image store to access index and manifests
		imageStore := storeCtlr.GetDefaultImageStore()

		// Get the index content to find all manifest digests
		indexBlob, err := imageStore.GetIndexContent("testrepo")
		So(err, ShouldBeNil)

		var indexContent ispec.Index
		err = json.Unmarshal(indexBlob, &indexContent)
		So(err, ShouldBeNil)

		So(len(indexContent.Manifests), ShouldBeGreaterThanOrEqualTo, 2)

		// Get the first manifest digest to delete
		firstManifestDigest := indexContent.Manifests[0].Digest

		// Get the second manifest digest (should remain valid)
		secondManifestDigest := indexContent.Manifests[1].Digest

		// 2. Delete the manifest from the disk
		manifestBlobPath := path.Join(dir, "testrepo", "blobs", "sha256", firstManifestDigest.Encoded())
		err = os.Remove(manifestBlobPath)
		So(err, ShouldBeNil)

		// 3. Start the controller (MetaDB parsing would be done in the background)
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// Search for the repository
		query := `
		{
			GlobalSearch(query:"testrepo:latest"){
				Images {
					RepoName Tag
					Manifests {
						Digest
					}
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := &zcommon.GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		// Verify we found the image
		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeEmpty)
		foundImage := responseStruct.GlobalSearchResult.GlobalSearch.Images[0]
		So(foundImage.RepoName, ShouldEqual, "testrepo")
		So(foundImage.Tag, ShouldEqual, "latest")

		// Verify only the valid manifest is found in search results (missing one was skipped by ParseStorage)
		So(len(foundImage.Manifests), ShouldEqual, 1)
		So(foundImage.Manifests[0].Digest, ShouldEqual, secondManifestDigest.String())
	})
}

func deleteUsedImages(repoTags []repoRef, baseURL string) {
	for _, image := range repoTags {
		status, err := DeleteImage(image.Repo, image.Tag, baseURL)
		So(status, ShouldBeIn, []int{http.StatusAccepted, http.StatusNotFound, http.StatusBadRequest})
		So(err, ShouldBeNil)
	}
}

func GlobalSearchGQL(query, baseURL string) *zcommon.GlobalSearchResultResp {
	queryStr := `
	{
		GlobalSearch(query:"` + query + `"){
			Images {
				RepoName Tag Digest MediaType Size DownloadCount LastUpdated IsSigned
				Description Licenses Labels Title Source Documentation Authors Vendor
				Manifests {
					Digest ConfigDigest LastUpdated Size IsSigned
					DownloadCount
					SignatureInfo {Tool IsTrusted Author}
					Platform {Os Arch}
					Layers {Size Digest}
					History {
						Layer { Size Digest }
						HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
					}
					Vulnerabilities {Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity}
					Referrers {MediaType ArtifactType Size Digest Annotations {Key Value}}
				}
				Referrers {MediaType ArtifactType Size Digest Annotations {Key Value}}
				Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
				SignatureInfo {Tool IsTrusted Author}
			}
			Repos {
				Name LastUpdated Size DownloadCount StarCount IsBookmarked IsStarred
				Platforms { Os Arch }
				Vendors
				NewestImage {
					RepoName Tag Digest MediaType Size DownloadCount LastUpdated IsSigned
					Description Licenses Labels Title Source Documentation Authors Vendor
					Manifests {
						Digest ConfigDigest LastUpdated Size IsSigned
						DownloadCount
						SignatureInfo {Tool IsTrusted Author}
						Platform {Os Arch}
						Layers {Size Digest}
						History {
							Layer { Size Digest }
							HistoryDescription { Author Comment Created CreatedBy EmptyLayer }
						}
						Vulnerabilities {Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity}
						Referrers {MediaType ArtifactType Size Digest Annotations {Key Value}}
					}
					Referrers {MediaType ArtifactType Size Digest Annotations {Key Value}}
					Vulnerabilities { Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity }
					SignatureInfo {Tool IsTrusted Author}
				}
			}
		}
	}`

	resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(queryStr))
	So(resp, ShouldNotBeNil)
	So(err, ShouldBeNil)
	So(resp.StatusCode(), ShouldEqual, 200)

	responseStruct := &zcommon.GlobalSearchResultResp{}

	err = json.Unmarshal(resp.Body(), responseStruct)
	So(err, ShouldBeNil)

	return responseStruct
}
