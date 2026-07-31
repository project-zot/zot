//go:build search

package search_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	. "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestGetReferrersGqlAuthorization(t *testing.T) {
	Convey("Referrers should not be returned for unauthorized users", t, func() {
		rootDir := t.TempDir()
		adminUserName := "admin"
		adminPassword := "admin123"
		normalUserName := "user"
		normalPassword := "user123"
		adminUserLine := GetBcryptCredString(adminUserName, adminPassword)
		normalUserLine := GetBcryptCredString(normalUserName, normalPassword)
		htpasswdPath := MakeHtpasswdFileFromString(t, adminUserLine+"\n"+normalUserLine)

		conf := config.New()
		conf.HTTP.Port = "0"
		conf.HTTP.Auth.HTPasswd = config.AuthHTPasswd{Path: htpasswdPath}
		conf.Storage.RootDirectory = rootDir
		defaultVal := true

		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"admin/**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"admin"},
							Actions: []string{"create", "read", "delete"},
						},
					},
				},
				"public/**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"admin"},
							Actions: []string{"create", "read", "delete"},
						},
						{
							Users:   []string{"user"},
							Actions: []string{"read"},
						},
					},
				},
			},
		}

		ctlr := api.NewController(conf)

		if err := ctlr.Init(); err != nil {
			t.Fatal(err)
		}

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		cm := NewControllerManager(ctlr)
		cm.WaitServerReady()
		baseURL := cm.BaseURL()

		uploadedImage := CreateDefaultImage()
		err := UploadImageWithBasicAuth(uploadedImage, baseURL, "admin/zot-test", "0.0.1", adminUserName, adminPassword)
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

		err = UploadImageWithBasicAuth(
			artifactImg, baseURL, "admin/zot-test", artifactManifestDigest.String(), adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		query := `{
			Referrers(repo:"admin/zot-test", digest:"` + manifestDigest.String() + `") {
				ArtifactType
				Digest
			}
		}`

		// admin user should be able to get referrer info
		adminClient := resty.New().SetBasicAuth(adminUserName, adminPassword)
		resp, err := adminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.ReferrersResp
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Referrers), ShouldEqual, 1)
		So(responseStruct.Referrers[0].ArtifactType, ShouldEqual, artifactType)
		So(responseStruct.Referrers[0].Digest, ShouldEqual, artifactManifestDigest.String())

		// non-admin user should not be able to get referrer info
		nonAdminClient := resty.New().SetBasicAuth(normalUserName, normalPassword)
		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var nonAdminResponse zcommon.ReferrersResp
		err = json.Unmarshal(resp.Body(), &nonAdminResponse)
		So(err, ShouldBeNil)
		So(len(nonAdminResponse.Referrers), ShouldEqual, 0)

		// upload public image and public artifact referrer
		err = UploadImageWithBasicAuth(uploadedImage, baseURL, "public/open", "0.0.1", adminUserName, adminPassword)
		So(err, ShouldBeNil)

		// update subject descriptor to point to public image
		subjectDescriptor = &ispec.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Size:      manifestSize,
			Digest:    manifestDigest,
		}
		artifactImg.Manifest.Subject = subjectDescriptor

		artifactManifestBlob, err = json.Marshal(artifactImg.Manifest)
		So(err, ShouldBeNil)
		artifactManifestDigest = godigest.FromBytes(artifactManifestBlob)

		err = UploadImageWithBasicAuth(
			artifactImg, baseURL, "public/open", artifactManifestDigest.String(), adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		query = `{
			Referrers(repo:"public/open", digest:"` + manifestDigest.String() + `") {
				ArtifactType
				Digest
			}
		}`

		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var publicResponse zcommon.ReferrersResp
		err = json.Unmarshal(resp.Body(), &publicResponse)
		So(err, ShouldBeNil)
		So(len(publicResponse.Referrers), ShouldEqual, 1)
		So(publicResponse.Referrers[0].ArtifactType, ShouldEqual, artifactType)
		So(publicResponse.Referrers[0].Digest, ShouldEqual, artifactManifestDigest.String())
	})
}
