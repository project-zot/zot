package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// immutableTagCondition is the per-tag policy shown in the immutable-tags article.
const immutableTagCondition = `(req.action != "update" && req.action != "delete") || ` +
	`!(req.tag in ["prod", "latest"] || req.tag.startsWith("release-") || ` +
	`req.tag.matches('^v[0-9]+[.][0-9]+[.][0-9]+$'))`

func TestImmutableTagAccessControl(t *testing.T) {
	conf := config.New()
	conf.Storage.GC = false
	conf.HTTP.Port = "0"

	const (
		alice = "alice"
		carol = "carol"
		admin = "admin"
		repo  = "apps"
	)

	htpasswd := test.GetBcryptCredString(alice, "alice-pass") +
		test.GetBcryptCredString(carol, "carol-pass") +
		test.GetBcryptCredString(admin, "admin-pass")
	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd:  config.AuthHTPasswd{Path: test.MakeHtpasswdFileFromString(t, htpasswd)},
		FailDelay: 0,
	}
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{{
					Users: []string{alice},
					Actions: []string{
						constants.ReadPermission,
						constants.CreatePermission,
						constants.UpdatePermission,
						constants.DeletePermission,
					},
					Conditions: []config.Condition{{
						Expression: immutableTagCondition,
						Message:    "tag is immutable",
					}},
				}},
				DefaultPolicy: []string{constants.ReadPermission, constants.CreatePermission},
			},
		},
		AdminPolicy: config.Policy{
			Users: []string{admin},
			Actions: []string{
				constants.ReadPermission,
				constants.CreatePermission,
				constants.UpdatePermission,
				constants.DeletePermission,
			},
		},
	}

	conf.Storage.RootDirectory = t.TempDir()
	ctlr := api.NewController(conf)
	cm := test.NewControllerManager(ctlr)
	baseURL := cm.StartAndWait()
	t.Cleanup(cm.StopServer)

	aliceClient := resty.New().SetBasicAuth(alice, "alice-pass")
	carolClient := resty.New().SetBasicAuth(carol, "carol-pass")
	adminClient := resty.New().SetBasicAuth(admin, "admin-pass")

	original := image.CreateImageWith().RandomLayers(1, 10).RandomConfig().Build()
	for _, tag := range []string{"prod", "latest", "release-1", "v1.2.3", "dev", "v1.2", "production", "release"} {
		require.NoError(t, image.UploadImageWithBasicAuth(original, baseURL, repo, tag, alice, "alice-pass"))
	}

	replacement := image.CreateImageWith().RandomLayers(1, 12).RandomConfig().Build()
	require.NoError(t, image.UploadImageWithBasicAuth(replacement, baseURL, repo, "scratch", alice, "alice-pass"))
	replacementBody, err := json.Marshal(replacement.Manifest)
	require.NoError(t, err)

	putTag := func(client *resty.Client, tag string) *resty.Response {
		t.Helper()
		resp, err := client.R().
			SetHeader("Content-Type", ispec.MediaTypeImageManifest).
			SetBody(replacementBody).
			Put(baseURL + "/v2/" + repo + "/manifests/" + tag)
		require.NoError(t, err)

		return resp
	}

	for _, tag := range []string{"prod", "latest", "release-1", "v1.2.3"} {
		resp := putTag(aliceClient, tag)
		require.Equal(t, http.StatusForbidden, resp.StatusCode(), tag)
		require.Contains(t, resp.String(), "tag is immutable", tag)

		got, err := aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/" + tag)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, got.StatusCode(), tag)
		require.Equal(t, original.ManifestDescriptor.Digest.String(), got.Header().Get(constants.DistContentDigestKey), tag)
	}

	// adminPolicy grants update and is not subject to the repository condition.
	// latest still names the original manifest, so this put is an update.
	beforeLatest, err := aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/latest")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, beforeLatest.StatusCode())
	require.Equal(t, original.ManifestDescriptor.Digest.String(),
		beforeLatest.Header().Get(constants.DistContentDigestKey))

	adminImage := image.CreateImageWith().RandomLayers(1, 14).RandomConfig().Build()
	require.NoError(t, image.UploadImageWithBasicAuth(
		adminImage, baseURL, repo, "admin-scratch", admin, "admin-pass"))
	adminBody, err := json.Marshal(adminImage.Manifest)
	require.NoError(t, err)
	adminResp, err := adminClient.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(adminBody).
		Put(baseURL + "/v2/" + repo + "/manifests/latest")
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, adminResp.StatusCode(), adminResp.String())

	afterLatest, err := aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/latest")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, afterLatest.StatusCode())
	require.Equal(t, adminImage.ManifestDescriptor.Digest.String(),
		afterLatest.Header().Get(constants.DistContentDigestKey))

	// production is not the exact tag prod. release does not have the release- prefix.
	for _, tag := range []string{"dev", "v1.2", "production", "release"} {
		resp := putTag(aliceClient, tag)
		require.Equal(t, http.StatusCreated, resp.StatusCode(), tag)
	}

	// A repeated put of the same bytes is still an update.
	same, err := aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, same.StatusCode())
	retry, err := aliceClient.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(same.Body()).
		Put(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, retry.StatusCode())
	require.Contains(t, retry.String(), "tag is immutable")

	// Carol can create a tag and cannot retarget one.
	carolImage := image.CreateImageWith().RandomLayers(1, 8).RandomConfig().Build()
	require.NoError(t, image.UploadImageWithBasicAuth(carolImage, baseURL, repo, "carol", carol, "carol-pass"))
	resp := putTag(carolClient, "dev")
	require.Equal(t, http.StatusForbidden, resp.StatusCode())

	// Delete of a mutable tag is still allowed.
	resp, err = aliceClient.R().Delete(baseURL + "/v2/" + repo + "/manifests/dev")
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, resp.StatusCode(), resp.String())
	dev, err := aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/dev")
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, dev.StatusCode())

	// Digest push with ?tag= is checked per tag.
	digestRef := replacement.ManifestDescriptor.Digest.String()
	digestURL, err := url.Parse(baseURL + "/v2/" + repo + "/manifests/" + digestRef)
	require.NoError(t, err)
	digestURL.RawQuery = "tag=prod"
	resp, err = aliceClient.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(replacementBody).
		Put(digestURL.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode())
	require.Contains(t, resp.String(), "tag is immutable")

	digestURL.RawQuery = "tag=scratch"
	resp, err = aliceClient.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(replacementBody).
		Put(digestURL.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode())

	// Delete of the tag name is denied. Delete of the digest URL is not, because req.tag is empty.
	resp, err = aliceClient.R().Delete(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode())
	require.Contains(t, resp.String(), "tag is immutable")

	prod, err := aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, prod.StatusCode())
	prodDigest := prod.Header().Get(constants.DistContentDigestKey)
	require.NotEmpty(t, prodDigest)

	resp, err = aliceClient.R().Delete(baseURL + "/v2/" + repo + "/manifests/" + prodDigest)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, resp.StatusCode(), resp.String())

	prod, err = aliceClient.R().Get(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, prod.StatusCode())
}

// defaultPolicy is checked after a matching policy whose condition returned false, and it has no
// conditions of its own. Listing update there lets Alice retarget prod.
func TestImmutableTagConditionBypassedByDefaultPolicy(t *testing.T) {
	conf := config.New()
	conf.Storage.GC = false
	conf.HTTP.Port = "0"

	const (
		alice = "alice"
		repo  = "apps"
	)

	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{
			Path: test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(alice, "alice-pass")),
		},
		FailDelay: 0,
	}
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{{
					Users: []string{alice},
					Actions: []string{
						constants.ReadPermission,
						constants.CreatePermission,
						constants.UpdatePermission,
						constants.DeletePermission,
					},
					Conditions: []config.Condition{{
						Expression: immutableTagCondition,
						Message:    "tag is immutable",
					}},
				}},
				DefaultPolicy: []string{
					constants.ReadPermission,
					constants.CreatePermission,
					constants.UpdatePermission,
				},
			},
		},
	}

	conf.Storage.RootDirectory = t.TempDir()
	ctlr := api.NewController(conf)
	cm := test.NewControllerManager(ctlr)
	baseURL := cm.StartAndWait()
	t.Cleanup(cm.StopServer)

	original := image.CreateImageWith().RandomLayers(1, 10).RandomConfig().Build()
	require.NoError(t, image.UploadImageWithBasicAuth(original, baseURL, repo, "prod", alice, "alice-pass"))

	replacement := image.CreateImageWith().RandomLayers(1, 12).RandomConfig().Build()
	require.NoError(t, image.UploadImageWithBasicAuth(replacement, baseURL, repo, "scratch", alice, "alice-pass"))
	body, err := json.Marshal(replacement.Manifest)
	require.NoError(t, err)

	client := resty.New().SetBasicAuth(alice, "alice-pass")
	resp, err := client.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(body).
		Put(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode(), resp.String())

	got, err := client.R().Get(baseURL + "/v2/" + repo + "/manifests/prod")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, got.StatusCode())
	require.Equal(t, replacement.ManifestDescriptor.Digest.String(), got.Header().Get(constants.DistContentDigestKey))
}
