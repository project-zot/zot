//go:build sync

package sync_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func writeAssertionFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	assertionFile := filepath.Join(dir, "assertion.jwt")

	if err := os.WriteFile(assertionFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write assertion file: %v", err)
	}

	return assertionFile
}

func TestOAuth2CredentialsHelper(t *testing.T) {
	Convey("Test OAuth2 Credentials Helper", t, func() {
		registryURL := "https://registry.example.com"
		remoteAddress := sync.StripRegistryTransport(registryURL)
		assertionFile := writeAssertionFile(t, "the-jwt-assertion")

		Convey("Validation of required fields", func() {
			_, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(), nil)
			So(err, ShouldNotBeNil)

			_, err = sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{AssertionFile: assertionFile})
			So(err, ShouldNotBeNil)

			_, err = sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{TokenURL: "https://idp.example.com/token"})
			So(err, ShouldNotBeNil)
		})

		Convey("Token retrieval, validity and refresh", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","token_type":"Bearer","expires_in":3600}`))
			}))
			defer server.Close()

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:      server.URL,
					AssertionFile: assertionFile,
					ClientID:      "the-client",
					Scopes:        []string{"repository:pull"},
				})
			So(err, ShouldBeNil)

			creds, err := credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(creds[remoteAddress].Username, ShouldEqual, "<token>")
			So(creds[remoteAddress].Password, ShouldEqual, "the-access-token")
			So(credentialHelper.AreCredentialsValid(remoteAddress), ShouldBeTrue)

			// the assertion file contents must be sent as a client_assertion by default
			So(receivedBody.Get("grant_type"), ShouldEqual, "client_credentials")
			So(receivedBody.Get("client_assertion"), ShouldEqual, "the-jwt-assertion")
			So(receivedBody.Get("client_id"), ShouldEqual, "the-client")
			So(receivedBody.Get("scope"), ShouldEqual, "repository:pull")

			refreshed, err := credentialHelper.RefreshCredentials(remoteAddress)
			So(err, ShouldBeNil)
			So(refreshed.Password, ShouldEqual, "the-access-token")
		})

		Convey("jwt-bearer grant sends the assertion parameter", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			secretFile := filepath.Join(t.TempDir(), "client-secret")
			So(os.WriteFile(secretFile, []byte("the-secret\n"), 0o600), ShouldBeNil)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:         server.URL,
					AssertionFile:    assertionFile,
					GrantType:        "urn:ietf:params:oauth:grant-type:jwt-bearer",
					ClientID:         "the-client",
					ClientSecretFile: secretFile,
					Username:         "robot",
				})
			So(err, ShouldBeNil)

			creds, err := credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(creds[remoteAddress].Username, ShouldEqual, "robot")
			So(receivedBody.Get("grant_type"), ShouldEqual, "urn:ietf:params:oauth:grant-type:jwt-bearer")
			So(receivedBody.Get("assertion"), ShouldEqual, "the-jwt-assertion")
			So(receivedBody.Get("client_id"), ShouldEqual, "the-client")
			So(receivedBody.Get("client_secret"), ShouldEqual, "the-secret")
		})

		Convey("Client secret is read from a file when configured", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			secretFile := filepath.Join(t.TempDir(), "client-secret")
			So(os.WriteFile(secretFile, []byte("file-secret\n"), 0o600), ShouldBeNil)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:         server.URL,
					AssertionFile:    assertionFile,
					ClientSecretFile: secretFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(receivedBody.Get("client_secret"), ShouldEqual, "file-secret")
		})

		Convey("Error on non-200 from the token endpoint", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "invalid_grant", http.StatusBadRequest)
			}))
			defer server.Close()

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, AssertionFile: assertionFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the assertion file is missing", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "https://idp.example.com/token",
					AssertionFile: filepath.Join(t.TempDir(), "does-not-exist.jwt"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token endpoint returns an empty access token", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3600}`))
			}))
			defer server.Close()

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, AssertionFile: assertionFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token endpoint returns invalid JSON", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`not-json`))
			}))
			defer server.Close()

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, AssertionFile: assertionFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token endpoint is unreachable", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "http://127.0.0.1:1/token",
					AssertionFile: assertionFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token URL is malformed", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "http://127.0.0.1\x7f/token",
					AssertionFile: assertionFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the client secret file is missing", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:         "https://idp.example.com/token",
					AssertionFile:    assertionFile,
					ClientSecretFile: filepath.Join(t.TempDir(), "no-secret"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Credentials are invalid when no token is cached or it expired", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "https://idp.example.com/token",
					AssertionFile: assertionFile,
				})
			So(err, ShouldBeNil)

			So(credentialHelper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
		})

		Convey("RefreshCredentials fails when the assertion file is missing", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "https://idp.example.com/token",
					AssertionFile: filepath.Join(t.TempDir(), "does-not-exist.jwt"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.RefreshCredentials(remoteAddress)
			So(err, ShouldNotBeNil)
		})
	})
}
