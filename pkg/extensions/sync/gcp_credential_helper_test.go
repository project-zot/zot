//go:build sync

package sync_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/oauth2"

	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

var (
	errTokenSourceUnavailable = errors.New("metadata server unavailable")
	errTokenMintFailed        = errors.New("no token for you")
)

// mintingTokenSource hands out a different access token on every call, so that a test can
// tell whether the helper asked the source again or reused what it already had.
type mintingTokenSource struct {
	calls  atomic.Int64
	expiry time.Time
}

func (source *mintingTokenSource) Token() (*oauth2.Token, error) {
	count := source.calls.Add(1)

	expiry := source.expiry
	if expiry.IsZero() {
		expiry = time.Now().Add(time.Hour)
	}

	return &oauth2.Token{
		AccessToken: "access-token-" + strconv.FormatInt(count, 10),
		TokenType:   "Bearer",
		Expiry:      expiry,
	}, nil
}

func newHelper(source oauth2.TokenSource) sync.CredentialHelper {
	return sync.NewGCPCredentialHelper(log.NewTestLogger(),
		func(_ context.Context) (oauth2.TokenSource, error) { return source, nil })
}

func TestGCPCredentialHelper(t *testing.T) {
	const remoteAddress = "us-central1-docker.pkg.dev"

	Convey("The access token is paired with the username Artifact Registry expects", t, func() {
		source := &mintingTokenSource{}
		helper := newHelper(source)

		credentials, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(credentials[remoteAddress].Username, ShouldEqual, "oauth2accesstoken")
		So(credentials[remoteAddress].Password, ShouldEqual, "access-token-1")
	})

	Convey("No token is fetched when there are no registries", t, func() {
		source := &mintingTokenSource{}
		helper := newHelper(source)

		credentials, err := helper.GetCredentials(nil)
		So(err, ShouldBeNil)
		So(credentials, ShouldNotBeNil)
		So(credentials, ShouldBeEmpty)
		So(source.calls.Load(), ShouldEqual, 0)
	})

	Convey("A failed fetch still yields a usable map", t, func() {
		helper := newHelper(failingTokenSource{})

		credentials, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldNotBeNil)
		So(credentials, ShouldNotBeNil) // the service writes into this map later
	})

	Convey("Every requested registry gets the same token", t, func() {
		source := &mintingTokenSource{}
		helper := newHelper(source)

		credentials, err := helper.GetCredentials([]string{
			"https://us-central1-docker.pkg.dev",
			"https://europe-west1-docker.pkg.dev",
		})
		So(err, ShouldBeNil)
		So(credentials["us-central1-docker.pkg.dev"].Password,
			ShouldEqual, credentials["europe-west1-docker.pkg.dev"].Password)
		So(source.calls.Load(), ShouldEqual, 1)
	})

	Convey("Credentials stay valid while the source returns the same token", t, func() {
		token := &oauth2.Token{AccessToken: "stable", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
		helper := newHelper(oauth2.StaticTokenSource(token))

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(helper.AreCredentialsValid(remoteAddress), ShouldBeTrue)
	})

	/* A fixed expiry window would call the token invalid well before the source rotates it,
	and rebuild the registry client on every sync operation in between. */
	Convey("A token that is close to expiring is still valid until it is rotated", t, func() {
		token := &oauth2.Token{AccessToken: "nearly-due", TokenType: "Bearer", Expiry: time.Now().Add(time.Second)}
		helper := newHelper(oauth2.StaticTokenSource(token))

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(helper.AreCredentialsValid(remoteAddress), ShouldBeTrue)
	})

	Convey("Credentials become invalid once the source rotates the token", t, func() {
		// an expiry inside the reuse window makes the wrapped source mint a token every time
		helper := newHelper(&mintingTokenSource{expiry: time.Now().Add(time.Second)})

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(helper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
	})

	Convey("An address that was never fetched is not valid", t, func() {
		helper := newHelper(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "stable"}))

		So(helper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
	})

	Convey("A refresh hands back the current token", t, func() {
		source := &mintingTokenSource{expiry: time.Now().Add(time.Second)}
		helper := newHelper(source)

		credentials, err := helper.RefreshCredentials(remoteAddress)
		So(err, ShouldBeNil)
		So(credentials.Username, ShouldEqual, "oauth2accesstoken")
		So(credentials.Password, ShouldEqual, "access-token-1")
		So(helper.AreCredentialsValid(remoteAddress), ShouldBeFalse) // the next call mints another one
	})

	Convey("A token source that cannot be built is reported, not cached", t, func() {
		var attempts atomic.Int64

		helper := sync.NewGCPCredentialHelper(log.NewTestLogger(),
			func(_ context.Context) (oauth2.TokenSource, error) {
				if attempts.Add(1) == 1 {
					return nil, errTokenSourceUnavailable
				}

				return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "late"}), nil
			})

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldNotBeNil)

		// the failure must not disable the helper for good
		credentials, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(credentials[remoteAddress].Password, ShouldEqual, "late")
	})

	Convey("Credentials are not valid when the token cannot be read", t, func() {
		helper := newHelper(&flakyTokenSource{})

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(helper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
	})

	Convey("A token source that fails to mint is reported", t, func() {
		helper := newHelper(failingTokenSource{})

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldNotBeNil)

		_, err = helper.RefreshCredentials(remoteAddress)
		So(err, ShouldNotBeNil)
	})
}

// flakyTokenSource yields one token and fails afterwards, so that a test can reach the
// branches that only run once credentials are already held.
type flakyTokenSource struct {
	calls atomic.Int64
}

func (source *flakyTokenSource) Token() (*oauth2.Token, error) {
	if source.calls.Add(1) > 1 {
		return nil, errTokenMintFailed
	}

	return &oauth2.Token{AccessToken: "first", TokenType: "Bearer", Expiry: time.Now().Add(time.Second)}, nil
}

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errTokenMintFailed
}

func TestGetGCPTokenSource(t *testing.T) {
	Convey("Application default credentials are read from the environment", t, func() {
		directory := t.TempDir()
		tokenFile := filepath.Join(directory, "token")
		So(os.WriteFile(tokenFile, []byte("a.subject.token"), 0o600), ShouldBeNil)

		/* an external account file is enough to build the token source offline: the exchange
		itself only happens when a token is asked for */
		credentialsFile := filepath.Join(directory, "credentials.json")
		contents := `{
			"type": "external_account",
			"audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v",
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"token_url": "https://sts.googleapis.com/v1/token",
			"credential_source": {"file": "` + tokenFile + `", "format": {"type": "text"}}
		}`
		So(os.WriteFile(credentialsFile, []byte(contents), 0o600), ShouldBeNil)

		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentialsFile)

		source, err := sync.GetGCPTokenSource(context.Background())
		So(err, ShouldBeNil)
		So(source, ShouldNotBeNil)
	})

	Convey("A missing credentials file is reported", t, func() {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))

		_, err := sync.GetGCPTokenSource(context.Background())
		So(err, ShouldNotBeNil)
	})
}
