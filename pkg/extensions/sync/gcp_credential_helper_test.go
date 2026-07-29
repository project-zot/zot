//go:build sync

package sync_test

import (
	"context"
	"errors"
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
		helper := newHelper(&mintingTokenSource{})

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldBeNil)
		So(helper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
	})

	Convey("An address that was never fetched is not valid", t, func() {
		helper := newHelper(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "stable"}))

		So(helper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
	})

	Convey("A refresh hands back the current token", t, func() {
		source := &mintingTokenSource{}
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

	Convey("A token source that fails to mint is reported", t, func() {
		helper := newHelper(failingTokenSource{})

		_, err := helper.GetCredentials([]string{"https://" + remoteAddress})
		So(err, ShouldNotBeNil)

		_, err = helper.RefreshCredentials(remoteAddress)
		So(err, ShouldNotBeNil)
	})
}

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errTokenMintFailed
}
