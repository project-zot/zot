//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	// gcpTokenUser is the fixed username Google Artifact Registry expects when the password
	// is an access token.
	gcpTokenUser = "oauth2accesstoken"

	/* gcpScope is the narrowest scope Artifact Registry offers: it publishes only
	cloud-platform and this read-only form, with nothing specific to a registry. Sync never
	writes to the upstream, so a token that could is a liability rather than a capability.
	The scope shapes the token for the credential sources that honour it, such as a service
	account or an external account; the metadata server may hand back whatever the instance
	was configured with instead. */
	gcpScope = "https://www.googleapis.com/auth/cloud-platform.read-only"
)

var (
	errUnableToLoadGCPCredentials = errors.New("unable to load the Google application default credentials")
	errUnableToGetGCPToken        = errors.New("unable to obtain a Google access token")
)

// GetGCPTokenSource returns the Application Default Credentials token source. It covers the
// metadata server on GCE and GKE, GOOGLE_APPLICATION_CREDENTIALS, an external account file
// for workload identity federation, and gcloud user credentials.
func GetGCPTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	credentials, err := google.FindDefaultCredentials(ctx, gcpScope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnableToLoadGCPCredentials, err)
	}

	return credentials.TokenSource, nil
}

type gcpCredentialsHelper struct {
	mu             sync.RWMutex
	accessTokens   map[string]string
	tokenSource    oauth2.TokenSource
	newTokenSource func(context.Context) (oauth2.TokenSource, error)
	log            log.Logger
}

func NewGCPCredentialHelper(
	log log.Logger,
	newTokenSource func(context.Context) (oauth2.TokenSource, error),
) CredentialHelper {
	return &gcpCredentialsHelper{
		accessTokens:   make(map[string]string),
		newTokenSource: newTokenSource,
		log:            log,
	}
}

/*
resolveTokenSource builds the token source on first use, so that credentials which are not reachable yet
when sync starts do not disable the helper for the lifetime of the process.

The result is wrapped in a reusing source. The TokenSource interface promises nothing about
caching, and AreCredentialsValid below is built on the token only changing when it is really
rotated, so the caching is made explicit here rather than assumed of whatever the credentials
hand back.
*/
func (credHelper *gcpCredentialsHelper) resolveTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	credHelper.mu.RLock()
	source := credHelper.tokenSource
	credHelper.mu.RUnlock()

	if source != nil {
		return source, nil
	}

	credHelper.mu.Lock()
	defer credHelper.mu.Unlock()

	// another caller may have won the race while the read lock was released
	if credHelper.tokenSource != nil {
		return credHelper.tokenSource, nil
	}

	source, err := credHelper.newTokenSource(ctx)
	if err != nil {
		return nil, err
	}

	credHelper.tokenSource = oauth2.ReuseTokenSource(nil, source)

	return credHelper.tokenSource, nil
}

func (credHelper *gcpCredentialsHelper) fetchToken(ctx context.Context) (*oauth2.Token, error) {
	source, err := credHelper.resolveTokenSource(ctx)
	if err != nil {
		return nil, err
	}

	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnableToGetGCPToken, err)
	}

	return token, nil
}

func (credHelper *gcpCredentialsHelper) rememberToken(remoteAddress string, token *oauth2.Token) {
	credHelper.mu.Lock()
	defer credHelper.mu.Unlock()

	credHelper.accessTokens[remoteAddress] = token.AccessToken
}

// GetCredentials pairs the current access token with the username Artifact Registry expects.
func (credHelper *gcpCredentialsHelper) GetCredentials(urls []string) (syncconf.CredentialsFile, error) {
	gcpCredentials := make(syncconf.CredentialsFile)

	// nothing to authenticate against, so do not go looking for credentials
	if len(urls) == 0 {
		return gcpCredentials, nil
	}

	token, err := credHelper.fetchToken(context.Background())
	if err != nil {
		return syncconf.CredentialsFile{}, err
	}

	for _, url := range urls {
		remoteAddress := StripRegistryTransport(url)
		gcpCredentials[remoteAddress] = syncconf.Credentials{Username: gcpTokenUser, Password: token.AccessToken}

		credHelper.rememberToken(remoteAddress, token)
	}

	return gcpCredentials, nil
}

/*
AreCredentialsValid reports whether the token held for a remote address is still the one the
token source hands out.

Unlike the ECR helper this does not compare a fixed window against an expiry. The token
source keeps a cached token and mints a new one only once the old one is seconds from
expiring, so a window of its own would mark the credentials expired while the source kept
returning the same token, and the registry client would be rebuilt on every sync operation
until the token finally rotated. Asking the source instead rebuilds it exactly once per
rotation, and costs nothing while the cached token is still good.
*/
func (credHelper *gcpCredentialsHelper) AreCredentialsValid(remoteAddress string) bool {
	credHelper.mu.RLock()
	held, ok := credHelper.accessTokens[remoteAddress]
	credHelper.mu.RUnlock()

	if !ok {
		return false
	}

	token, err := credHelper.fetchToken(context.Background())
	if err != nil {
		credHelper.log.Error().Err(err).Str("url", remoteAddress).
			Msg("failed to read the Google access token")

		return false
	}

	if token.AccessToken != held {
		credHelper.log.Info().Str("url", remoteAddress).Msg("the Google access token has been rotated")

		return false
	}

	return true
}

// RefreshCredentials returns the current access token for the given remote address.
func (credHelper *gcpCredentialsHelper) RefreshCredentials(
	remoteAddress string,
) (syncconf.Credentials, error) {
	credHelper.log.Info().Str("url", remoteAddress).Msg("refreshing the Google access token")

	token, err := credHelper.fetchToken(context.Background())
	if err != nil {
		return syncconf.Credentials{}, err
	}

	credHelper.rememberToken(remoteAddress, token)

	return syncconf.Credentials{Username: gcpTokenUser, Password: token.AccessToken}, nil
}
