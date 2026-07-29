//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	// gcpTokenUser is the fixed username Google Artifact Registry expects when the password
	// is an access token.
	gcpTokenUser = "oauth2accesstoken"

	// gcpScope is the scope a registry pull needs. Application Default Credentials applies
	// it for the credential sources that are scope aware, such as gcloud user credentials.
	gcpScope = "https://www.googleapis.com/auth/cloud-platform"
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

type gcpCredential struct {
	accessToken string
	expiry      time.Time
}

type gcpCredentialsHelper struct {
	mu             sync.RWMutex
	credentials    map[string]gcpCredential
	tokenSource    oauth2.TokenSource
	newTokenSource func(context.Context) (oauth2.TokenSource, error)
	log            log.Logger
}

func NewGCPCredentialHelper(
	log log.Logger,
	newTokenSource func(context.Context) (oauth2.TokenSource, error),
) CredentialHelper {
	return &gcpCredentialsHelper{
		credentials:    make(map[string]gcpCredential),
		newTokenSource: newTokenSource,
		log:            log,
	}
}

/*
source builds the token source on first use, so that credentials which are not reachable yet
when sync starts do not disable the helper for the lifetime of the process.

The result is wrapped in a reusing source. The TokenSource interface promises nothing about
caching, and AreCredentialsValid below is built on the token only changing when it is really
rotated, so the caching is made explicit here rather than assumed of whatever the credentials
hand back.
*/
func (credHelper *gcpCredentialsHelper) source(ctx context.Context) (oauth2.TokenSource, error) {
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

func (credHelper *gcpCredentialsHelper) token(ctx context.Context) (*oauth2.Token, error) {
	source, err := credHelper.source(ctx)
	if err != nil {
		return nil, err
	}

	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnableToGetGCPToken, err)
	}

	return token, nil
}

func (credHelper *gcpCredentialsHelper) store(remoteAddress string, token *oauth2.Token) {
	credHelper.mu.Lock()
	defer credHelper.mu.Unlock()

	credHelper.credentials[remoteAddress] = gcpCredential{accessToken: token.AccessToken, expiry: token.Expiry}
}

// GetCredentials pairs the current access token with the username Artifact Registry expects.
func (credHelper *gcpCredentialsHelper) GetCredentials(urls []string) (syncconf.CredentialsFile, error) {
	gcpCredentials := make(syncconf.CredentialsFile)

	// nothing to authenticate against, so do not go looking for credentials
	if len(urls) == 0 {
		return gcpCredentials, nil
	}

	token, err := credHelper.token(context.Background())
	if err != nil {
		return syncconf.CredentialsFile{}, err
	}

	for _, url := range urls {
		remoteAddress := StripRegistryTransport(url)
		gcpCredentials[remoteAddress] = syncconf.Credentials{Username: gcpTokenUser, Password: token.AccessToken}

		credHelper.store(remoteAddress, token)
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
	credential, ok := credHelper.credentials[remoteAddress]
	credHelper.mu.RUnlock()

	if !ok {
		return false
	}

	token, err := credHelper.token(context.Background())
	if err != nil {
		credHelper.log.Error().Err(err).Str("url", remoteAddress).
			Msg("failed to read the Google access token")

		return false
	}

	if token.AccessToken != credential.accessToken {
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

	token, err := credHelper.token(context.Background())
	if err != nil {
		return syncconf.Credentials{}, err
	}

	credHelper.store(remoteAddress, token)

	return syncconf.Credentials{Username: gcpTokenUser, Password: token.AccessToken}, nil
}
