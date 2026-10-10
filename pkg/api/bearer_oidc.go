package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/cel"
	"zotregistry.dev/zot/v2/pkg/log"
)

// oidcProviderRefreshInterval defines the target interval for refreshing discovery metadata.
// Signing keys are cached and refreshed independently by go-oidc.
const oidcProviderRefreshInterval = 1 * time.Minute

const oidcHTTPTimeout = 10 * time.Second

var bearerOIDCTokenMatch = regexp.MustCompile("(?i)bearer (.*)")

// OIDCBearerAuthorizer validates OIDC ID tokens for workload identity authentication.
type OIDCBearerAuthorizer struct {
	providers []*oidcProvider
}

// oidcProvider validates OIDC ID tokens for workload identity authentication.
// It holds the configuration for a single OIDC issuer.
type oidcProvider struct {
	issuer          string
	audiences       []string
	claimProcessor  *cel.ClaimProcessor
	skipIssuerCheck bool
	httpClient      *http.Client
	log             log.Logger

	// The *oidc.IDTokenVerifier is created lazily to avoid network calls during initialization.
	// We really don't want to block startup if the OIDC issuer is temporarily unreachable.
	// Also, we periodically refresh the provider to pick up any changes in the issuer's configuration.
	verifier         *oidc.IDTokenVerifier
	verifierMu       sync.RWMutex
	verifierDeadline time.Time
	provider         *oidc.Provider
	refreshDone      chan struct{}
}

// NewOIDCBearerAuthorizer creates a new OIDC bearer token authorizer.
func NewOIDCBearerAuthorizer(oidcConfig []config.BearerOIDCConfig, log log.Logger) (*OIDCBearerAuthorizer, error) {
	providers := make([]*oidcProvider, 0, len(oidcConfig))
	issuers := make([]string, 0, len(oidcConfig))

	for i := range oidcConfig {
		conf := &oidcConfig[i]
		provider, err := newOIDCProvider(conf, log)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to create OIDC bearer provider[%d]: %w", zerr.ErrBadConfig, i, err)
		}

		providers = append(providers, provider)
		issuers = append(issuers, conf.Issuer)
	}

	log.Info().Strs("issuers", issuers).Msg("the OIDC workload identity authentication was enabled")

	return &OIDCBearerAuthorizer{
		providers: providers,
	}, nil
}

// AuthenticateRequest is a convenience method that handles the full authentication flow
// and returns whether authentication succeeded and any error.
func (a *OIDCBearerAuthorizer) AuthenticateRequest(ctx context.Context,
	authHeader string,
) (string, []string, bool, error) {
	res, err := a.Authenticate(ctx, authHeader)
	if err != nil {
		return "", nil, false, err
	}

	if res.Username == "" {
		return "", nil, false, fmt.Errorf("%w: empty username", zerr.ErrInvalidBearerToken)
	}

	return res.Username, res.Groups, true, nil
}

// Authenticate validates an OIDC token and extracts the identity.
// Returns the username and groups extracted from the token claims.
func (a *OIDCBearerAuthorizer) Authenticate(ctx context.Context, header string) (*cel.ClaimResult, error) {
	if header == "" {
		return nil, zerr.ErrNoBearerToken
	}
	tokenString := bearerOIDCTokenMatch.ReplaceAllString(header, "$1")
	if tokenString == "" || tokenString == header {
		return nil, zerr.ErrInvalidBearerToken
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, claims); err != nil {
		return nil, fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}
	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}

	errs := make([]error, 0, len(a.providers))

	for _, provider := range a.providers {
		// The unverified issuer only selects candidates; each candidate still verifies the token.
		googleIssuerAlias := provider.issuer == "https://accounts.google.com" && issuer == "accounts.google.com"
		if !provider.skipIssuerCheck && provider.issuer != issuer && !googleIssuerAlias {
			continue
		}
		res, err := provider.authenticate(ctx, header)
		if err == nil {
			return res, nil
		}
		errs = append(errs, err)
	}
	switch len(errs) {
	case 0:
		return nil, zerr.ErrInvalidBearerToken
	case 1:
		return nil, errs[0]
	default:
		return nil, errors.Join(errs...)
	}
}

// newOIDCProvider creates a new OIDC provider based on the given configuration.
func newOIDCProvider(oidcConfig *config.BearerOIDCConfig, log log.Logger) (*oidcProvider, error) {
	// Validate configuration
	if oidcConfig.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", zerr.ErrBadConfig)
	}
	claimProcessor, err := cel.NewClaimProcessor(oidcConfig.Audiences, oidcConfig.ClaimMapping)
	if err != nil {
		return nil, fmt.Errorf("failed to create claim processor: %w", err)
	}
	if oidcConfig.CertificateAuthority != "" && oidcConfig.CertificateAuthorityFile != "" {
		return nil, fmt.Errorf("%w: only one of certificateAuthority or certificateAuthorityFile can be set",
			zerr.ErrBadConfig)
	}

	// Prepare CA.
	caCert := []byte(oidcConfig.CertificateAuthority)
	if file := oidcConfig.CertificateAuthorityFile; file != "" {
		caCert, err = os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate authority file: %w", err)
		}
	}

	httpClient := &http.Client{Timeout: oidcHTTPTimeout}
	if len(caCert) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("%w: failed to append certificate authority PEM", zerr.ErrBadConfig)
		}
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("%w: failed to get default HTTP transport", zerr.ErrBadConfig)
		}
		testTransport := defaultTransport.Clone()
		testTransport.TLSClientConfig = &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		}
		httpClient.Transport = testTransport
	}

	return &oidcProvider{
		issuer:          oidcConfig.Issuer,
		audiences:       oidcConfig.Audiences,
		claimProcessor:  claimProcessor,
		skipIssuerCheck: oidcConfig.SkipIssuerVerification,
		httpClient:      httpClient,
		log:             log,
	}, nil
}

func (a *oidcProvider) authenticate(ctx context.Context, header string) (*cel.ClaimResult, error) {
	if header == "" {
		return nil, zerr.ErrNoBearerToken
	}

	// Extract token from Authorization header
	tokenString := bearerOIDCTokenMatch.ReplaceAllString(header, "$1")
	if tokenString == "" || tokenString == header {
		return nil, zerr.ErrInvalidBearerToken
	}

	// Get verifier.
	verifier, err := a.getVerifier(ctx)
	if err != nil {
		a.log.Err(err).Msg("failed to get OIDC token verifier")

		return nil, fmt.Errorf("%w: %w", zerr.ErrInvalidOrUnreachableOIDCIssuer, err)
	}

	// Verify the token
	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		a.log.Debug().Err(err).Msg("the OIDC token verification failed")

		return nil, fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}

	// Extract claims
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: failed to extract claims: %w", zerr.ErrInvalidBearerToken, err)
	}

	// Process claims to extract username and groups.
	res, err := a.claimProcessor.Process(ctx, claims)
	if err != nil {
		a.log.Debug().Err(err).Msg("the OIDC token claim processing failed")

		return nil, fmt.Errorf("%w: failed to process claims: %w", zerr.ErrInvalidBearerToken, err)
	}

	a.log.Debug().Str("username", res.Username).Strs("groups", res.Groups).Msg("the OIDC token was authenticated")

	return res, nil
}

// getVerifier retrieves or refreshes the oidc.IDTokenVerifier as needed.
func (o *oidcProvider) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	o.verifierMu.Lock()
	verifier := o.verifier
	done := o.refreshDone
	if done == nil && (verifier == nil || !time.Now().Before(o.verifierDeadline)) {
		done = make(chan struct{})
		o.refreshDone = done

		go o.refreshVerifier(context.WithoutCancel(ctx), done)
	}
	o.verifierMu.Unlock()

	if verifier != nil {
		return verifier, nil
	}

	// Only initial discovery blocks authentication. Other requests share the refresh.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		o.verifierMu.RLock()
		defer o.verifierMu.RUnlock()
		if o.verifier == nil {
			return nil, fmt.Errorf("%w: failed to discover OIDC provider from issuer %s",
				zerr.ErrInvalidOrUnreachableOIDCIssuer, o.issuer)
		}

		return o.verifier, nil
	}
}

func (o *oidcProvider) refreshVerifier(ctx context.Context, done chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, oidcHTTPTimeout)
	defer cancel()
	ctx = oidc.ClientContext(ctx, o.httpClient)
	provider, err := oidc.NewProvider(ctx, o.issuer)

	o.verifierMu.Lock()
	defer o.verifierMu.Unlock()
	defer close(done)
	o.refreshDone = nil
	o.verifierDeadline = time.Now().Add(oidcProviderRefreshInterval)
	if err != nil {
		o.log.Err(err).Str("issuer", o.issuer).Msg("failed to refresh OIDC provider")

		return
	}

	// Reuse the provider's remote key cache unless verification metadata has changed.
	var previous, current oidc.ProviderConfig
	if err := provider.Claims(&current); err != nil {
		o.log.Err(err).Msg("failed to read OIDC provider metadata")

		return
	}
	if o.provider != nil {
		if err := o.provider.Claims(&previous); err == nil &&
			previous.JWKSURL == current.JWKSURL && slices.Equal(previous.Algorithms, current.Algorithms) {
			return
		}
	}
	o.provider = provider
	o.verifier = provider.Verifier(&oidc.Config{
		ClientID:          "", // We'll check audiences manually
		SkipIssuerCheck:   o.skipIssuerCheck,
		SkipClientIDCheck: true, // Check audiences manually to support multiple
		SkipExpiryCheck:   false,
		Now:               time.Now,
	})
}
