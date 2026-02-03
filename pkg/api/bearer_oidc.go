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
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/cel"
	"zotregistry.dev/zot/v2/pkg/log"
)

// oidcProviderRefreshInterval defines the target interval for refreshing the public keys.
// With a 1 minute interval, repeated calls will generally reuse cached keys and only trigger
// a refresh roughly once per minute, but this is best-effort and not a strict upper bound.
const oidcProviderRefreshInterval = 1 * time.Minute

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
	errs := make([]error, 0, len(a.providers))

	for _, provider := range a.providers {
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

	var httpClient *http.Client
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
		httpClient = &http.Client{Transport: testTransport}
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
	// If the verifier is still fresh, return it.
	o.verifierMu.RLock()
	verifier, deadline := o.verifier, o.verifierDeadline
	o.verifierMu.RUnlock()
	if verifier != nil && time.Now().Before(deadline) {
		return verifier, nil
	}

	// Time to refresh the verifier.
	if hc := o.httpClient; hc != nil {
		ctx = oidc.ClientContext(ctx, hc)
	}
	p, err := oidc.NewProvider(ctx, o.issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh OIDC provider from issuer %s: %w", o.issuer, err)
	}
	verifier = p.Verifier(&oidc.Config{
		ClientID:          "", // We'll check audiences manually
		SkipIssuerCheck:   o.skipIssuerCheck,
		SkipClientIDCheck: true, // Check audiences manually to support multiple
		SkipExpiryCheck:   false,
		Now:               time.Now,
	})

	// Update the verifier and deadline.
	o.verifierMu.Lock()
	o.verifier = verifier
	o.verifierDeadline = time.Now().Add(oidcProviderRefreshInterval)
	o.verifierMu.Unlock()

	return verifier, nil
}
