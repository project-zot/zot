package api

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

var bearerOIDCTokenMatch = regexp.MustCompile("(?i)bearer (.*)")

// OIDCBearerAuthorizer validates OIDC ID tokens for workload identity authentication.
type OIDCBearerAuthorizer struct {
	issuer          string
	audiences       []string
	claimMapping    *config.ClaimMapping
	verifier        *oidc.IDTokenVerifier
	skipIssuerCheck bool
	log             log.Logger
}

// NewOIDCBearerAuthorizer creates a new OIDC bearer token authorizer.
func NewOIDCBearerAuthorizer(ctx context.Context, oidcConfig *config.BearerOIDCConfig, log log.Logger) (*OIDCBearerAuthorizer, error) {
	if oidcConfig == nil {
		return nil, fmt.Errorf("%w: OIDC config is nil", zerr.ErrBadConfig)
	}

	if oidcConfig.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", zerr.ErrBadConfig)
	}

	if len(oidcConfig.Audiences) == 0 {
		return nil, fmt.Errorf("%w: at least one audience is required", zerr.ErrBadConfig)
	}

	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, oidcConfig.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create OIDC provider: %w", zerr.ErrBadConfig, err)
	}

	// Configure verifier
	verifierConfig := &oidc.Config{
		ClientID:          oidcConfig.Audiences[0], // Primary audience
		SkipIssuerCheck:   oidcConfig.SkipIssuerVerification,
		SkipClientIDCheck: false,
		SkipExpiryCheck:   false,
		Now:               time.Now,
	}

	// Support multiple audiences
	if len(oidcConfig.Audiences) > 1 {
		verifierConfig.SupportedSigningAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
	}

	verifier := provider.Verifier(verifierConfig)

	log.Info().Str("issuer", oidcConfig.Issuer).Strs("audiences", oidcConfig.Audiences).
		Msg("OIDC workload identity authentication enabled")

	return &OIDCBearerAuthorizer{
		issuer:          oidcConfig.Issuer,
		audiences:       oidcConfig.Audiences,
		claimMapping:    oidcConfig.ClaimMapping,
		verifier:        verifier,
		skipIssuerCheck: oidcConfig.SkipIssuerVerification,
		log:             log,
	}, nil
}

// Authenticate validates an OIDC token and extracts the identity.
// Returns the username and groups extracted from the token claims.
func (a *OIDCBearerAuthorizer) Authenticate(ctx context.Context, header string) (string, []string, error) {
	if header == "" {
		return "", nil, zerr.ErrNoBearerToken
	}

	// Extract token from Authorization header
	tokenString := bearerOIDCTokenMatch.ReplaceAllString(header, "$1")
	if tokenString == "" || tokenString == header {
		return "", nil, zerr.ErrInvalidBearerToken
	}

	// Verify the token
	idToken, err := a.verifier.Verify(ctx, tokenString)
	if err != nil {
		a.log.Debug().Err(err).Msg("OIDC token verification failed")
		return "", nil, fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}

	// Verify audience (the verifier checks the first audience, but we need to check all)
	if !a.skipIssuerCheck && !a.verifyAudience(idToken) {
		a.log.Debug().Str("token_aud", fmt.Sprintf("%v", idToken.Audience)).
			Strs("accepted_aud", a.audiences).
			Msg("token audience not accepted")
		return "", nil, fmt.Errorf("%w: audience not accepted", zerr.ErrInvalidBearerToken)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return "", nil, fmt.Errorf("%w: failed to extract claims: %w", zerr.ErrInvalidBearerToken, err)
	}

	// Extract username from configured claim
	username := a.extractUsername(claims)
	if username == "" {
		a.log.Debug().Interface("claims", claims).Msg("failed to extract username from token")
		return "", nil, fmt.Errorf("%w: no username found in token", zerr.ErrInvalidBearerToken)
	}

	// Extract groups if present
	groups := a.extractGroups(claims)

	a.log.Debug().Str("username", username).Strs("groups", groups).Msg("OIDC token authenticated")

	return username, groups, nil
}

// verifyAudience checks if the token's audience matches any of the accepted audiences.
func (a *OIDCBearerAuthorizer) verifyAudience(token *oidc.IDToken) bool {
	tokenAudiences := token.Audience
	for _, tokenAud := range tokenAudiences {
		for _, acceptedAud := range a.audiences {
			if tokenAud == acceptedAud {
				return true
			}
		}
	}
	return false
}

// extractUsername extracts the username from token claims based on claim mapping configuration.
func (a *OIDCBearerAuthorizer) extractUsername(claims map[string]interface{}) string {
	// Default claim to use for username
	claimName := "sub"

	// Use configured claim mapping if available
	if a.claimMapping != nil && a.claimMapping.Username != "" {
		claimName = a.claimMapping.Username
	}

	// Try to get the claim value
	if val, ok := claims[claimName]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	// Fallback: try "sub" if configured claim didn't work and wasn't "sub"
	if claimName != "sub" {
		if val, ok := claims["sub"]; ok {
			if strVal, ok := val.(string); ok {
				return strVal
			}
		}
	}

	return ""
}

// extractGroups extracts groups from token claims.
// It looks for "groups" claim as an array of strings.
func (a *OIDCBearerAuthorizer) extractGroups(claims map[string]interface{}) []string {
	groups := []string{}

	// Try to extract groups from "groups" claim
	if groupsClaim, ok := claims["groups"]; ok {
		switch v := groupsClaim.(type) {
		case []interface{}:
			for _, g := range v {
				if str, ok := g.(string); ok {
					groups = append(groups, str)
				}
			}
		case []string:
			groups = v
		case string:
			// Single group as string
			groups = append(groups, v)
		}
	}

	return groups
}

// AuthenticateRequest is a convenience method that handles the full authentication flow
// and returns whether authentication succeeded and any error.
func (a *OIDCBearerAuthorizer) AuthenticateRequest(ctx context.Context, authHeader string) (string, []string, bool, error) {
	username, groups, err := a.Authenticate(ctx, authHeader)
	if err != nil {
		return "", nil, false, err
	}

	if username == "" {
		return "", nil, false, fmt.Errorf("%w: empty username", zerr.ErrInvalidBearerToken)
	}

	return username, groups, true, nil
}

// CreateOAuth2Config creates an oauth2.Config for use with the OIDC provider.
// This is a helper method for testing purposes.
func CreateOAuth2Config(issuer string, clientID string, clientSecret string, redirectURL string, scopes []string) (*oauth2.Config, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}, nil
}
