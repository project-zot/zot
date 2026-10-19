package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/project-zot/mockoidc"
)

var errMalformedJWT = errors.New("malformed jwt")

// MockOIDCRun starts a mock OIDC server which signs ID tokens with RS256.
func MockOIDCRun() (*mockoidc.MockOIDC, error) {
	return mockOIDCRun(nil)
}

// MockOIDCRunWithIDTokenSigningAlg starts a mock OIDC server which signs ID tokens with the given
// RSA based algorithm (for example PS512), advertises only that algorithm in the discovery document
// (id_token_signing_alg_values_supported) and publishes its signing key with that algorithm in the JWKS.
// mockoidc itself always signs with RS256, so ID tokens are re-signed with the same key on their way out.
func MockOIDCRunWithIDTokenSigningAlg(alg jose.SignatureAlgorithm) (*mockoidc.MockOIDC, error) {
	return mockOIDCRun(func(server *mockoidc.MockOIDC) func(http.Handler) http.Handler {
		return idTokenSigningAlgMiddleware(server.Keypair, alg)
	})
}

func mockOIDCRun(middlewareFactory func(*mockoidc.MockOIDC) func(http.Handler) http.Handler,
) (*mockoidc.MockOIDC, error) {
	// Create a fresh RSA Private Key for token signing
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048) //nolint:mnd

	// Create an unstarted MockOIDC server
	mockServer, _ := mockoidc.NewServer(rsaKey)

	// Create the net.Listener, kernel will chose a valid port
	listener, _ := net.Listen("tcp", "127.0.0.1:0") //nolint: noctx

	bearerMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
			// stateVal := req.Form.Get("state")
			header := req.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2) //nolint:mnd

			if header != "" {
				if strings.ToLower(parts[0]) == "bearer" {
					req.Header.Set("Authorization", strings.Join([]string{"Bearer", parts[1]}, " "))
				}
			}

			next.ServeHTTP(response, req)
		})
	}

	err := mockServer.AddMiddleware(bearerMiddleware)
	if err != nil {
		return mockServer, err
	}

	if middlewareFactory != nil {
		err := mockServer.AddMiddleware(middlewareFactory(mockServer))
		if err != nil {
			return mockServer, err
		}
	}

	// tlsConfig can be nil if you want HTTP
	return mockServer, mockServer.Start(listener, nil)
}

// idTokenSigningAlgMiddleware makes the mock issuer look like one which signs ID tokens with alg:
// the discovery document advertises alg, the JWKS publishes the key with alg and ID tokens returned
// by the token endpoint are re-signed with alg.
func idTokenSigningAlgMiddleware(keypair *mockoidc.Keypair, alg jose.SignatureAlgorithm,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case mockoidc.DiscoveryEndpoint:
				rewriteJSONResponse(response, req, next, func(body map[string]any) error {
					body["id_token_signing_alg_values_supported"] = []string{string(alg)}

					return nil
				})
			case mockoidc.JWKSEndpoint:
				writeJWKS(response, keypair, alg)
			case mockoidc.TokenEndpoint:
				rewriteJSONResponse(response, req, next, func(body map[string]any) error {
					idToken, ok := body["id_token"].(string)
					if !ok || idToken == "" {
						return nil
					}

					resigned, err := resignJWT(idToken, keypair, alg)
					if err != nil {
						return err
					}

					body["id_token"] = resigned

					return nil
				})
			default:
				next.ServeHTTP(response, req)
			}
		})
	}
}

// rewriteJSONResponse serves the request with next and, if it succeeded with a JSON body,
// lets rewrite modify the decoded body before it is written to the client.
func rewriteJSONResponse(response http.ResponseWriter, req *http.Request, next http.Handler,
	rewrite func(body map[string]any) error,
) {
	recorder := httptest.NewRecorder()
	next.ServeHTTP(recorder, req)

	maps.Copy(response.Header(), recorder.Header())

	if recorder.Code != http.StatusOK {
		response.WriteHeader(recorder.Code)
		_, _ = response.Write(recorder.Body.Bytes())

		return
	}

	var body map[string]any

	err := json.Unmarshal(recorder.Body.Bytes(), &body)
	if err == nil {
		err = rewrite(body)
	}

	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)

		return
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)

		return
	}

	response.Header().Del("Content-Length")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func writeJWKS(response http.ResponseWriter, keypair *mockoidc.Keypair, alg jose.SignatureAlgorithm) {
	kid, err := keypair.KeyID()
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)

		return
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       keypair.PublicKey,
			KeyID:     kid,
			Use:       "sig",
			Algorithm: string(alg),
		}},
	}

	encoded, err := json.Marshal(jwks)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)

		return
	}

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

// resignJWT signs the payload of token again with keypair and alg, keeping the claims unchanged.
func resignJWT(token string, keypair *mockoidc.Keypair, alg jose.SignatureAlgorithm) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 { //nolint:mnd
		return "", errMalformedJWT
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	kid, err := keypair.KeyID()
	if err != nil {
		return "", err
	}

	signerOptions := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: keypair.PrivateKey}, signerOptions)
	if err != nil {
		return "", err
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return signed.CompactSerialize()
}
