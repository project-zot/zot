package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	apiconfig "zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

var (
	errAWSConnection = errors.New("aws connection error")
	errAWSConfig     = errors.New("aws config error")
)

// mockSecretsManager implements api.AWSSecretsManagerClient for testing.
type mockSecretsManager struct {
	secretString string
	err          error
	callCount    int
}

func (m *mockSecretsManager) GetSecretValue(
	_ context.Context,
	_ *secretsmanager.GetSecretValueInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.GetSecretValueOutput, error) {
	m.callCount++

	if m.err != nil {
		return nil, m.err
	}

	return &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(m.secretString),
	}, nil
}

// mockAWSImplementation implements api.AWSSecretsManagerProvider for testing.
type mockAWSImplementation struct {
	client  api.AWSSecretsManagerClient
	loadErr error
}

func (m *mockAWSImplementation) LoadDefaultConfig(
	_ context.Context,
	_ ...func(*awsconfig.LoadOptions) error,
) (aws.Config, error) {
	if m.loadErr != nil {
		return aws.Config{}, m.loadErr
	}

	return aws.Config{}, nil
}

func (m *mockAWSImplementation) NewFromConfig(_ aws.Config) api.AWSSecretsManagerClient {
	return m.client
}

// ed25519KeyToJWKS converts an ed25519.PublicKey to a single-key JWKS JSON string.
func ed25519KeyToJWKS(pub ed25519.PublicKey, kid string) string {
	jwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     kid,
		Algorithm: "EdDSA",
		Use:       "sig",
	}

	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	data, err := json.Marshal(keySet)
	if err != nil {
		panic(err)
	}

	return string(data)
}

// ed25519KeyToPEM converts an ed25519.PublicKey to PEM-encoded PKIX format.
func ed25519KeyToPEM(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestNewAWSSecretsManagerAuthorizerValidation(t *testing.T) {
	Convey("Test AWS Secrets Manager config validation", t, func() {
		Convey("Zero refresh interval gets default", func() {
			mock := &mockSecretsManager{}
			conf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "my-secret",
				RefreshInterval: 0,
			}
			_, err := api.NewAWSSecretsManager(conf, &mockAWSImplementation{client: mock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)
			// The default was applied (conf.RefreshInterval is mutated).
			So(conf.RefreshInterval, ShouldEqual, time.Minute)
		})

		Convey("LoadDefaultConfig error is propagated", func() {
			impl := &mockAWSImplementation{loadErr: errAWSConfig}
			conf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "my-secret",
				RefreshInterval: time.Hour,
			}
			_, err := api.NewAWSSecretsManager(conf, impl, log.NewLogger("error", ""))
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrBadConfig)
			So(err, ShouldWrap, errAWSConfig)
		})
	})
}

func TestAWSSecretsManagerGetPublicKeys(t *testing.T) {
	Convey("Test GetPublicKeys with mock secrets manager", t, func() {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		So(err, ShouldBeNil)

		secretJSON, err := json.Marshal(map[string]string{
			"key-1": ed25519KeyToPEM(pubKey),
		})
		So(err, ShouldBeNil)

		mock := &mockSecretsManager{secretString: string(secretJSON)}
		conf := &apiconfig.AWSSecretsManagerConfig{
			Region:          "us-east-1",
			SecretName:      "test-secret",
			RefreshInterval: time.Hour,
		}

		authz, err := api.NewAWSSecretsManager(conf, &mockAWSImplementation{client: mock}, log.NewLogger("error", ""))
		So(err, ShouldBeNil)

		Convey("Keys are fetched on first call", func() {
			keys, err := authz.GetPublicKeys(context.Background())
			So(err, ShouldBeNil)
			So(keys, ShouldContainKey, "key-1")
			So(mock.callCount, ShouldEqual, 1)
		})

		Convey("Keys are cached within refresh interval", func() {
			keys1, err := authz.GetPublicKeys(context.Background())
			So(err, ShouldBeNil)
			So(keys1, ShouldContainKey, "key-1")

			keys2, err := authz.GetPublicKeys(context.Background())
			So(err, ShouldBeNil)
			So(keys2, ShouldContainKey, "key-1")

			// Only one call to the mock — second call used the cache.
			So(mock.callCount, ShouldEqual, 1)
		})

		Convey("AWS error is propagated", func() {
			failMock := &mockSecretsManager{err: errAWSConnection}
			failConf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "test-secret",
				RefreshInterval: time.Hour,
			}

			failAuthz, err := api.NewAWSSecretsManager(
				failConf, &mockAWSImplementation{client: failMock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)

			_, err = failAuthz.GetPublicKeys(context.Background())
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, errAWSConnection)
		})

		Convey("Invalid JSON secret is rejected", func() {
			badMock := &mockSecretsManager{secretString: "not-json"}
			badConf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "test-secret",
				RefreshInterval: time.Hour,
			}

			badAuthz, err := api.NewAWSSecretsManager(
				badConf, &mockAWSImplementation{client: badMock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)

			_, err = badAuthz.GetPublicKeys(context.Background())
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "failed to parse secret JSON")
		})

		Convey("Invalid PEM key in secret is rejected", func() {
			badKeyJSON, err := json.Marshal(map[string]string{
				"bad-key": "not-a-pem-key",
			})
			So(err, ShouldBeNil)

			badMock := &mockSecretsManager{secretString: string(badKeyJSON)}
			badConf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "test-secret",
				RefreshInterval: time.Hour,
			}

			badAuthz, err := api.NewAWSSecretsManager(
				badConf, &mockAWSImplementation{client: badMock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)

			_, err = badAuthz.GetPublicKeys(context.Background())
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "failed to load public key")
		})

		Convey("JWKS-format key is parsed correctly", func() {
			jwksPub, _, err := ed25519.GenerateKey(rand.Reader)
			So(err, ShouldBeNil)

			jwksJSON, err := json.Marshal(map[string]string{
				"jwks-key": ed25519KeyToJWKS(jwksPub, "jwks-kid"),
			})
			So(err, ShouldBeNil)

			jwksMock := &mockSecretsManager{secretString: string(jwksJSON)}
			jwksConf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "test-secret",
				RefreshInterval: time.Hour,
			}

			jwksAuthz, err := api.NewAWSSecretsManager(
				jwksConf, &mockAWSImplementation{client: jwksMock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)

			keys, err := jwksAuthz.GetPublicKeys(context.Background())
			So(err, ShouldBeNil)
			So(keys, ShouldContainKey, "jwks-key")
		})

		Convey("JWKS with multiple keys in one entry is rejected", func() {
			// Build a JWKS with 2 keys to trigger the "expected 1 key" error.
			jwksPub1, _, err := ed25519.GenerateKey(rand.Reader)
			So(err, ShouldBeNil)

			jwksPub2, _, err := ed25519.GenerateKey(rand.Reader)
			So(err, ShouldBeNil)

			keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: jwksPub1, KeyID: "k1", Algorithm: "EdDSA", Use: "sig"},
				{Key: jwksPub2, KeyID: "k2", Algorithm: "EdDSA", Use: "sig"},
			}}

			multiData, err := json.Marshal(keySet)
			So(err, ShouldBeNil)

			multiJSON, err := json.Marshal(map[string]string{
				"multi-key": string(multiData),
			})
			So(err, ShouldBeNil)

			multiMock := &mockSecretsManager{secretString: string(multiJSON)}
			multiConf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "test-secret",
				RefreshInterval: time.Hour,
			}

			multiAuthz, err := api.NewAWSSecretsManager(
				multiConf, &mockAWSImplementation{client: multiMock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)

			_, err = multiAuthz.GetPublicKeys(context.Background())
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "expected 1 key in JWKS, found 2")
		})
	})
}

func TestAWSSecretsManagerGetPublicKey(t *testing.T) {
	Convey("Test GetPublicKey kid-based selection with mock", t, func() {
		pubKey1, _, err := ed25519.GenerateKey(rand.Reader)
		So(err, ShouldBeNil)

		pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
		So(err, ShouldBeNil)

		secretJSON, err := json.Marshal(map[string]string{
			"kid-alpha": ed25519KeyToPEM(pubKey1),
			"kid-beta":  ed25519KeyToPEM(pubKey2),
		})
		So(err, ShouldBeNil)

		mock := &mockSecretsManager{secretString: string(secretJSON)}
		conf := &apiconfig.AWSSecretsManagerConfig{
			Region:          "us-east-1",
			SecretName:      "test-secret",
			RefreshInterval: time.Hour,
		}

		authz, err := api.NewAWSSecretsManager(conf, &mockAWSImplementation{client: mock}, log.NewLogger("error", ""))
		So(err, ShouldBeNil)

		Convey("Matching kid returns the correct key", func() {
			token := &jwt.Token{Header: map[string]any{"kid": "kid-alpha"}}
			key, err := authz.GetPublicKey(context.Background(), token)
			So(err, ShouldBeNil)
			So(key, ShouldNotBeNil)
		})

		Convey("Missing kid header is rejected", func() {
			token := &jwt.Token{Header: map[string]any{}}
			_, err := authz.GetPublicKey(context.Background(), token)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})

		Convey("Non-string kid header is rejected", func() {
			token := &jwt.Token{Header: map[string]any{"kid": 12345}}
			_, err := authz.GetPublicKey(context.Background(), token)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})

		Convey("Unknown kid is rejected", func() {
			token := &jwt.Token{Header: map[string]any{"kid": "kid-unknown"}}
			_, err := authz.GetPublicKey(context.Background(), token)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})

		Convey("GetSecretValue error is propagated through GetPublicKey", func() {
			failMock := &mockSecretsManager{err: errAWSConnection}
			failConf := &apiconfig.AWSSecretsManagerConfig{
				Region:          "us-east-1",
				SecretName:      "test-secret",
				RefreshInterval: time.Hour,
			}

			failAuthz, err := api.NewAWSSecretsManager(
				failConf, &mockAWSImplementation{client: failMock}, log.NewLogger("error", ""))
			So(err, ShouldBeNil)

			token := &jwt.Token{Header: map[string]any{"kid": "any-kid"}}
			_, err = failAuthz.GetPublicKey(context.Background(), token)
			So(err, ShouldNotBeNil)
			So(err, ShouldWrap, errAWSConnection)
		})
	})
}

func TestAWSSecretsManagerBearerAuthorizerE2E(t *testing.T) {
	Convey("Test BearerAuthorizer with ASM key function end-to-end", t, func() {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		So(err, ShouldBeNil)

		const kid = "e2e-test-key"

		secretJSON, err := json.Marshal(map[string]string{
			kid: ed25519KeyToPEM(pubKey),
		})
		So(err, ShouldBeNil)

		mock := &mockSecretsManager{secretString: string(secretJSON)}
		conf := &apiconfig.AWSSecretsManagerConfig{
			Region:          "us-east-1",
			SecretName:      "test-secret",
			RefreshInterval: time.Hour,
		}

		authz, err := api.NewAWSSecretsManager(conf, &mockAWSImplementation{client: mock}, log.NewLogger("error", ""))
		So(err, ShouldBeNil)

		authorizer := api.NewBearerAuthorizer("realm", "service", authz.GetPublicKey)

		Convey("Valid EdDSA token with matching kid is authorized", func() {
			now := time.Now()
			claims := api.ClaimsWithAccess{
				Access: []api.ResourceAccess{
					{
						Name:    "test-repo",
						Type:    "repository",
						Actions: []string{"pull"},
					},
				},
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
					IssuedAt:  jwt.NewNumericDate(now),
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			token.Header["kid"] = kid

			signedToken, err := token.SignedString(privKey)
			So(err, ShouldBeNil)

			requested := &api.ResourceAction{
				Type:   "repository",
				Name:   "test-repo",
				Action: "pull",
			}

			err = authorizer.Authorize(context.Background(), "Bearer "+signedToken, requested)
			So(err, ShouldBeNil)
		})

		Convey("Token without kid header is rejected", func() {
			now := time.Now()
			claims := api.ClaimsWithAccess{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
					IssuedAt:  jwt.NewNumericDate(now),
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			// Deliberately omit kid header.

			signedToken, err := token.SignedString(privKey)
			So(err, ShouldBeNil)

			err = authorizer.Authorize(context.Background(), "Bearer "+signedToken, nil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})

		Convey("Token with unknown kid is rejected", func() {
			now := time.Now()
			claims := api.ClaimsWithAccess{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
					IssuedAt:  jwt.NewNumericDate(now),
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			token.Header["kid"] = "nonexistent-kid"

			signedToken, err := token.SignedString(privKey)
			So(err, ShouldBeNil)

			err = authorizer.Authorize(context.Background(), "Bearer "+signedToken, nil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})
	})
}

func TestAWSSecretsManagerProductionImplementation(t *testing.T) {
	Convey("Test production implementation coverage", t, func() {
		impl := api.AWSSecretsManagerProviderImplementation{}

		Convey("LoadDefaultConfig does not panic", func() {
			_, err := impl.LoadDefaultConfig(context.Background())
			if err != nil {
				t.Log("no aws creds")
			} else {
				t.Log("aws creds available")
			}
		})

		Convey("NewFromConfig returns a non-nil client", func() {
			client := impl.NewFromConfig(aws.Config{})
			So(client, ShouldNotBeNil)
		})
	})
}
