package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/golang-jwt/jwt/v5"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

// defaultAWSSecretsManagerRefreshInterval defines the target interval for refreshing the public keys.
// With a 1 minute interval, repeated calls will generally reuse cached keys and only trigger
// a refresh roughly once per minute, but this is best-effort and not a strict upper bound.
const defaultAWSSecretsManagerRefreshInterval = 1 * time.Minute

// AWSSecretsManagerAuthorizer retrieves public keys from AWS Secrets Manager.
type AWSSecretsManagerAuthorizer struct {
	client          AWSSecretsManagerClient
	secretName      string
	refreshInterval time.Duration

	// The keys are loaded lazily to avoid network calls during initialization.
	// We really don't want to block startup if AWS Secrets Manager is temporarily
	// unreachable. Also, we periodically refresh the keys to pick up any changes.
	keys         map[string]any
	keysMu       sync.RWMutex
	keysDeadline time.Time
}

// AWSSecretsManagerClient defines an interface for retrieving
// public keys from AWS Secrets Manager.
type AWSSecretsManagerClient interface {
	GetSecretValue(
		ctx context.Context,
		params *secretsmanager.GetSecretValueInput,
		optFns ...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)
}

// AWSSecretsManagerProvider abstracts the functions from the AWS SDK
// needed to create AWS Secrets Manager clients.
type AWSSecretsManagerProvider interface {
	LoadDefaultConfig(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error)
	NewFromConfig(aws.Config) AWSSecretsManagerClient
}

// AWSSecretsManagerProviderImplementation is the production implementation
// for creating AWS Secrets Manager clients.
type AWSSecretsManagerProviderImplementation struct{}

// LoadDefaultConfig is the production implementation for loading
// AWS configuration.
func (AWSSecretsManagerProviderImplementation) LoadDefaultConfig(
	ctx context.Context,
	optFns ...func(*awsconfig.LoadOptions) error,
) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, optFns...)
}

// NewFromConfig is the production implementation for creating
// AWS Secrets Manager clients.
func (AWSSecretsManagerProviderImplementation) NewFromConfig(cfg aws.Config) AWSSecretsManagerClient {
	return secretsmanager.NewFromConfig(cfg)
}

// NewAWSSecretsManager creates a AWSSecretsManagerAuthorizer that retrieves
// public keys from AWS Secrets Manager based on the provided configuration.
func NewAWSSecretsManager(
	conf *config.AWSSecretsManagerConfig,
	impl AWSSecretsManagerProvider,
	logger log.Logger,
) (*AWSSecretsManagerAuthorizer, error) {
	// Apply default refresh interval if not specified.
	if conf.RefreshInterval == 0 {
		conf.RefreshInterval = defaultAWSSecretsManagerRefreshInterval
	}

	// Build AWS Secrets Manager client.
	awsConf, err := impl.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(conf.Region))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load AWS configuration: %w", zerr.ErrBadConfig, err)
	}

	logger.
		Info().
		Str("region", conf.Region).
		Str("secretName", conf.SecretName).
		Dur("refreshInterval", conf.RefreshInterval).
		Msg("the AWS Secrets Manager JWT verification was enabled")

	return &AWSSecretsManagerAuthorizer{
		client:          impl.NewFromConfig(awsConf),
		secretName:      conf.SecretName,
		refreshInterval: conf.RefreshInterval,
	}, nil
}

// GetPublicKey retrieves the public key matching the JWT header claim `kid`,
// refreshing all the keys if the refresh interval has elapsed.
func (a *AWSSecretsManagerAuthorizer) GetPublicKey(ctx context.Context, token *jwt.Token) (any, error) {
	keys, err := a.GetPublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys from AWS Secrets Manager: %w", err)
	}

	kid, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: token missing 'kid' header", zerr.ErrInvalidBearerToken)
	}

	keyID, ok := kid.(string)
	if !ok {
		return nil, fmt.Errorf("%w: token 'kid' header is not a string", zerr.ErrInvalidBearerToken)
	}

	pubKey, ok := keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: no public key found for kid %s", zerr.ErrInvalidBearerToken, keyID)
	}

	return pubKey, nil
}

// GetPublicKeys retrieves the public keys from AWS Secrets Manager.
func (a *AWSSecretsManagerAuthorizer) GetPublicKeys(ctx context.Context) (map[string]any, error) {
	// If the keys are still fresh, return them.
	a.keysMu.RLock()
	keys, deadline := a.keys, a.keysDeadline
	a.keysMu.RUnlock()
	if len(keys) > 0 && time.Now().Before(deadline) {
		return keys, nil
	}

	// Time to refresh the keys.
	resp, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(a.secretName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret from AWS Secrets Manager: %w", err)
	}

	// Parse the secret as a map of key ID to public key.
	var rawKeys map[string]string
	if err := json.Unmarshal([]byte(*resp.SecretString), &rawKeys); err != nil {
		return nil, fmt.Errorf("failed to parse secret JSON: %w", err)
	}

	// Parse the public keys.
	keys = make(map[string]any, len(rawKeys))
	for kid, rawKey := range rawKeys {
		pubKey, err := loadPublicKeyFromBytes([]byte(rawKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load public key for kid %s: %w", kid, err)
		}
		keys[kid] = pubKey
	}

	// Update the cached keys.
	a.keysMu.Lock()
	a.keys = keys
	a.keysDeadline = time.Now().Add(a.refreshInterval)
	a.keysMu.Unlock()

	return keys, nil
}
