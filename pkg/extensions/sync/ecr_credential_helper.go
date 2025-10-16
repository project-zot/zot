//go:build sync
// +build sync

package sync

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

// ECR tokens are valid for 12 hours. The expiryWindow variable is set to 1 hour,
// meaning if the remaining validity of the token is less than 1 hour, it will be considered expired.
const (
	expiryWindow          int = 1
	ecrURLSplitPartsCount int = 6
	mockExpiryDuration    int = 12
	usernameTokenParts    int = 2
)

var (
	errInvalidURLFormat          = errors.New("invalid ECR URL is received")
	errInvalidTokenFormat        = errors.New("invalid token format received from ECR")
	errUnableToLoadAWSConfig     = errors.New("unable to load AWS config for region")
	errUnableToGetECRAuthToken   = errors.New("unable to get ECR authorization token for account")
	errUnableToDecodeECRToken    = errors.New("unable to decode ECR token")
	errFailedToGetECRCredentials = errors.New("failed to get ECR credentials")
)

type ecrCredential struct {
	username string
	password string
	expiry   time.Time
	account  string
	region   string
}

type ecrCredentialsHelper struct {
	credentials        map[string]ecrCredential
	log                log.Logger
	getCredentialsFunc func(string) (ecrCredential, error)
}

func NewECRCredentialHelper(log log.Logger, getCredentialsFunc func(string) (ecrCredential, error)) CredentialHelper {
	return &ecrCredentialsHelper{
		credentials:        make(map[string]ecrCredential),
		log:                log,
		getCredentialsFunc: getCredentialsFunc,
	}
}

// extractAccountAndRegion extracts the account ID and region from the given ECR URL.
// Example URL format: account.dkr.ecr.region.amazonaws.com.
func extractAccountAndRegion(url string) (string, string, error) {
	parts := strings.Split(url, ".")
	if len(parts) < ecrURLSplitPartsCount {
		return "", "", fmt.Errorf("%w: %s", errInvalidURLFormat, url)
	}

	accountID := parts[0] // First part is the account ID

	region := parts[3] // Fourth part is the region

	return accountID, region, nil
}

// getMockECRCredentials provides mock credentials for testing purposes.
func GetMockECRCredentials(remoteAddress string) (ecrCredential, error) {
	// Extract account ID and region from the URL.
	accountID, region, err := extractAccountAndRegion(remoteAddress)
	if err != nil {
		return ecrCredential{}, fmt.Errorf("%w %s: %w", errInvalidTokenFormat, remoteAddress, err)
	}
	expiry := time.Now().Add(time.Duration(mockExpiryDuration) * time.Hour)

	return ecrCredential{
		username: "mockUsername",
		password: "mockPassword",
		expiry:   expiry,
		account:  accountID,
		region:   region,
	}, nil
}

// getECRCredentials retrieves actual ECR credentials using AWS SDK.
func GetECRCredentials(remoteAddress string) (ecrCredential, error) {
	// Extract account ID and region from the URL.
	accountID, region, err := extractAccountAndRegion(remoteAddress)
	if err != nil {
		return ecrCredential{}, fmt.Errorf("%w %s: %w", errInvalidTokenFormat, remoteAddress, err)
	}

	// Load the AWS config for the specific region.
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return ecrCredential{}, fmt.Errorf("%w %s: %w", errUnableToLoadAWSConfig, region, err)
	}

	// Create an ECR client
	ecrClient := ecr.NewFromConfig(cfg)

	// Fetch the ECR authorization token.
	ecrAuth, err := ecrClient.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{
		RegistryIds: []string{accountID}, // Filter by the account ID.
	})
	if err != nil {
		return ecrCredential{}, fmt.Errorf("%w %s: %w", errUnableToGetECRAuthToken, accountID, err)
	}

	// Decode the base64-encoded ECR token.
	authToken := *ecrAuth.AuthorizationData[0].AuthorizationToken

	decodedToken, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return ecrCredential{}, fmt.Errorf("%w: %w", errUnableToDecodeECRToken, err)
	}

	// Split the decoded token into username and password (username is "AWS").
	tokenParts := strings.Split(string(decodedToken), ":")
	if len(tokenParts) != usernameTokenParts {
		return ecrCredential{}, fmt.Errorf("%w", errInvalidTokenFormat)
	}

	expiry := *ecrAuth.AuthorizationData[0].ExpiresAt
	username := tokenParts[0]
	password := tokenParts[1]

	return ecrCredential{username: username, password: password, expiry: expiry, account: accountID, region: region}, nil
}

// GetECRCredentials retrieves the ECR credentials (username and password) from AWS ECR.
func (credHelper *ecrCredentialsHelper) GetCredentials(urls []string) (syncconf.CredentialsFile, error) {
	ecrCredentials := make(syncconf.CredentialsFile)

	for _, url := range urls {
		remoteAddress := StripRegistryTransport(url)

		// Use the injected credential retrieval function.
		ecrCred, err := credHelper.getCredentialsFunc(remoteAddress)
		if err != nil {
			return syncconf.CredentialsFile{}, fmt.Errorf("%w %s: %w", errFailedToGetECRCredentials, url, err)
		}
		// Store the credentials in the map using the base URL as the key.
		ecrCredentials[remoteAddress] = syncconf.Credentials{
			Username: ecrCred.username,
			Password: ecrCred.password,
		}
		credHelper.credentials[remoteAddress] = ecrCred
	}

	return ecrCredentials, nil
}

// AreCredentialsValid checks if the credentials for a given remote address are still valid.
func (credHelper *ecrCredentialsHelper) AreCredentialsValid(remoteAddress string) bool {
	expiry := credHelper.credentials[remoteAddress].expiry
	expiryDuration := time.Duration(expiryWindow) * time.Hour

	if time.Until(expiry) <= expiryDuration {
		credHelper.log.Info().
			Str("url", remoteAddress).
			Msg("the credentials are close to expiring")

		return false
	}

	credHelper.log.Info().
		Str("url", remoteAddress).
		Msg("the credentials are valid")

	return true
}

// RefreshCredentials refreshes the ECR credentials for the given remote address.
func (credHelper *ecrCredentialsHelper) RefreshCredentials(
	remoteAddress string,
) (syncconf.Credentials, error) {
	credHelper.log.Info().Str("url", remoteAddress).Msg("refreshing the ECR credentials")

	ecrCred, err := credHelper.getCredentialsFunc(remoteAddress)
	if err != nil {
		return syncconf.Credentials{}, fmt.Errorf("%w %s: %w", errFailedToGetECRCredentials, remoteAddress, err)
	}

	return syncconf.Credentials{Username: ecrCred.username, Password: ecrCred.password}, nil
}
