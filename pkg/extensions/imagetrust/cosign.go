//go:build imagetrust
// +build imagetrust

package imagetrust

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	godigest "github.com/opencontainers/go-digest"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoreSigs "github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	zerr "zotregistry.dev/zot/errors"
)

const cosignDirRelativePath = "_cosign"

type PublicKeyLocalStorage struct {
	cosignDir string
}

type PublicKeyAWSStorage struct {
	secretsManagerClient SecretsManagerClient
	secretsManagerCache  SecretsManagerCache
}

type publicKeyStorage interface {
	StorePublicKey(name godigest.Digest, publicKeyContent []byte) error
	GetPublicKeyVerifier(name string) (sigstoreSigs.Verifier, []byte, error)
	GetPublicKeys() ([]string, error)
}

func NewPublicKeyLocalStorage(rootDir string) (*PublicKeyLocalStorage, error) {
	dir := path.Join(rootDir, cosignDirRelativePath)

	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, defaultDirPerms)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	return &PublicKeyLocalStorage{
		cosignDir: dir,
	}, nil
}

func NewPublicKeyAWSStorage(
	secretsManagerClient SecretsManagerClient, secretsManagerCache SecretsManagerCache,
) *PublicKeyAWSStorage {
	return &PublicKeyAWSStorage{
		secretsManagerClient: secretsManagerClient,
		secretsManagerCache:  secretsManagerCache,
	}
}

func (local *PublicKeyLocalStorage) GetCosignDirPath() (string, error) {
	if local.cosignDir != "" {
		return local.cosignDir, nil
	}

	return "", zerr.ErrSignConfigDirNotSet
}

func VerifyCosignSignature(
	cosignStorage publicKeyStorage, repo string, digest godigest.Digest, signatureKey string, layerContent []byte,
) (string, bool, error) {
	publicKeys, err := cosignStorage.GetPublicKeys()
	if err != nil {
		return "", false, err
	}

	for _, publicKey := range publicKeys {
		// cosign verify the image
		pubKeyVerifier, pubKeyContent, err := cosignStorage.GetPublicKeyVerifier(publicKey)
		if err != nil {
			continue
		}

		pkcs11Key, ok := pubKeyVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}

		verifier := pubKeyVerifier

		b64sig := signatureKey

		signature, err := base64.StdEncoding.DecodeString(b64sig)
		if err != nil {
			continue
		}

		compressed := io.NopCloser(bytes.NewReader(layerContent))

		payload, err := io.ReadAll(compressed)
		if err != nil {
			continue
		}

		err = verifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload),
			options.WithContext(context.Background()))

		if err == nil {
			return string(pubKeyContent), true, nil
		}
	}

	return "", false, nil
}

func (local *PublicKeyLocalStorage) GetPublicKeyVerifier(fileName string) (sigstoreSigs.Verifier, []byte, error) {
	cosignDir, err := local.GetCosignDirPath()
	if err != nil {
		return nil, []byte{}, err
	}

	ctx := context.Background()
	keyRef := path.Join(cosignDir, fileName)
	hashAlgorithm := crypto.SHA256

	pubKeyContent, err := os.ReadFile(keyRef)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, hashAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, pubKeyContent, nil
}

func (cloud *PublicKeyAWSStorage) GetPublicKeyVerifier(secretName string) (sigstoreSigs.Verifier, []byte, error) {
	hashAlgorithm := crypto.SHA256

	// get key
	raw, err := cloud.secretsManagerCache.GetSecretString(secretName)
	if err != nil {
		return nil, nil, err
	}

	rawDecoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, nil, err
	}

	// PEM encoded file.
	key, err := cryptoutils.UnmarshalPEMToPublicKey(rawDecoded)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := sigstoreSigs.LoadVerifier(key, hashAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, rawDecoded, nil
}

func (local *PublicKeyLocalStorage) GetPublicKeys() ([]string, error) {
	cosignDir, err := local.GetCosignDirPath()
	if err != nil {
		return []string{}, err
	}

	files, err := os.ReadDir(cosignDir)
	if err != nil {
		return []string{}, err
	}

	publicKeys := []string{}
	for _, file := range files {
		publicKeys = append(publicKeys, file.Name())
	}

	return publicKeys, nil
}

func (cloud *PublicKeyAWSStorage) GetPublicKeys() ([]string, error) {
	ctx := context.Background()
	listSecretsInput := secretsmanager.ListSecretsInput{
		Filters: []types.Filter{
			{
				Key:    types.FilterNameStringTypeDescription,
				Values: []string{"cosign public key"},
			},
		},
	}

	secrets, err := cloud.secretsManagerClient.ListSecrets(ctx, &listSecretsInput)
	if err != nil {
		return []string{}, err
	}

	publicKeys := []string{}

	for _, secret := range secrets.SecretList {
		publicKeys = append(publicKeys, *(secret.Name))
	}

	return publicKeys, nil
}

func UploadPublicKey(cosignStorage publicKeyStorage, publicKeyContent []byte) error {
	// validate public key
	if ok, err := validatePublicKey(publicKeyContent); !ok {
		return err
	}

	name := godigest.FromBytes(publicKeyContent)

	return cosignStorage.StorePublicKey(name, publicKeyContent)
}

func (local *PublicKeyLocalStorage) StorePublicKey(name godigest.Digest, publicKeyContent []byte) error {
	// add public key to "{rootDir}/_cosign/{name.pub}"
	cosignDir, err := local.GetCosignDirPath()
	if err != nil {
		return err
	}

	// store public key
	publicKeyPath := path.Join(cosignDir, name.String())

	return os.WriteFile(publicKeyPath, publicKeyContent, defaultFilePerms)
}

func (cloud *PublicKeyAWSStorage) StorePublicKey(name godigest.Digest, publicKeyContent []byte) error {
	n := name.Encoded()
	description := "cosign public key"
	secret := base64.StdEncoding.EncodeToString(publicKeyContent)
	secretInputParam := &secretsmanager.CreateSecretInput{
		Name:         &n,
		Description:  &description,
		SecretString: &secret,
	}

	_, err := cloud.secretsManagerClient.CreateSecret(context.Background(), secretInputParam)
	if err != nil && IsResourceExistsException(err) {
		return nil
	}

	return err
}

func validatePublicKey(publicKeyContent []byte) (bool, error) {
	_, err := cryptoutils.UnmarshalPEMToPublicKey(publicKeyContent)
	if err != nil {
		return false, fmt.Errorf("%w: %w", zerr.ErrInvalidPublicKeyContent, err)
	}

	return true, nil
}
