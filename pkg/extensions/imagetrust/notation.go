//go:build imagetrust
// +build imagetrust

package imagetrust

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
)

const (
	notationDirRelativePath = "_notation"
	truststoreName          = "default"
)

type CertificateLocalStorage struct {
	notationDir string
}

type CertificateAWSStorage struct {
	secretsManagerClient SecretsManagerClient
	secretsManagerCache  SecretsManagerCache
}

type certificateStorage interface {
	LoadTrustPolicyDocument() (*trustpolicy.Document, error)
	StoreCertificate(certificateContent []byte, truststoreType string) error
	GetVerifier(policyDoc *trustpolicy.Document) (notation.Verifier, error)
	InitTrustpolicy(trustpolicy []byte) error
}

func NewCertificateLocalStorage(rootDir string) (*CertificateLocalStorage, error) {
	dir := path.Join(rootDir, notationDirRelativePath)

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

	certStorage := &CertificateLocalStorage{
		notationDir: dir,
	}

	if err := InitTrustpolicyFile(certStorage); err != nil {
		return nil, err
	}

	for _, truststoreType := range truststore.Types {
		defaultTruststore := path.Join(dir, "truststore", "x509", string(truststoreType), truststoreName)

		_, err = os.Stat(defaultTruststore)
		if os.IsNotExist(err) {
			err = os.MkdirAll(defaultTruststore, defaultDirPerms)
			if err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, err
		}
	}

	return certStorage, nil
}

func NewCertificateAWSStorage(
	secretsManagerClient SecretsManagerClient, secretsManagerCache SecretsManagerCache,
) (*CertificateAWSStorage, error) {
	certStorage := &CertificateAWSStorage{
		secretsManagerClient: secretsManagerClient,
		secretsManagerCache:  secretsManagerCache,
	}

	err := InitTrustpolicyFile(certStorage)
	if err != nil {
		return nil, err
	}

	return certStorage, nil
}

func InitTrustpolicyFile(notationStorage certificateStorage) error {
	truststores := []string{}

	for _, truststoreType := range truststore.Types {
		truststores = append(truststores, fmt.Sprintf("\"%s:%s\"", string(truststoreType), truststoreName))
	}

	defaultTruststores := strings.Join(truststores, ",")

	// according to https://github.com/notaryproject/notation/blob/main/specs/commandline/verify.md
	// the value of signatureVerification.level field from trustpolicy.json file
	// could be one of these values: `strict`, `permissive`, `audit` or `skip`
	// this default trustpolicy.json file sets the signatureVerification.level
	// to `strict` which enforces all validations (this means that even if there is
	// a certificate that verifies a signature, but that certificate has expired, then the
	// signature is not trusted; if this field were set to `permissive` then the
	// signature would be trusted)
	trustPolicy := `{
	"version": "1.0",
	"trustPolicies": [
		{
			"name": "default-config",
			"registryScopes": [ "*" ],
			"signatureVerification": {
				"level" : "strict" 
			},
			"trustStores": [` + defaultTruststores + `],
			"trustedIdentities": [
				"*"
			]
		}
	]
}`

	return notationStorage.InitTrustpolicy([]byte(trustPolicy))
}

func (local *CertificateLocalStorage) InitTrustpolicy(trustpolicy []byte) error {
	notationDir, err := local.GetNotationDirPath()
	if err != nil {
		return err
	}

	return os.WriteFile(path.Join(notationDir, dir.PathTrustPolicy), trustpolicy, defaultDirPerms)
}

func (cloud *CertificateAWSStorage) InitTrustpolicy(trustpolicy []byte) error {
	name := "trustpolicy"
	description := "notation trustpolicy file"
	secret := base64.StdEncoding.EncodeToString(trustpolicy)
	secretInputParam := &secretsmanager.CreateSecretInput{
		Name:         &name,
		Description:  &description,
		SecretString: &secret,
	}

	_, err := cloud.secretsManagerClient.CreateSecret(context.Background(), secretInputParam)
	if err != nil && IsResourceExistsException(err) {
		trustpolicyContent, err := cloud.secretsManagerCache.GetSecretString(name)
		if err != nil {
			return err
		}

		existingTrustpolicy, err := base64.StdEncoding.DecodeString(trustpolicyContent)
		if err == nil && bytes.Equal(trustpolicy, existingTrustpolicy) {
			return nil
		}

		force := true

		deleteSecretParam := &secretsmanager.DeleteSecretInput{
			SecretId:                   &name,
			ForceDeleteWithoutRecovery: &force,
		}

		_, err = cloud.secretsManagerClient.DeleteSecret(context.Background(), deleteSecretParam)

		if err != nil {
			return err
		}

		err = cloud.recreateSecret(secretInputParam)

		return err
	}

	return err
}

func (cloud *CertificateAWSStorage) recreateSecret(secretInputParam *secretsmanager.CreateSecretInput) error {
	maxAttempts := 5
	retrySec := 2

	var err error

	for i := 0; i < maxAttempts; i++ {
		_, err = cloud.secretsManagerClient.CreateSecret(context.Background(), secretInputParam)

		if err == nil {
			return nil
		}

		time.Sleep(time.Duration(retrySec) * time.Second)
	}

	return err
}

func (local *CertificateLocalStorage) GetNotationDirPath() (string, error) {
	if local.notationDir != "" {
		return local.notationDir, nil
	}

	return "", zerr.ErrSignConfigDirNotSet
}

func (cloud *CertificateAWSStorage) GetCertificates(
	ctx context.Context, storeType truststore.Type, namedStore string,
) ([]*x509.Certificate, error) {
	certificates := []*x509.Certificate{}

	if !validateTruststoreType(string(storeType)) {
		return []*x509.Certificate{}, zerr.ErrInvalidTruststoreType
	}

	if !validateTruststoreName(namedStore) {
		return []*x509.Certificate{}, zerr.ErrInvalidTruststoreName
	}

	listSecretsInput := secretsmanager.ListSecretsInput{
		Filters: []types.Filter{
			{
				Key:    types.FilterNameStringTypeName,
				Values: []string{path.Join(string(storeType), namedStore)},
			},
		},
	}

	secrets, err := cloud.secretsManagerClient.ListSecrets(ctx, &listSecretsInput)
	if err != nil {
		return []*x509.Certificate{}, err
	}

	for _, secret := range secrets.SecretList {
		// get key
		raw, err := cloud.secretsManagerCache.GetSecretString(*(secret.Name))
		if err != nil {
			return []*x509.Certificate{}, err
		}

		rawDecoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return []*x509.Certificate{}, err
		}

		certs, _, err := parseAndValidateCertificateContent(rawDecoded)
		if err != nil {
			return []*x509.Certificate{}, err
		}

		err = truststore.ValidateCertificates(certs)
		if err != nil {
			return []*x509.Certificate{}, err
		}

		certificates = append(certificates, certs...)
	}

	return certificates, nil
}

// Equivalent function for trustpolicy.LoadDocument() but using a specific SysFS not the one returned by ConfigFS().
func (local *CertificateLocalStorage) LoadTrustPolicyDocument() (*trustpolicy.Document, error) {
	notationDir, err := local.GetNotationDirPath()
	if err != nil {
		return nil, err
	}

	jsonFile, err := dir.NewSysFS(notationDir).Open(dir.PathTrustPolicy)
	if err != nil {
		return nil, err
	}

	defer jsonFile.Close()

	policyDocument := &trustpolicy.Document{}

	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, err
	}

	return policyDocument, nil
}

func (cloud *CertificateAWSStorage) LoadTrustPolicyDocument() (*trustpolicy.Document, error) {
	policyDocument := &trustpolicy.Document{}

	raw, err := cloud.secretsManagerCache.GetSecretString("trustpolicy")
	if err != nil {
		return nil, err
	}

	rawDecoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = json.Compact(&buf, rawDecoded)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(buf.Bytes(), policyDocument)
	if err != nil {
		return nil, err
	}

	return policyDocument, nil
}

// NewFromConfig returns a verifier based on local file system.
// Equivalent function for verifier.NewFromConfig()
// but using LoadTrustPolicyDocumnt() function instead of trustpolicy.LoadDocument() function.
func NewFromConfig(notationStorage certificateStorage) (notation.Verifier, error) {
	// Load trust policy.
	policyDocument, err := notationStorage.LoadTrustPolicyDocument()
	if err != nil {
		return nil, err
	}

	return notationStorage.GetVerifier(policyDocument)
}

func (local *CertificateLocalStorage) GetVerifier(policyDoc *trustpolicy.Document) (notation.Verifier, error) {
	notationDir, err := local.GetNotationDirPath()
	if err != nil {
		return nil, err
	}
	x509TrustStore := truststore.NewX509TrustStore(dir.NewSysFS(notationDir))

	return verifier.New(policyDoc, x509TrustStore,
		plugin.NewCLIManager(dir.NewSysFS(path.Join(notationDir, dir.PathPlugins))))
}

func (cloud *CertificateAWSStorage) GetVerifier(policyDoc *trustpolicy.Document) (notation.Verifier, error) {
	return verifier.New(policyDoc, cloud,
		plugin.NewCLIManager(dir.NewSysFS(path.Join(dir.PathPlugins))))
}

func VerifyNotationSignature(
	notationStorage certificateStorage, artifactDescriptor ispec.Descriptor, artifactReference string,
	rawSignature []byte, signatureMediaType string,
) (string, time.Time, bool, error) {
	var (
		date   time.Time
		author string
	)

	// If there's no signature associated with the reference.
	if len(rawSignature) == 0 {
		return author, date, false, notation.ErrorSignatureRetrievalFailed{
			Msg: fmt.Sprintf("no signature associated with %q is provided, make sure the image was signed successfully",
				artifactReference),
		}
	}

	// Initialize verifier.
	verifier, err := NewFromConfig(notationStorage)
	if err != nil {
		return author, date, false, err
	}

	ctx := context.Background()

	// Set VerifyOptions.
	opts := notation.VerifierVerifyOptions{
		// ArtifactReference is important to validate registry scope format
		// If "registryScopes" field from trustpolicy.json file is not wildcard then "domain:80/repo@" should not be hardcoded
		ArtifactReference:  "domain:80/repo@" + artifactReference,
		SignatureMediaType: signatureMediaType,
		PluginConfig:       map[string]string{},
	}

	// Verify the notation signature which should be associated with the artifactDescriptor.
	outcome, err := verifier.Verify(ctx, artifactDescriptor, rawSignature, opts)
	if outcome.EnvelopeContent != nil {
		author = outcome.EnvelopeContent.SignerInfo.CertificateChain[0].Subject.String()

		if outcome.VerificationLevel == trustpolicy.LevelStrict && (err == nil ||
			CheckExpiryErr(outcome.VerificationResults, outcome.EnvelopeContent.SignerInfo.CertificateChain[0].NotAfter, err)) {
			expiry := outcome.EnvelopeContent.SignerInfo.SignedAttributes.Expiry
			if !expiry.IsZero() && expiry.Before(outcome.EnvelopeContent.SignerInfo.CertificateChain[0].NotAfter) {
				date = outcome.EnvelopeContent.SignerInfo.SignedAttributes.Expiry
			} else {
				date = outcome.EnvelopeContent.SignerInfo.CertificateChain[0].NotAfter
			}
		}
	}

	if err != nil {
		return author, date, false, err
	}

	// Verification Succeeded.
	return author, date, true, nil
}

func CheckExpiryErr(verificationResults []*notation.ValidationResult, notAfter time.Time, err error) bool {
	for _, result := range verificationResults {
		if result.Type == trustpolicy.TypeExpiry {
			if errors.Is(err, result.Error) {
				return true
			}
		} else if result.Type == trustpolicy.TypeAuthenticTimestamp {
			if errors.Is(err, result.Error) && time.Now().After(notAfter) {
				return true
			} else {
				return false
			}
		}
	}

	return false
}

func UploadCertificate(
	notationStorage certificateStorage, certificateContent []byte, truststoreType string,
) error {
	// validate truststore type
	if !validateTruststoreType(truststoreType) {
		return zerr.ErrInvalidTruststoreType
	}

	// validate certificate
	if _, ok, err := parseAndValidateCertificateContent(certificateContent); !ok {
		return err
	}

	// store certificate
	err := notationStorage.StoreCertificate(certificateContent, truststoreType)

	return err
}

func (local *CertificateLocalStorage) StoreCertificate(
	certificateContent []byte, truststoreType string,
) error {
	// add certificate to "{rootDir}/_notation/truststore/x509/{type}/default/{name.crt}"
	configDir, err := local.GetNotationDirPath()
	if err != nil {
		return err
	}

	name := godigest.FromBytes(certificateContent)

	// store certificate
	truststorePath := path.Join(configDir, dir.TrustStoreDir, "x509", truststoreType, truststoreName, name.String())

	if err := os.MkdirAll(filepath.Dir(truststorePath), defaultDirPerms); err != nil {
		return err
	}

	return os.WriteFile(truststorePath, certificateContent, defaultFilePerms)
}

func (cloud *CertificateAWSStorage) StoreCertificate(
	certificateContent []byte, truststoreType string,
) error {
	name := path.Join(truststoreType, truststoreName, godigest.FromBytes(certificateContent).Encoded())
	description := "notation certificate"
	secret := base64.StdEncoding.EncodeToString(certificateContent)
	secretInputParam := &secretsmanager.CreateSecretInput{
		Name:         &name,
		Description:  &description,
		SecretString: &secret,
	}

	_, err := cloud.secretsManagerClient.CreateSecret(context.Background(), secretInputParam)

	if err != nil && IsResourceExistsException(err) {
		return nil
	}

	return err
}

func validateTruststoreType(truststoreType string) bool {
	for _, t := range truststore.Types {
		if string(t) == truststoreType {
			return true
		}
	}

	return false
}

func validateTruststoreName(truststoreName string) bool {
	if strings.Contains(truststoreName, "..") {
		return false
	}

	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(truststoreName)
}

// implementation from https://github.com/notaryproject/notation-core-go/blob/main/x509/cert.go#L20
func parseAndValidateCertificateContent(certificateContent []byte) ([]*x509.Certificate, bool, error) {
	var certs []*x509.Certificate

	block, rest := pem.Decode(certificateContent)
	if block == nil {
		// data may be in DER format
		derCerts, err := x509.ParseCertificates(certificateContent)
		if err != nil {
			return []*x509.Certificate{}, false, fmt.Errorf("%w: %w", zerr.ErrInvalidCertificateContent, err)
		}

		certs = append(certs, derCerts...)
	} else {
		// data is in PEM format
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return []*x509.Certificate{}, false, fmt.Errorf("%w: %w", zerr.ErrInvalidCertificateContent, err)
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}

	if len(certs) == 0 {
		return []*x509.Certificate{}, false, fmt.Errorf("%w: no valid certificates found in payload",
			zerr.ErrInvalidCertificateContent)
	}

	return certs, true, nil
}
