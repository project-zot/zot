package signatures

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
)

const notationDirRelativePath = "_notation"

var (
	notationDir     = ""              //nolint:gochecknoglobals
	TrustpolicyLock = new(sync.Mutex) //nolint: gochecknoglobals
)

func InitNotationDir(rootDir string) error {
	dir := path.Join(rootDir, notationDirRelativePath)

	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, defaultDirPerms)
		if err != nil {
			return err
		}
	}

	if err == nil {
		notationDir = dir

		if _, err := LoadTrustPolicyDocument(notationDir); os.IsNotExist(err) {
			return InitTrustpolicyFile(notationDir)
		}
	}

	return err
}

func InitTrustpolicyFile(configDir string) error {
	// according to https://github.com/notaryproject/notation/blob/main/specs/commandline/verify.md
	// the value of signatureVerification.level field from trustpolicy.json file
	// could be one of these values: `strict`, `permissive`, `audit` or `skip`
	// this default trustpolicy.json file sets the signatureVerification.level
	// to `strict` which enforces all validations (this means that even if there is
	// a certificate that verifies a signature, but that certificate has expired, then the
	// signature is not trusted; if this field were set to `permissive` then the
	// signature would be trusted)
	trustPolicy := `
	{
		"version": "1.0",
		"trustPolicies": [
			{
				"name": "default-config",
				"registryScopes": [ "*" ],
				"signatureVerification": {
					"level" : "strict" 
				},
				"trustStores": [],
				"trustedIdentities": [
					"*"
				]
			}
		]
	}`

	TrustpolicyLock.Lock()
	defer TrustpolicyLock.Unlock()

	return os.WriteFile(path.Join(configDir, dir.PathTrustPolicy), []byte(trustPolicy), defaultDirPerms)
}

func GetNotationDirPath() (string, error) {
	if notationDir != "" {
		return notationDir, nil
	}

	return "", zerr.ErrSignConfigDirNotSet
}

// Equivalent function for trustpolicy.LoadDocument() but using a specific SysFS not the one returned by ConfigFS().
func LoadTrustPolicyDocument(notationDir string) (*trustpolicy.Document, error) {
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

// NewFromConfig returns a verifier based on local file system.
// Equivalent function for verifier.NewFromConfig()
// but using LoadTrustPolicyDocumnt() function instead of trustpolicy.LoadDocument() function.
func NewFromConfig() (notation.Verifier, error) {
	notationDir, err := GetNotationDirPath()
	if err != nil {
		return nil, err
	}

	// Load trust policy.
	TrustpolicyLock.Lock()
	defer TrustpolicyLock.Unlock()

	policyDocument, err := LoadTrustPolicyDocument(notationDir)
	if err != nil {
		return nil, err
	}

	// Load trust store.
	x509TrustStore := truststore.NewX509TrustStore(dir.NewSysFS(notationDir))

	return verifier.New(policyDocument, x509TrustStore,
		plugin.NewCLIManager(dir.NewSysFS(path.Join(notationDir, dir.PathPlugins))))
}

func VerifyNotationSignature(
	artifactDescriptor ispec.Descriptor, artifactReference string, rawSignature []byte, signatureMediaType string,
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
	verifier, err := NewFromConfig()
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

func UploadCertificate(certificateContent []byte, truststoreType, truststoreName string) error {
	// validate truststore type
	if !validateTruststoreType(truststoreType) {
		return zerr.ErrInvalidTruststoreType
	}

	// validate truststore name
	if !validateTruststoreName(truststoreName) {
		return zerr.ErrInvalidTruststoreName
	}

	// validate certificate
	if ok, err := validateCertificate(certificateContent); !ok {
		return err
	}

	// add certificate to "{rootDir}/_notation/truststore/x509/{type}/{name}/{name.crt}"
	configDir, err := GetNotationDirPath()
	if err != nil {
		return err
	}

	name := godigest.FromBytes(certificateContent)

	// store certificate
	truststorePath := path.Join(configDir, dir.TrustStoreDir, "x509", truststoreType, truststoreName, name.String())

	if err := os.MkdirAll(filepath.Dir(truststorePath), defaultDirPerms); err != nil {
		return err
	}

	err = os.WriteFile(truststorePath, certificateContent, defaultFilePerms)
	if err != nil {
		return err
	}

	// add certificate to "trustpolicy.json"
	TrustpolicyLock.Lock()
	defer TrustpolicyLock.Unlock()

	trustpolicyDoc, err := LoadTrustPolicyDocument(configDir)
	if err != nil {
		return err
	}

	truststoreToAppend := fmt.Sprintf("%s:%s", truststoreType, truststoreName)

	for _, t := range trustpolicyDoc.TrustPolicies[0].TrustStores {
		if t == truststoreToAppend {
			return nil
		}
	}

	trustpolicyDoc.TrustPolicies[0].TrustStores = append(trustpolicyDoc.TrustPolicies[0].TrustStores, truststoreToAppend)

	trustpolicyDocContent, err := json.Marshal(trustpolicyDoc)
	if err != nil {
		return err
	}

	return os.WriteFile(path.Join(configDir, dir.PathTrustPolicy), trustpolicyDocContent, defaultFilePerms)
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
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(truststoreName)
}

// implementation from https://github.com/notaryproject/notation-core-go/blob/main/x509/cert.go#L20
func validateCertificate(certificateContent []byte) (bool, error) {
	var certs []*x509.Certificate

	block, rest := pem.Decode(certificateContent)
	if block == nil {
		// data may be in DER format
		derCerts, err := x509.ParseCertificates(certificateContent)
		if err != nil {
			return false, err
		}

		certs = append(certs, derCerts...)
	} else {
		// data is in PEM format
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return false, err
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}

	if len(certs) == 0 {
		return false, zerr.ErrInvalidCertificateContent
	}

	return true, nil
}
