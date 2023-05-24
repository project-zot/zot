package signatures

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
)

const notationDirRelativePath = "_notation"

var notationDir = "" //nolint:gochecknoglobals

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
	}

	return err
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
