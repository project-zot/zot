package extensions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	notconfig "github.com/notaryproject/notation-go/config"
	"github.com/notaryproject/notation-go/dir"
	notreg "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/notation-go/verifier"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"zotregistry.io/zot/pkg/test"
)

var (
	ErrKeyNotFound           = errors.New("key not found")
	ErrAlreadyExists         = errors.New("already exists")
	ErrSignatureVerification = errors.New("signature verification failed")

	NotationPathLock = new(sync.Mutex) //nolint: gochecknoglobals
)

func SignImageUsingCosign(repoTag, port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "cosign")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
	if err != nil {
		return err
	}

	imageURL := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	const timeoutPeriod = 5

	// sign the image
	return sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: timeoutPeriod * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.SignOptions{
			Registry:          options.RegistryOptions{AllowInsecure: true},
			AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=1.0"}},
			Upload:            true,
		},
		[]string{imageURL})
}

func SignImageUsingNotary(repoTag, port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "notation")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	NotationPathLock.Lock()
	defer NotationPathLock.Unlock()

	LoadNotationPath(tdir)

	// generate a keypair
	err = GenerateNotationCerts(tdir, "notation-sign-test")
	if err != nil {
		return err
	}

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	err = SignWithNotation("notation-sign-test", image, tdir)

	return err
}

func LoadNotationPath(tdir string) {
	dir.UserConfigDir = filepath.Join(tdir, "notation")

	// set user libexec
	dir.UserLibexecDir = dir.UserConfigDir
}

func GenerateNotationCerts(tdir string, certName string) error {
	// generate RSA private key
	bits := 2048

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	rsaCertTuple := testhelper.GetRSASelfSignedCertTupleWithPK(key, "cert")

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCertTuple.Cert.Raw})

	// write private key
	relativeKeyPath, relativeCertPath := dir.LocalKeyPath(certName)

	configFS := dir.ConfigFS()

	keyPath, err := configFS.SysPath(relativeKeyPath)
	if err != nil {
		return err
	}

	certPath, err := configFS.SysPath(relativeCertPath)
	if err != nil {
		return err
	}

	if err := WriteFileWithPermission(keyPath, keyPEM, 0o600, false); err != nil { //nolint:gomnd
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// write self-signed certificate
	if err := WriteFileWithPermission(certPath, certBytes, 0o644, false); err != nil { //nolint:gomnd
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	signingKeys, err := notconfig.LoadSigningKeys()
	if err != nil {
		return err
	}

	keySuite := notconfig.KeySuite{
		Name: certName,
		X509KeyPair: &notconfig.X509KeyPair{
			KeyPath:         keyPath,
			CertificatePath: certPath,
		},
	}

	// addKeyToSigningKeys
	if Contains(signingKeys.Keys, keySuite.Name) {
		return ErrAlreadyExists
	}

	signingKeys.Keys = append(signingKeys.Keys, keySuite)

	// Add to the trust store
	trustStorePath := path.Join(tdir, fmt.Sprintf("notation/truststore/x509/ca/%s", certName))

	if _, err := os.Stat(filepath.Join(trustStorePath, filepath.Base(certPath))); err == nil {
		return ErrAlreadyExists
	}

	if err := os.MkdirAll(trustStorePath, 0o755); err != nil { //nolint:gomnd
		return fmt.Errorf("GenerateNotationCerts os.MkdirAll failed: %w", err)
	}

	trustCertPath := path.Join(trustStorePath, fmt.Sprintf("%s%s", certName, dir.LocalCertificateExtension))

	err = test.CopyFile(certPath, trustCertPath)
	if err != nil {
		return err
	}

	// Save to the SigningKeys.json
	if err := signingKeys.Save(); err != nil {
		return err
	}

	return nil
}

func SignWithNotation(keyName string, reference string, tdir string) error {
	ctx := context.TODO()

	// getSigner
	var newSigner notation.Signer

	mediaType := jws.MediaTypeEnvelope

	// ResolveKey
	signingKeys, err := LoadNotationSigningkeys(tdir)
	if err != nil {
		return err
	}

	idx := Index(signingKeys.Keys, keyName)
	if idx < 0 {
		return ErrKeyNotFound
	}

	key := signingKeys.Keys[idx]

	if key.X509KeyPair != nil {
		newSigner, err = signer.NewFromFiles(key.X509KeyPair.KeyPath, key.X509KeyPair.CertificatePath)
		if err != nil {
			return err
		}
	}

	// prepareSigningContent
	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	plainHTTP := true

	// Resolve referance
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repositoryOpts := notreg.RepositoryOptions{}

	sigRepo := notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	sigOpts := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: mediaType,
			PluginConfig:       map[string]string{},
		},
		ArtifactReference: ref.String(),
	}

	_, err = notation.Sign(ctx, newSigner, sigRepo, sigOpts)
	if err != nil {
		return err
	}

	return nil
}

func WriteFileWithPermission(path string, data []byte, perm fs.FileMode, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}
	flag := os.O_WRONLY | os.O_CREATE

	if overwrite {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_EXCL
	}

	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()

		return err
	}

	return file.Close()
}

func LoadNotationSigningkeys(tdir string) (*notconfig.SigningKeys, error) {
	var err error

	var signingKeysInfo *notconfig.SigningKeys

	filePath := path.Join(tdir, "notation/signingkeys.json")

	file, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// create file
			newSigningKeys := notconfig.NewSigningKeys()

			newFile, err := os.Create(filePath)
			if err != nil {
				return newSigningKeys, err
			}

			defer newFile.Close()

			encoder := json.NewEncoder(newFile)
			encoder.SetIndent("", "    ")

			err = encoder.Encode(newSigningKeys)

			return newSigningKeys, err
		}

		return nil, err
	}

	defer file.Close()

	err = json.NewDecoder(file).Decode(&signingKeysInfo)

	return signingKeysInfo, err
}

func VerifyWithNotation(reference string, tdir string) error {
	// check if trustpolicy.json exists
	trustpolicyPath := path.Join(tdir, "notation/trustpolicy.json")

	if _, err := os.Stat(trustpolicyPath); errors.Is(err, os.ErrNotExist) {
		trustPolicy := `
			{
				"version": "1.0",
				"trustPolicies": [
					{
						"name": "good",
						"registryScopes": [ "*" ],
						"signatureVerification": {
							"level" : "audit"
						},
						"trustStores": ["ca:good"],
						"trustedIdentities": [
							"*"
						]
					}
				]
			}`

		file, err := os.Create(trustpolicyPath)
		if err != nil {
			return err
		}

		defer file.Close()

		_, err = file.WriteString(trustPolicy)
		if err != nil {
			return err
		}
	}

	// start verifying signatures
	ctx := context.TODO()

	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	plainHTTP := true

	// Resolve referance
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repositoryOpts := notreg.RepositoryOptions{}

	repo := notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	manifestDesc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return err
	}

	if err := ref.ValidateReferenceAsDigest(); err != nil {
		ref.Reference = manifestDesc.Digest.String()
	}

	// getVerifier
	newVerifier, err := verifier.NewFromConfig()
	if err != nil {
		return err
	}

	remoteRepo = &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repo = notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	configs := map[string]string{}

	verifyOpts := notation.VerifyOptions{
		ArtifactReference:    ref.String(),
		PluginConfig:         configs,
		MaxSignatureAttempts: math.MaxInt64,
	}

	_, outcomes, err := notation.Verify(ctx, newVerifier, repo, verifyOpts)
	if err != nil || len(outcomes) == 0 {
		return ErrSignatureVerification
	}

	return nil
}

func ListNotarySignatures(reference string, tdir string) ([]godigest.Digest, error) {
	signatures := []godigest.Digest{}

	ctx := context.TODO()

	// getSignatureRepository
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return signatures, err
	}

	plainHTTP := true

	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	sigRepo := notreg.NewRepository(remoteRepo)

	artifactDesc, err := sigRepo.Resolve(ctx, reference)
	if err != nil {
		return signatures, err
	}

	err = sigRepo.ListSignatures(ctx, artifactDesc, func(signatureManifests []ispec.Descriptor) error {
		for _, sigManifestDesc := range signatureManifests {
			signatures = append(signatures, sigManifestDesc.Digest)
		}

		return nil
	})

	return signatures, err
}

func LoadNotationConfig(tdir string) (*notconfig.Config, error) {
	var configInfo *notconfig.Config

	filePath := path.Join(tdir, "notation/signingkeys.json")

	file, err := os.Open(filePath)
	if err != nil {
		return configInfo, err
	}

	defer file.Close()

	err = json.NewDecoder(file).Decode(&configInfo)
	if err != nil {
		return configInfo, err
	}

	// set default value
	configInfo.SignatureFormat = strings.ToLower(configInfo.SignatureFormat)
	if configInfo.SignatureFormat == "" {
		configInfo.SignatureFormat = "jws"
	}

	return configInfo, nil
}

type isser interface {
	Is(string) bool
}

// Index returns the index of the first occurrence of name in s,
// or -1 if not present.
func Index[E isser](s []E, name string) int {
	for i, v := range s {
		if v.Is(name) {
			return i
		}
	}

	return -1
}

// Contains reports whether name is present in s.
func Contains[E isser](s []E, name string) bool {
	return Index(s, name) >= 0
}
