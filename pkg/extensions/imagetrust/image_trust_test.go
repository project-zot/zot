//go:build imagetrust

package imagetrust_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	guuid "github.com/gofrs/uuid"
	"github.com/notaryproject/notation-go"
	notreg "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/imagetrust"
	"zotregistry.dev/zot/v2/pkg/log"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	"zotregistry.dev/zot/v2/pkg/test/signature"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

var (
	errExpiryError     = errors.New("expiry err")
	errUnexpectedError = errors.New("unexpected err")
)

func TestInitCosignAndNotationDirs(t *testing.T) {
	Convey("InitCosignDir error", t, func() {
		dir := t.TempDir()
		err := os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewPublicKeyLocalStorage(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o500)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewPublicKeyLocalStorage(dir)
		So(err, ShouldNotBeNil)

		pubKeyStorage := &imagetrust.PublicKeyLocalStorage{}
		cosignDir, err := pubKeyStorage.GetCosignDirPath()
		So(cosignDir, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})

	Convey("InitNotationDir error", t, func() {
		dir := t.TempDir()
		err := os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewPublicKeyLocalStorage(dir)
		So(err, ShouldNotBeNil)

		_, err = imagetrust.NewCertificateLocalStorage(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o500)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewPublicKeyLocalStorage(dir)
		So(err, ShouldNotBeNil)

		_, err = imagetrust.NewCertificateLocalStorage(dir)
		So(err, ShouldNotBeNil)

		certStorage := &imagetrust.CertificateLocalStorage{}
		notationDir, err := certStorage.GetNotationDirPath()
		So(notationDir, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})

	Convey("UploadCertificate - notationDir is not set", t, func() {
		rootDir := t.TempDir()

		signature.NotationPathLock.Lock()
		defer signature.NotationPathLock.Unlock()

		signature.LoadNotationPath(rootDir)

		// generate a keypair
		err := signature.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		certStorgae := &imagetrust.CertificateLocalStorage{}
		err = imagetrust.UploadCertificate(certStorgae, certificateContent, "ca")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})

	Convey("UploadPublicKey - cosignDir is not set", t, func() {
		rootDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(rootDir)

		// generate a keypair
		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(rootDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		pubKeyStorage := &imagetrust.PublicKeyLocalStorage{}
		err = imagetrust.UploadPublicKey(pubKeyStorage, publicKeyContent)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})
}

func TestVerifySignatures(t *testing.T) {
	Convey("empty manifest digest", t, func() {
		image := CreateRandomImage()

		imgTrustStore := &imagetrust.ImageTrustStore{}
		_, _, _, err := imgTrustStore.VerifySignature("", []byte(""), "", "", image.AsImageMeta(), "repo")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrBadSignatureManifestDigest)
	})

	Convey("wrong signature type", t, func() {
		image := CreateRandomImage()

		imgTrustStore := &imagetrust.ImageTrustStore{}
		_, _, _, err := imgTrustStore.VerifySignature("wrongType", []byte(""), "", image.Digest(), image.AsImageMeta(),
			"repo")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidSignatureType)
	})

	Convey("verify cosign signature", t, func() {
		repo := "repo" //nolint:goconst
		tag := "test"  //nolint:goconst

		image := CreateRandomImage()

		Convey("cosignDir is not set", func() {
			imgTrustStore := &imagetrust.ImageTrustStore{
				CosignStorage: &imagetrust.PublicKeyLocalStorage{},
			}

			_, _, _, err := imgTrustStore.VerifySignature("cosign", []byte(""), "", image.Digest(), image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
		})

		Convey("cosignDir does not have read permissions", func() {
			dir := t.TempDir()

			pubKeyStorage, err := imagetrust.NewPublicKeyLocalStorage(dir)
			So(err, ShouldBeNil)

			cosignDir, err := pubKeyStorage.GetCosignDirPath()
			So(err, ShouldBeNil)
			err = os.Chmod(cosignDir, 0o300)
			So(err, ShouldBeNil)

			imgTrustStore := &imagetrust.ImageTrustStore{
				CosignStorage: pubKeyStorage,
			}

			_, _, _, err = imgTrustStore.VerifySignature("cosign", []byte(""), "", image.Digest(), image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
		})

		Convey("no valid public key", func() {
			dir := t.TempDir()

			pubKeyStorage, err := imagetrust.NewPublicKeyLocalStorage(dir)
			So(err, ShouldBeNil)

			cosignDir, err := pubKeyStorage.GetCosignDirPath()
			So(err, ShouldBeNil)

			err = test.WriteFileWithPermission(path.Join(cosignDir, "file"), []byte("not a public key"), 0o600, false)
			So(err, ShouldBeNil)

			imgTrustStore := &imagetrust.ImageTrustStore{
				CosignStorage: pubKeyStorage,
			}

			_, _, isTrusted, err := imgTrustStore.VerifySignature("cosign", []byte(""), "", image.Digest(), image.AsImageMeta(),
				repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeFalse)
		})

		Convey("signature is trusted", func() {
			rootDir := t.TempDir()

			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port
			conf.Storage.GC = false
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = rootDir

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(conf.HTTP.Port)
			defer cm.StopServer()

			err := UploadImage(image, baseURL, repo, tag)
			So(err, ShouldBeNil)

			pubKeyStorage, err := imagetrust.NewPublicKeyLocalStorage(rootDir)
			So(err, ShouldBeNil)

			cosignDir, err := pubKeyStorage.GetCosignDirPath()
			So(err, ShouldBeNil)

			cwd, err := os.Getwd()
			So(err, ShouldBeNil)

			_ = os.Chdir(cosignDir)

			// generate a keypair
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
			So(err, ShouldBeNil)

			_ = os.Chdir(cwd)

			// sign the image
			err = sign.SignCmd(context.TODO(),
				&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
				options.KeyOpts{KeyRef: path.Join(cosignDir, "cosign.key"), PassFunc: generate.GetPass},
				options.SignOptions{
					Registry:          options.RegistryOptions{AllowInsecure: true},
					AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=" + tag}},
					Upload:            true,
				},
				[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repo, image.DigestStr())})
			So(err, ShouldBeNil)

			err = os.Remove(path.Join(cosignDir, "cosign.key"))
			So(err, ShouldBeNil)

			indexContent, err := ctlr.StoreController.DefaultStore.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var index ispec.Index

			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			var (
				rawSignature []byte
				sigKey       string
			)

			for _, manifest := range index.Manifests {
				if manifest.Digest != image.Digest() {
					blobContent, err := ctlr.StoreController.DefaultStore.GetBlobContent(repo, manifest.Digest)
					So(err, ShouldBeNil)

					var cosignSig ispec.Manifest

					err = json.Unmarshal(blobContent, &cosignSig)
					So(err, ShouldBeNil)

					sigKey = cosignSig.Layers[0].Annotations[zcommon.CosignSigKey]

					rawSignature, err = ctlr.StoreController.DefaultStore.GetBlobContent(repo, cosignSig.Layers[0].Digest)
					So(err, ShouldBeNil)
				}
			}

			imgTrustStore := &imagetrust.ImageTrustStore{
				CosignStorage: pubKeyStorage,
			}

			// signature is trusted
			author, _, isTrusted, err := imgTrustStore.VerifySignature("cosign", rawSignature, sigKey, image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeTrue)
			So(author, ShouldNotBeEmpty)
		})
	})

	Convey("verify notation signature", t, func() {
		repo := "repo" //nolint:goconst
		tag := "test"  //nolint:goconst
		image := CreateRandomImage()

		Convey("notationDir is not set", func() {
			imgTrustStore := &imagetrust.ImageTrustStore{
				NotationStorage: &imagetrust.CertificateLocalStorage{},
			}

			_, _, _, err := imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
		})

		Convey("no signature provided", func() {
			dir := t.TempDir()

			certStorage, err := imagetrust.NewCertificateLocalStorage(dir)
			So(err, ShouldBeNil)

			imgTrustStore := &imagetrust.ImageTrustStore{
				NotationStorage: certStorage,
			}

			_, _, isTrusted, err := imgTrustStore.VerifySignature("notation", []byte(""), "", image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
			So(isTrusted, ShouldBeFalse)
		})

		Convey("trustpolicy.json does not exist", func() {
			dir := t.TempDir()

			certStorage, err := imagetrust.NewCertificateLocalStorage(dir)
			So(err, ShouldBeNil)

			notationDir, _ := certStorage.GetNotationDirPath()

			err = os.Remove(path.Join(notationDir, "trustpolicy.json"))
			So(err, ShouldBeNil)

			imgTrustStore := &imagetrust.ImageTrustStore{
				NotationStorage: certStorage,
			}

			_, _, _, err = imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
		})

		Convey("trustpolicy.json has invalid content", func() {
			dir := t.TempDir()

			certStorage, err := imagetrust.NewCertificateLocalStorage(dir)
			So(err, ShouldBeNil)

			notationDir, err := certStorage.GetNotationDirPath()
			So(err, ShouldBeNil)

			err = test.WriteFileWithPermission(path.Join(notationDir, "trustpolicy.json"), []byte("invalid content"),
				0o600, true)
			So(err, ShouldBeNil)

			imgTrustStore := &imagetrust.ImageTrustStore{
				NotationStorage: certStorage,
			}

			_, _, _, err = imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
		})

		Convey("signature is trusted", func() {
			rootDir := t.TempDir()

			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port
			conf.Storage.GC = false
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = rootDir

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(conf.HTTP.Port)
			defer cm.StopServer()

			err := UploadImage(image, baseURL, repo, tag)
			So(err, ShouldBeNil)

			certStorage, err := imagetrust.NewCertificateLocalStorage(rootDir)
			So(err, ShouldBeNil)

			notationDir, err := certStorage.GetNotationDirPath()
			So(err, ShouldBeNil)

			signature.NotationPathLock.Lock()
			defer signature.NotationPathLock.Unlock()

			signature.LoadNotationPath(notationDir)

			// generate a keypair
			err = signature.GenerateNotationCerts(notationDir, "notation-sign-test")
			So(err, ShouldBeNil)

			// sign the imageURL
			imageURL := fmt.Sprintf("localhost:%s/%s", port, fmt.Sprintf("%s:%s", repo, tag))

			err = signature.SignWithNotation("notation-sign-test", imageURL, notationDir, true)
			So(err, ShouldBeNil)

			err = test.CopyFiles(path.Join(notationDir, "notation", "truststore"), path.Join(notationDir, "truststore"))
			So(err, ShouldBeNil)

			err = os.RemoveAll(path.Join(notationDir, "notation"))
			So(err, ShouldBeNil)

			trustPolicy := `
			{
				"version": "1.0",
				"trustPolicies": [
					{
						"name": "notation-sign-test",
						"registryScopes": [ "*" ],
						"signatureVerification": {
							"level" : "strict" 
						},
						"trustStores": ["ca:notation-sign-test"],
						"trustedIdentities": [
							"*"
						]
					}
				]
			}`

			err = test.WriteFileWithPermission(path.Join(notationDir, "trustpolicy.json"), []byte(trustPolicy), 0o600, true)
			So(err, ShouldBeNil)

			indexContent, err := ctlr.StoreController.DefaultStore.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var index ispec.Index

			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			var (
				rawSignature []byte
				sigKey       string
			)

			for _, manifest := range index.Manifests {
				if manifest.Digest != image.Digest() {
					blobContent, err := ctlr.StoreController.DefaultStore.GetBlobContent(repo, manifest.Digest)
					So(err, ShouldBeNil)

					var notationSig ispec.Manifest

					err = json.Unmarshal(blobContent, &notationSig)
					So(err, ShouldBeNil)

					sigKey = notationSig.Layers[0].MediaType

					rawSignature, err = ctlr.StoreController.DefaultStore.GetBlobContent(repo, notationSig.Layers[0].Digest)
					So(err, ShouldBeNil)
				}
			}

			imgTrustStore := &imagetrust.ImageTrustStore{
				NotationStorage: certStorage,
			}

			// signature is trusted
			author, _, isTrusted, err := imgTrustStore.VerifySignature("notation", rawSignature, sigKey, image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeTrue)
			So(author, ShouldNotBeEmpty)

			err = os.Truncate(path.Join(notationDir, "truststore/x509/ca/notation-sign-test/notation-sign-test.crt"), 0)
			So(err, ShouldBeNil)

			// signature is not trusted
			author, _, isTrusted, err = imgTrustStore.VerifySignature("notation", rawSignature, sigKey, image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldNotBeNil)
			So(isTrusted, ShouldBeFalse)
			So(author, ShouldNotBeEmpty)
		})
	})
}

func TestCheckExpiryErr(t *testing.T) {
	Convey("no expiry err", t, func() {
		isExpiryErr := imagetrust.CheckExpiryErr([]*notation.ValidationResult{{Error: nil, Type: "wrongtype"}}, time.Now(),
			nil)
		So(isExpiryErr, ShouldBeFalse)

		isExpiryErr = imagetrust.CheckExpiryErr([]*notation.ValidationResult{{
			Error: nil, Type: trustpolicy.TypeAuthenticTimestamp,
		}}, time.Now(), errExpiryError)
		So(isExpiryErr, ShouldBeFalse)
	})

	Convey("expiry err", t, func() {
		isExpiryErr := imagetrust.CheckExpiryErr([]*notation.ValidationResult{
			{Error: errExpiryError, Type: trustpolicy.TypeExpiry},
		}, time.Now(), errExpiryError)
		So(isExpiryErr, ShouldBeTrue)

		isExpiryErr = imagetrust.CheckExpiryErr([]*notation.ValidationResult{
			{Error: errExpiryError, Type: trustpolicy.TypeAuthenticTimestamp},
		}, time.Now().AddDate(0, 0, -1), errExpiryError)
		So(isExpiryErr, ShouldBeTrue)
	})
}

func TestLocalTrustStoreUploadErr(t *testing.T) {
	Convey("certificate can't be stored", t, func() {
		rootDir := t.TempDir()

		signature.NotationPathLock.Lock()
		defer signature.NotationPathLock.Unlock()

		signature.LoadNotationPath(rootDir)

		// generate a keypair
		err := signature.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		certStorage, err := imagetrust.NewCertificateLocalStorage(rootDir)
		So(err, ShouldBeNil)

		notationDir, err := certStorage.GetNotationDirPath()
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca/default"), 0o100)
		So(err, ShouldBeNil)

		err = imagetrust.UploadCertificate(certStorage, certificateContent, "ca")
		So(err, ShouldNotBeNil)
	})
}

func TestLocalTrustStore(t *testing.T) {
	Convey("NewLocalImageTrustStore error", t, func() {
		rootDir := t.TempDir()
		err := os.Chmod(rootDir, 0o000)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewLocalImageTrustStore(rootDir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(rootDir, 0o700)
		So(err, ShouldBeNil)

		notationDir := path.Join(rootDir, "_notation")

		err = os.MkdirAll(notationDir, 0o000)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewLocalImageTrustStore(rootDir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(notationDir, 0o700)
		So(err, ShouldBeNil)

		err = os.MkdirAll(path.Join(notationDir, "truststore"), 0o500)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewLocalImageTrustStore(rootDir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(notationDir, "truststore"), 0o700)
		So(err, ShouldBeNil)

		err = os.MkdirAll(path.Join(notationDir, "truststore/x509/ca/default"), 0o700)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca"), 0o000)
		So(err, ShouldBeNil)

		_, err = imagetrust.NewLocalImageTrustStore(rootDir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca"), 0o700)
		So(err, ShouldBeNil)
	})

	Convey("InitTrustpolicy error", t, func() {
		notationStorage := &imagetrust.CertificateLocalStorage{}
		err := notationStorage.InitTrustpolicy([]byte{})
		So(err, ShouldNotBeNil)
	})

	Convey("GetVerifier error", t, func() {
		notationStorage := &imagetrust.CertificateLocalStorage{}
		_, err := notationStorage.GetVerifier(&trustpolicy.Document{})
		So(err, ShouldNotBeNil)
	})

	Convey("GetPublicKeyVerifier errors", t, func() {
		cosignStorage := &imagetrust.PublicKeyLocalStorage{}
		_, _, err := cosignStorage.GetPublicKeyVerifier("")
		So(err, ShouldNotBeNil)

		rootDir := t.TempDir()

		cosignStorage, err = imagetrust.NewPublicKeyLocalStorage(rootDir)
		So(err, ShouldBeNil)

		_, _, err = cosignStorage.GetPublicKeyVerifier("inexistentfile")
		So(err, ShouldNotBeNil)
	})

	Convey("test with local storage", t, func() {
		rootDir := t.TempDir()

		imageTrustStore, err := imagetrust.NewLocalImageTrustStore(rootDir)
		So(err, ShouldBeNil)

		var dbDriverParams map[string]any

		RunUploadTests(t, *imageTrustStore)
		RunVerificationTests(t, dbDriverParams)
	})
}

func TestLocalTrustStoreRedis(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("test local storage and redis", t, func() {
		rootDir := t.TempDir()

		imageTrustStore, err := imagetrust.NewLocalImageTrustStore(rootDir)
		So(err, ShouldBeNil)

		dbDriverParams := map[string]any{
			"name": "redis",
			"url":  "redis://" + miniRedis.Addr(),
		}

		RunUploadTests(t, *imageTrustStore)
		RunVerificationTests(t, dbDriverParams)
	})
}

func TestAWSTrustStore(t *testing.T) {
	tskip.SkipDynamo(t)

	trustpolicyDoc := "trustpolicy"

	Convey("NewAWSImageTrustStore error", t, func() {
		_, err := imagetrust.NewAWSImageTrustStore("us-east-2", "wrong;endpoint")
		So(err, ShouldNotBeNil)
	})

	Convey("InitTrustpolicy retry", t, func() {
		content := "trustpolicy content"
		secretsManagerMock := mocks.SecretsManagerMock{
			DeleteSecretFn: func(ctx context.Context, params *secretsmanager.DeleteSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.DeleteSecretOutput, error) {
				return &secretsmanager.DeleteSecretOutput{}, nil
			},
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				return &secretsmanager.CreateSecretOutput{}, getResourceExistsException()
			},
		}
		secretsManagerCacheMock := mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return "", errUnexpectedError
			},
		}

		_, err := imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldNotBeNil)

		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return content, nil
			},
		}

		_, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldNotBeNil)

		secretsManagerMock = mocks.SecretsManagerMock{
			DeleteSecretFn: func(ctx context.Context, params *secretsmanager.DeleteSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.DeleteSecretOutput, error) {
				return &secretsmanager.DeleteSecretOutput{}, errUnexpectedError
			},
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				return &secretsmanager.CreateSecretOutput{}, getResourceExistsException()
			},
		}

		_, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldNotBeNil)

		errVal := make(chan bool)

		secretsManagerMock = mocks.SecretsManagerMock{
			DeleteSecretFn: func(ctx context.Context, params *secretsmanager.DeleteSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.DeleteSecretOutput, error) {
				go func() {
					time.Sleep(3 * time.Second)

					errVal <- true
				}()

				return &secretsmanager.DeleteSecretOutput{}, nil
			},
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				select {
				case <-errVal:
					return &secretsmanager.CreateSecretOutput{}, nil
				default:
					return &secretsmanager.CreateSecretOutput{}, getResourceExistsException()
				}
			},
		}

		_, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)
	})

	Convey("GetCertificates errors", t, func() {
		name := "ca/test/digest"
		content := "invalid certificate content"

		secretsManagerMock := mocks.SecretsManagerMock{
			DeleteSecretFn: func(ctx context.Context, params *secretsmanager.DeleteSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.DeleteSecretOutput, error) {
				return &secretsmanager.DeleteSecretOutput{}, nil
			},
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				if *params.Name == trustpolicyDoc {
					return &secretsmanager.CreateSecretOutput{}, nil
				}

				return &secretsmanager.CreateSecretOutput{}, errUnexpectedError
			},
			ListSecretsFn: func(ctx context.Context, params *secretsmanager.ListSecretsInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.ListSecretsOutput, error) {
				return &secretsmanager.ListSecretsOutput{
					SecretList: []types.SecretListEntry{{Name: &name}},
				}, nil
			},
		}
		secretsManagerCacheMock := mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return content, nil
			},
		}

		notationStorage, err := imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		_, err = notationStorage.GetCertificates(context.Background(), "wrongType", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidTruststoreType)

		_, err = notationStorage.GetCertificates(context.Background(), "ca", "invalid;name")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidTruststoreName)

		_, err = notationStorage.GetCertificates(context.Background(), "ca", "test")
		So(err, ShouldNotBeNil)

		newName := "ca/newtest/digest"
		newSecret := base64.StdEncoding.EncodeToString([]byte(content))

		secretsManagerMock = mocks.SecretsManagerMock{
			DeleteSecretFn: func(ctx context.Context, params *secretsmanager.DeleteSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.DeleteSecretOutput, error) {
				return &secretsmanager.DeleteSecretOutput{}, nil
			},
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				if *params.Name == trustpolicyDoc {
					return &secretsmanager.CreateSecretOutput{}, nil
				}

				return &secretsmanager.CreateSecretOutput{}, errUnexpectedError
			},
			ListSecretsFn: func(ctx context.Context, params *secretsmanager.ListSecretsInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.ListSecretsOutput, error) {
				return &secretsmanager.ListSecretsOutput{
					SecretList: []types.SecretListEntry{{Name: &newName}},
				}, nil
			},
		}
		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return newSecret, nil
			},
		}

		notationStorage, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		_, err = notationStorage.GetCertificates(context.Background(), "ca", "newtest")
		So(err, ShouldNotBeNil)

		secretsManagerMock = mocks.SecretsManagerMock{
			ListSecretsFn: func(ctx context.Context, params *secretsmanager.ListSecretsInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.ListSecretsOutput, error) {
				return &secretsmanager.ListSecretsOutput{}, errUnexpectedError
			},
		}

		notationStorage, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		_, err = notationStorage.GetCertificates(context.Background(), "ca", "newtest")
		So(err, ShouldNotBeNil)

		secretsManagerMock = mocks.SecretsManagerMock{
			ListSecretsFn: func(ctx context.Context, params *secretsmanager.ListSecretsInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.ListSecretsOutput, error) {
				return &secretsmanager.ListSecretsOutput{SecretList: []types.SecretListEntry{{Name: &name}}}, nil
			},
		}

		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return "", errUnexpectedError
			},
		}

		notationStorage, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		_, err = notationStorage.GetCertificates(context.Background(), "ca", "newtest")
		So(err, ShouldNotBeNil)
	})

	Convey("GetPublicKeyVerifier errors", t, func() {
		secretsManagerMock := mocks.SecretsManagerMock{}
		secretsManagerCacheMock := mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return "", errUnexpectedError
			},
		}

		cosignStorage := imagetrust.NewPublicKeyAWSStorage(secretsManagerMock, secretsManagerCacheMock)

		_, _, err := cosignStorage.GetPublicKeyVerifier("badsecret")
		So(err, ShouldNotBeNil)

		secretName := "digest"
		secret := "invalid public key content"

		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return secret, nil
			},
		}

		cosignStorage = imagetrust.NewPublicKeyAWSStorage(secretsManagerMock, secretsManagerCacheMock)

		_, _, err = cosignStorage.GetPublicKeyVerifier(secretName)
		So(err, ShouldNotBeNil)

		newSecret := base64.StdEncoding.EncodeToString([]byte(secret))

		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return newSecret, nil
			},
		}

		cosignStorage = imagetrust.NewPublicKeyAWSStorage(secretsManagerMock, secretsManagerCacheMock)

		_, _, err = cosignStorage.GetPublicKeyVerifier(secretName)
		So(err, ShouldNotBeNil)
	})

	Convey("GetPublicKeys error", t, func() {
		secretsManagerMock := mocks.SecretsManagerMock{
			ListSecretsFn: func(ctx context.Context, params *secretsmanager.ListSecretsInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.ListSecretsOutput, error) {
				return &secretsmanager.ListSecretsOutput{}, errUnexpectedError
			},
		}

		cosignStorage := imagetrust.NewPublicKeyAWSStorage(secretsManagerMock, nil)

		_, err := cosignStorage.GetPublicKeys()
		So(err, ShouldNotBeNil)
	})

	Convey("StorePublicKeys error", t, func() {
		secretsManagerMock := mocks.SecretsManagerMock{
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				return &secretsmanager.CreateSecretOutput{}, errUnexpectedError
			},
		}

		cosignStorage := imagetrust.NewPublicKeyAWSStorage(secretsManagerMock, nil)

		err := cosignStorage.StorePublicKey(digest.FromString("dig"), []byte("content"))
		So(err, ShouldNotBeNil)

		secretsManagerMock = mocks.SecretsManagerMock{
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				return &secretsmanager.CreateSecretOutput{}, getResourceExistsException()
			},
		}

		cosignStorage = imagetrust.NewPublicKeyAWSStorage(secretsManagerMock, nil)

		err = cosignStorage.StorePublicKey(digest.FromString("dig"), []byte("content"))
		So(err, ShouldBeNil)
	})

	Convey("StoreCertificate error", t, func() {
		secretsManagerMock := mocks.SecretsManagerMock{
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				if *params.Name != trustpolicyDoc {
					return &secretsmanager.CreateSecretOutput{}, getResourceExistsException()
				}

				return &secretsmanager.CreateSecretOutput{}, nil
			},
		}

		notationStorage, err := imagetrust.NewCertificateAWSStorage(secretsManagerMock, nil)
		So(err, ShouldBeNil)

		err = notationStorage.StoreCertificate([]byte("content"), "ca")
		So(err, ShouldBeNil)
	})

	Convey("VerifySignature - trustpolicy.json does not exist", t, func() {
		repo := "repo"
		image := CreateRandomImage()

		secretsManagerMock := mocks.SecretsManagerMock{
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				return &secretsmanager.CreateSecretOutput{}, nil
			},
		}

		secretsManagerCacheMock := mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return "", errUnexpectedError
			},
		}

		notationStorage, err := imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		imgTrustStore := &imagetrust.ImageTrustStore{
			NotationStorage: notationStorage,
		}

		_, _, _, err = imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
			image.AsImageMeta(), repo)
		So(err, ShouldNotBeNil)
	})

	Convey("VerifySignature - trustpolicy.json has invalid content", t, func() {
		repo := "repo"
		image := CreateRandomImage()

		secretsManagerMock := mocks.SecretsManagerMock{
			CreateSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput,
				optFns ...func(*secretsmanager.Options),
			) (*secretsmanager.CreateSecretOutput, error) {
				return &secretsmanager.CreateSecretOutput{}, nil
			},
		}

		secretsManagerCacheMock := mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return "invalid content", nil
			},
		}

		notationStorage, err := imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		imgTrustStore := &imagetrust.ImageTrustStore{
			NotationStorage: notationStorage,
		}

		_, _, _, err = imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
			image.AsImageMeta(), repo)
		So(err, ShouldNotBeNil)

		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return base64.StdEncoding.EncodeToString([]byte("invalid content")), nil
			},
		}

		notationStorage, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		imgTrustStore = &imagetrust.ImageTrustStore{
			NotationStorage: notationStorage,
		}

		_, _, _, err = imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
			image.AsImageMeta(), repo)
		So(err, ShouldNotBeNil)

		secretsManagerCacheMock = mocks.SecretsManagerCacheMock{
			GetSecretStringFn: func(secretID string) (string, error) {
				return base64.StdEncoding.EncodeToString([]byte(`{"Version": {"bad": "input"}}`)), nil
			},
		}

		notationStorage, err = imagetrust.NewCertificateAWSStorage(secretsManagerMock, secretsManagerCacheMock)
		So(err, ShouldBeNil)

		imgTrustStore = &imagetrust.ImageTrustStore{
			NotationStorage: notationStorage,
		}

		_, _, _, err = imgTrustStore.VerifySignature("notation", []byte("signature"), "", image.Digest(),
			image.AsImageMeta(), repo)
		So(err, ShouldNotBeNil)
	})

	Convey("test with AWS storage", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		cacheTablename := "BlobTable" + uuid.String()
		repoMetaTablename := "RepoMetadataTable" + uuid.String()
		versionTablename := "Version" + uuid.String()
		userDataTablename := "UserDataTable" + uuid.String()
		apiKeyTablename := "ApiKeyTable" + uuid.String()
		imageMetaTablename := "imageMetaTable" + uuid.String()
		repoBlobsInfoTablename := "repoBlobsInfoTable" + uuid.String()

		dynamoDBDriverParams := map[string]any{
			"name":                   "dynamodb",
			"endpoint":               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			"region":                 "us-east-2",
			"cachetablename":         cacheTablename,
			"repometatablename":      repoMetaTablename,
			"imagemetatablename":     imageMetaTablename,
			"repoblobsinfotablename": repoBlobsInfoTablename,
			"userdatatablename":      userDataTablename,
			"apikeytablename":        apiKeyTablename,
			"versiontablename":       versionTablename,
		}

		t.Logf("using dynamo driver options: %v", dynamoDBDriverParams)

		imageTrustStore, err := imagetrust.NewAWSImageTrustStore(
			"us-east-2",
			os.Getenv("DYNAMODBMOCK_ENDPOINT"),
		)
		So(err, ShouldBeNil)

		RunUploadTests(t, *imageTrustStore)
		RunVerificationTests(t, dynamoDBDriverParams)
	})
}

func RunUploadTests(t *testing.T, imageTrustStore imagetrust.ImageTrustStore) { //nolint: thelper
	cosignStorage := imageTrustStore.CosignStorage
	notationStorage := imageTrustStore.NotationStorage

	Convey("public key - invalid content", func() {
		err := imagetrust.UploadPublicKey(cosignStorage, []byte("wrong content"))
		So(err, ShouldNotBeNil)
	})

	Convey("upload public key successfully", func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		keyDir := t.TempDir()
		_ = os.Chdir(keyDir)

		// generate a keypair
		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		err = imagetrust.UploadPublicKey(cosignStorage, publicKeyContent)
		So(err, ShouldBeNil)
	})

	Convey("invalid truststore type", func() {
		err := imagetrust.UploadCertificate(notationStorage,
			[]byte("certificate content"), "wrongType",
		)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidTruststoreType)
	})

	Convey("invalid certificate content", func() {
		content := "invalid certificate content"

		err := imagetrust.UploadCertificate(notationStorage,
			[]byte(content), "ca",
		)
		So(err, ShouldNotBeNil)

		content = `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
		`

		err = imagetrust.UploadCertificate(notationStorage,
			[]byte(content), "ca",
		)
		So(err, ShouldNotBeNil)

		content = ``

		err = imagetrust.UploadCertificate(notationStorage,
			[]byte(content), "ca",
		)
		So(err, ShouldNotBeNil)
	})

	Convey("upload certificate successfully", func() {
		certDir := t.TempDir()

		signature.NotationPathLock.Lock()
		defer signature.NotationPathLock.Unlock()

		signature.LoadNotationPath(certDir)

		// generate a keypair
		err := signature.GenerateNotationCerts(certDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(certDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = imagetrust.UploadCertificate(notationStorage, certificateContent, "ca")
		So(err, ShouldBeNil)
	})
}

func RunVerificationTests(t *testing.T, dbDriverParams map[string]any) { //nolint: thelper
	Convey("verify signatures are trusted", func() {
		defaultValue := true
		rootDir := t.TempDir()
		logFile := test.MakeTempFile(t, "zot-log.txt")
		defer logFile.Close()

		writers := io.MultiWriter(os.Stdout, logFile)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false

		if dbDriverParams != nil {
			conf.Storage.RemoteCache = true

			conf.Storage.CacheDriver = dbDriverParams
		}
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultValue
		conf.Extensions.Trust.Cosign = defaultValue
		conf.Extensions.Trust.Notation = defaultValue

		ctlr := api.NewController(conf)
		ctlr.Log = log.NewLoggerWithWriter("debug", writers)
		ctlr.Config.Storage.RootDirectory = rootDir

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		repo := "repo" //nolint:goconst
		tag := "test"  //nolint:goconst

		Convey("verify running an image trust with context done", func() {
			image := CreateRandomImage()

			err := UploadImage(image, baseURL, repo, tag)
			So(err, ShouldBeNil)
		})

		Convey("verify cosign signature is trusted", func() {
			image := CreateRandomImage()

			err := UploadImage(image, baseURL, repo, tag)
			So(err, ShouldBeNil)

			cwd, err := os.Getwd()
			So(err, ShouldBeNil)

			keyDir := t.TempDir()
			_ = os.Chdir(keyDir)

			// generate a keypair
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
			So(err, ShouldBeNil)

			_ = os.Chdir(cwd)

			// sign the image
			err = sign.SignCmd(context.TODO(),
				&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
				options.KeyOpts{KeyRef: path.Join(keyDir, "cosign.key"), PassFunc: generate.GetPass},
				options.SignOptions{
					Registry:          options.RegistryOptions{AllowInsecure: true},
					AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=" + tag}},
					Upload:            true,
				},
				[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repo, image.DigestStr())})
			So(err, ShouldBeNil)

			indexContent, err := ctlr.StoreController.DefaultStore.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var index ispec.Index

			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			var (
				rawSignature []byte
				sigKey       string
			)

			for _, manifest := range index.Manifests {
				if manifest.Digest != image.Digest() {
					blobContent, err := ctlr.StoreController.DefaultStore.GetBlobContent(repo, manifest.Digest)
					So(err, ShouldBeNil)

					var cosignSig ispec.Manifest

					err = json.Unmarshal(blobContent, &cosignSig)
					So(err, ShouldBeNil)

					sigKey = cosignSig.Layers[0].Annotations[zcommon.CosignSigKey]

					rawSignature, err = ctlr.StoreController.DefaultStore.GetBlobContent(repo, cosignSig.Layers[0].Digest)
					So(err, ShouldBeNil)
				}
			}

			publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
			So(err, ShouldBeNil)
			So(publicKeyContent, ShouldNotBeNil)

			// upload the public key
			client := resty.New()
			resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
				SetBody(publicKeyContent).Post(baseURL + constants.FullCosign)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			imageTrustStore := ctlr.MetaDB.ImageTrustStore()

			// signature is trusted
			author, _, isTrusted, err := imageTrustStore.VerifySignature("cosign", rawSignature, sigKey, image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeTrue)
			So(author, ShouldNotBeEmpty)

			Convey("run imagetrust task with context done", func() {
				repoMeta, err := ctlr.MetaDB.GetRepoMeta(context.Background(), repo)
				So(err, ShouldBeNil)

				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				task := imagetrust.NewValidityTask(ctlr.MetaDB, repoMeta, ctlr.Log)
				err = task.DoWork(cancelCtx)
				So(err, ShouldEqual, cancelCtx.Err())
			})
		})

		Convey("verify notation signature is trusted", func() {
			image := CreateRandomImage()

			err := UploadImage(image, baseURL, repo, tag)
			So(err, ShouldBeNil)

			notationDir := t.TempDir()

			signature.NotationPathLock.Lock()
			defer signature.NotationPathLock.Unlock()

			signature.LoadNotationPath(notationDir)

			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)

			certName := fmt.Sprintf("notation-sign-test-%s", uuid)

			// generate a keypair
			err = signature.GenerateNotationCerts(notationDir, certName)
			So(err, ShouldBeNil)

			// sign the image
			imageURL := fmt.Sprintf("localhost:%s/%s", port, fmt.Sprintf("%s:%s", repo, tag))

			err = signature.SignWithNotation(certName, imageURL, notationDir, false)
			So(err, ShouldBeNil)

			indexContent, err := ctlr.StoreController.DefaultStore.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var index ispec.Index
			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			var (
				rawSignature []byte
				sigKey       string
			)

			for _, manifest := range index.Manifests {
				blobContent, err := ctlr.StoreController.DefaultStore.GetBlobContent(repo, manifest.Digest)
				So(err, ShouldBeNil)

				var notationSig ispec.Manifest

				err = json.Unmarshal(blobContent, &notationSig)
				So(err, ShouldBeNil)

				t.Logf("Processing manifest %v", notationSig)

				if notationSig.Config.MediaType != notreg.ArtifactTypeNotation ||
					notationSig.Subject.Digest != image.Digest() {
					continue
				}

				sigKey = notationSig.Layers[0].MediaType

				rawSignature, err = ctlr.StoreController.DefaultStore.GetBlobContent(repo, notationSig.Layers[0].Digest)
				So(err, ShouldBeNil)

				t.Logf("Identified notation signature manifest %v", notationSig)

				break
			}

			So(sigKey, ShouldNotBeEmpty)

			certificateContent, err := os.ReadFile(
				path.Join(notationDir,
					"notation/truststore/x509/ca/"+certName,
					certName+".crt",
				),
			)
			So(err, ShouldBeNil)
			So(certificateContent, ShouldNotBeNil)

			client := resty.New()
			resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
				SetBody(certificateContent).Post(baseURL + constants.FullNotation)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			imageTrustStore := ctlr.MetaDB.ImageTrustStore()

			// signature is trusted
			author, _, isTrusted, err := imageTrustStore.VerifySignature("notation", rawSignature, sigKey, image.Digest(),
				image.AsImageMeta(), repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeTrue)
			So(author, ShouldEqual, "CN=cert,O=Notary,L=Seattle,ST=WA,C=US")
		})
	})
}

func getResourceExistsException() error {
	errAlreadyExists := "the secret already exists"

	return &smithy.OperationError{
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Err: &types.ResourceExistsException{
					Message: &errAlreadyExists,
				},
			},
		},
	}
}
