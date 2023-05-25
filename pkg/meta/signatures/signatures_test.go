package signatures_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/meta/signatures"
	"zotregistry.io/zot/pkg/test"
)

var errExpiryError = errors.New("expiry err")

func TestInitCosignAndNotationDirs(t *testing.T) {
	Convey("InitCosignDir error", t, func() {
		dir := t.TempDir()
		err := os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		err = signatures.InitCosignAndNotationDirs(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o500)
		So(err, ShouldBeNil)

		err = signatures.InitCosignAndNotationDirs(dir)
		So(err, ShouldNotBeNil)

		cosignDir, err := signatures.GetCosignDirPath()
		So(cosignDir, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})

	Convey("InitNotationDir error", t, func() {
		dir := t.TempDir()
		err := os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		err = signatures.InitCosignAndNotationDirs(dir)
		So(err, ShouldNotBeNil)

		err = signatures.InitNotationDir(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o500)
		So(err, ShouldBeNil)

		err = signatures.InitCosignAndNotationDirs(dir)
		So(err, ShouldNotBeNil)

		err = signatures.InitNotationDir(dir)
		So(err, ShouldNotBeNil)

		notationDir, err := signatures.GetNotationDirPath()
		So(notationDir, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})

	Convey("UploadCertificate - notationDir is not set", t, func() {
		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err := test.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = signatures.UploadCertificate(certificateContent, "ca", "notation-upload-test")
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

		err = signatures.UploadPublicKey(publicKeyContent)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
	})
}

func TestVerifySignatures(t *testing.T) {
	Convey("wrong manifest content", t, func() {
		manifestContent := []byte("wrong json")

		_, _, _, err := signatures.VerifySignature("", []byte(""), "", "", manifestContent, "repo")
		So(err, ShouldNotBeNil)
	})

	Convey("empty manifest digest", t, func() {
		image, err := test.GetRandomImage("image")
		So(err, ShouldBeNil)

		manifestContent, err := json.Marshal(image.Manifest)
		So(err, ShouldBeNil)

		_, _, _, err = signatures.VerifySignature("", []byte(""), "", "", manifestContent, "repo")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrBadManifestDigest)
	})

	Convey("wrong signature type", t, func() {
		image, err := test.GetRandomImage("image")
		So(err, ShouldBeNil)

		manifestContent, err := json.Marshal(image.Manifest)
		So(err, ShouldBeNil)

		manifestDigest, err := image.Digest()
		So(err, ShouldBeNil)

		_, _, _, err = signatures.VerifySignature("wrongType", []byte(""), "", manifestDigest, manifestContent, "repo")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidSignatureType)
	})

	Convey("verify cosign signature", t, func() {
		repo := "repo"
		tag := "test"
		image, err := test.GetRandomImage(tag)
		So(err, ShouldBeNil)

		manifestContent, err := json.Marshal(image.Manifest)
		So(err, ShouldBeNil)

		manifestDigest, err := image.Digest()
		So(err, ShouldBeNil)

		Convey("cosignDir is not set", func() {
			_, _, _, err = signatures.VerifySignature("cosign", []byte(""), "", manifestDigest, manifestContent, repo)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
		})

		Convey("cosignDir does not have read permissions", func() {
			dir := t.TempDir()

			err := signatures.InitCosignDir(dir)
			So(err, ShouldBeNil)

			cosignDir, err := signatures.GetCosignDirPath()
			So(err, ShouldBeNil)
			err = os.Chmod(cosignDir, 0o300)
			So(err, ShouldBeNil)

			_, _, _, err = signatures.VerifySignature("cosign", []byte(""), "", manifestDigest, manifestContent, repo)
			So(err, ShouldNotBeNil)
		})

		Convey("no valid public key", func() {
			dir := t.TempDir()

			err := signatures.InitCosignDir(dir)
			So(err, ShouldBeNil)

			cosignDir, err := signatures.GetCosignDirPath()
			So(err, ShouldBeNil)

			err = test.WriteFileWithPermission(path.Join(cosignDir, "file"), []byte("not a public key"), 0o600, false)
			So(err, ShouldBeNil)

			_, _, isTrusted, err := signatures.VerifySignature("cosign", []byte(""), "", manifestDigest, manifestContent, repo)
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

			err := test.UploadImage(image, baseURL, repo)
			So(err, ShouldBeNil)

			err = signatures.InitCosignDir(rootDir)
			So(err, ShouldBeNil)

			cosignDir, err := signatures.GetCosignDirPath()
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
			err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
				options.KeyOpts{KeyRef: path.Join(cosignDir, "cosign.key"), PassFunc: generate.GetPass},
				options.SignOptions{
					Registry:          options.RegistryOptions{AllowInsecure: true},
					AnnotationOptions: options.AnnotationOptions{Annotations: []string{fmt.Sprintf("tag=%s", tag)}},
					Upload:            true,
				},
				[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repo, manifestDigest.String())})
			So(err, ShouldBeNil)

			err = os.Remove(path.Join(cosignDir, "cosign.key"))
			So(err, ShouldBeNil)

			indexContent, err := ctlr.StoreController.DefaultStore.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var index ispec.Index
			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			var rawSignature []byte
			var sigKey string

			for _, manifest := range index.Manifests {
				if manifest.Digest != manifestDigest {
					blobContent, err := ctlr.StoreController.DefaultStore.GetBlobContent(repo, manifest.Digest)
					So(err, ShouldBeNil)

					var cosignSig ispec.Manifest

					err = json.Unmarshal(blobContent, &cosignSig)
					So(err, ShouldBeNil)

					sigKey = cosignSig.Layers[0].Annotations[signatures.CosignSigKey]

					rawSignature, err = ctlr.StoreController.DefaultStore.GetBlobContent(repo, cosignSig.Layers[0].Digest)
					So(err, ShouldBeNil)
				}
			}

			// signature is trusted
			author, _, isTrusted, err := signatures.VerifySignature("cosign", rawSignature, sigKey, manifestDigest,
				manifestContent, repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeTrue)
			So(author, ShouldNotBeEmpty)
		})
	})

	Convey("verify notation signature", t, func() {
		repo := "repo"
		tag := "test"
		image, err := test.GetRandomImage(tag)
		So(err, ShouldBeNil)

		manifestContent, err := json.Marshal(image.Manifest)
		So(err, ShouldBeNil)

		manifestDigest, err := image.Digest()
		So(err, ShouldBeNil)

		Convey("notationDir is not set", func() {
			_, _, _, err = signatures.VerifySignature("notation", []byte("signature"), "", manifestDigest, manifestContent, repo)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrSignConfigDirNotSet)
		})

		Convey("no signature provided", func() {
			dir := t.TempDir()

			err := signatures.InitNotationDir(dir)
			So(err, ShouldBeNil)

			_, _, isTrusted, err := signatures.VerifySignature("notation", []byte(""), "", manifestDigest, manifestContent, repo)
			So(err, ShouldNotBeNil)
			So(isTrusted, ShouldBeFalse)
		})

		Convey("trustpolicy.json does not exist", func() {
			dir := t.TempDir()

			err := signatures.InitNotationDir(dir)
			So(err, ShouldBeNil)

			notationDir, _ := signatures.GetNotationDirPath()

			err = os.Remove(path.Join(notationDir, "trustpolicy.json"))
			So(err, ShouldBeNil)

			_, _, _, err = signatures.VerifySignature("notation", []byte("signature"), "", manifestDigest, manifestContent, repo)
			So(err, ShouldNotBeNil)
		})

		Convey("trustpolicy.json has invalid content", func() {
			dir := t.TempDir()

			err := signatures.InitNotationDir(dir)
			So(err, ShouldBeNil)

			notationDir, err := signatures.GetNotationDirPath()
			So(err, ShouldBeNil)

			err = test.WriteFileWithPermission(path.Join(notationDir, "trustpolicy.json"), []byte("invalid content"),
				0o600, true)
			So(err, ShouldBeNil)

			_, _, _, err = signatures.VerifySignature("notation", []byte("signature"), "", manifestDigest, manifestContent,
				repo)
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

			err := test.UploadImage(image, baseURL, repo)
			So(err, ShouldBeNil)

			err = signatures.InitNotationDir(rootDir)
			So(err, ShouldBeNil)

			notationDir, err := signatures.GetNotationDirPath()
			So(err, ShouldBeNil)

			test.NotationPathLock.Lock()
			defer test.NotationPathLock.Unlock()

			test.LoadNotationPath(notationDir)

			// generate a keypair
			err = test.GenerateNotationCerts(notationDir, "notation-sign-test")
			So(err, ShouldBeNil)

			// sign the image
			image := fmt.Sprintf("localhost:%s/%s", port, fmt.Sprintf("%s:%s", repo, tag))

			err = test.SignWithNotation("notation-sign-test", image, notationDir)
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

			var rawSignature []byte
			var sigKey string

			for _, manifest := range index.Manifests {
				if manifest.Digest != manifestDigest {
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

			// signature is trusted
			author, _, isTrusted, err := signatures.VerifySignature("notation", rawSignature, sigKey, manifestDigest,
				manifestContent, repo)
			So(err, ShouldBeNil)
			So(isTrusted, ShouldBeTrue)
			So(author, ShouldNotBeEmpty)

			err = os.Truncate(path.Join(notationDir, "truststore/x509/ca/notation-sign-test/notation-sign-test.crt"), 0)
			So(err, ShouldBeNil)

			// signature is not trusted
			author, _, isTrusted, err = signatures.VerifySignature("notation", rawSignature, sigKey, manifestDigest,
				manifestContent, repo)
			So(err, ShouldNotBeNil)
			So(isTrusted, ShouldBeFalse)
			So(author, ShouldNotBeEmpty)
		})
	})
}

func TestCheckExpiryErr(t *testing.T) {
	Convey("no expiry err", t, func() {
		isExpiryErr := signatures.CheckExpiryErr([]*notation.ValidationResult{{Error: nil, Type: "wrongtype"}}, time.Now(),
			nil)
		So(isExpiryErr, ShouldBeFalse)

		isExpiryErr = signatures.CheckExpiryErr([]*notation.ValidationResult{{
			Error: nil, Type: trustpolicy.TypeAuthenticTimestamp,
		}}, time.Now(), errExpiryError)
		So(isExpiryErr, ShouldBeFalse)
	})

	Convey("expiry err", t, func() {
		isExpiryErr := signatures.CheckExpiryErr([]*notation.ValidationResult{
			{Error: errExpiryError, Type: trustpolicy.TypeExpiry},
		}, time.Now(), errExpiryError)
		So(isExpiryErr, ShouldBeTrue)

		isExpiryErr = signatures.CheckExpiryErr([]*notation.ValidationResult{
			{Error: errExpiryError, Type: trustpolicy.TypeAuthenticTimestamp},
		}, time.Now().AddDate(0, 0, -1), errExpiryError)
		So(isExpiryErr, ShouldBeTrue)
	})
}

func TestUploadPublicKey(t *testing.T) {
	Convey("public key - invalid content", t, func() {
		err := signatures.UploadPublicKey([]byte("wrong content"))
		So(err, ShouldNotBeNil)
	})

	Convey("upload public key successfully", t, func() {
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

		err = signatures.InitCosignDir(rootDir)
		So(err, ShouldBeNil)

		err = signatures.UploadPublicKey(publicKeyContent)
		So(err, ShouldBeNil)
	})
}

func TestUploadCertificate(t *testing.T) {
	Convey("invalid truststore type", t, func() {
		err := signatures.UploadCertificate([]byte("certificate content"), "wrongType", "store")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidTruststoreType)
	})

	Convey("invalid truststore name", t, func() {
		err := signatures.UploadCertificate([]byte("certificate content"), "ca", "*store?")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrInvalidTruststoreName)
	})

	Convey("invalid certificate content", t, func() {
		err := signatures.UploadCertificate([]byte("invalid content"), "ca", "store")
		So(err, ShouldNotBeNil)

		content := `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
		`

		err = signatures.UploadCertificate([]byte(content), "ca", "store")
		So(err, ShouldNotBeNil)

		content = ``

		err = signatures.UploadCertificate([]byte(content), "ca", "store")
		So(err, ShouldNotBeNil)
	})

	Convey("truststore dir can not be created", t, func() {
		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err := test.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = signatures.InitNotationDir(rootDir)
		So(err, ShouldBeNil)

		notationDir, err := signatures.GetNotationDirPath()
		So(err, ShouldBeNil)

		err = os.Chmod(notationDir, 0o100)
		So(err, ShouldBeNil)

		err = signatures.UploadCertificate(certificateContent, "ca", "notation-upload-test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(notationDir, 0o777)
		So(err, ShouldBeNil)
	})

	Convey("certificate can't be stored", t, func() {
		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err := test.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = signatures.InitNotationDir(rootDir)
		So(err, ShouldBeNil)

		notationDir, err := signatures.GetNotationDirPath()
		So(err, ShouldBeNil)

		err = os.MkdirAll(path.Join(notationDir, "truststore/x509/ca/notation-upload-test"), 0o777)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca/notation-upload-test"), 0o100)
		So(err, ShouldBeNil)

		err = signatures.UploadCertificate(certificateContent, "ca", "notation-upload-test")
		So(err, ShouldNotBeNil)
	})

	Convey("trustpolicy - invalid content", t, func() {
		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err := test.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = signatures.InitNotationDir(rootDir)
		So(err, ShouldBeNil)

		notationDir, err := signatures.GetNotationDirPath()
		So(err, ShouldBeNil)

		err = test.WriteFileWithPermission(path.Join(notationDir, "trustpolicy.json"), []byte("invalid content"),
			0o600, true)
		So(err, ShouldBeNil)

		err = signatures.UploadCertificate(certificateContent, "ca", "notation-upload-test")
		So(err, ShouldNotBeNil)
	})

	Convey("trustpolicy - truststore already exists", t, func() {
		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err := test.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = signatures.InitNotationDir(rootDir)
		So(err, ShouldBeNil)

		notationDir, err := signatures.GetNotationDirPath()
		So(err, ShouldBeNil)

		trustpolicyDoc, err := signatures.LoadTrustPolicyDocument(notationDir)
		So(err, ShouldBeNil)

		trustpolicyDoc.TrustPolicies[0].TrustStores = append(trustpolicyDoc.TrustPolicies[0].TrustStores,
			"ca:notation-upload-test")

		trustpolicyDocContent, err := json.Marshal(trustpolicyDoc)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(notationDir, "trustpolicy.json"), trustpolicyDocContent, 0o400)
		So(err, ShouldBeNil)

		err = signatures.UploadCertificate(certificateContent, "ca", "notation-upload-test")
		So(err, ShouldBeNil)
	})

	Convey("upload certificate successfully", t, func() {
		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err := test.GenerateNotationCerts(rootDir, "notation-upload-test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "notation-upload-test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		err = signatures.InitNotationDir(rootDir)
		So(err, ShouldBeNil)

		err = signatures.UploadCertificate(certificateContent, "ca", "notation-upload-test")
		So(err, ShouldBeNil)
	})
}
