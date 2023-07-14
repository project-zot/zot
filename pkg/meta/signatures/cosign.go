package signatures

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/options"

	zerr "zotregistry.io/zot/errors"
)

const (
	CosignSigKey          = "dev.cosignproject.cosign/signature"
	cosignDirRelativePath = "_cosign"
)

var cosignDir = "" //nolint:gochecknoglobals

func InitCosignDir(rootDir string) error {
	dir := path.Join(rootDir, cosignDirRelativePath)

	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, defaultDirPerms)
		if err != nil {
			return err
		}
	}

	if err == nil {
		cosignDir = dir
	}

	return err
}

func GetCosignDirPath() (string, error) {
	if cosignDir != "" {
		return cosignDir, nil
	}

	return "", zerr.ErrSignConfigDirNotSet
}

func VerifyCosignSignature(
	repo string, digest godigest.Digest, signatureKey string, layerContent []byte,
) (string, bool, error) {
	cosignDir, err := GetCosignDirPath()
	if err != nil {
		return "", false, err
	}

	files, err := os.ReadDir(cosignDir)
	if err != nil {
		return "", false, err
	}

	for _, file := range files {
		if !file.IsDir() {
			// cosign verify the image
			ctx := context.Background()
			keyRef := path.Join(cosignDir, file.Name())
			hashAlgorithm := crypto.SHA256

			pubKey, err := sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, hashAlgorithm)
			if err != nil {
				continue
			}

			pkcs11Key, ok := pubKey.(*pkcs11key.Key)
			if ok {
				defer pkcs11Key.Close()
			}

			verifier := pubKey

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

			err = verifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx))

			if err == nil {
				publicKey, err := os.ReadFile(keyRef)
				if err != nil {
					continue
				}

				return string(publicKey), true, nil
			}
		}
	}

	return "", false, nil
}

func UploadPublicKey(publicKeyContent []byte) error {
	// validate public key
	if ok, err := validatePublicKey(publicKeyContent); !ok {
		return err
	}

	// add public key to "{rootDir}/_cosign/{name.pub}"
	configDir, err := GetCosignDirPath()
	if err != nil {
		return err
	}

	name := godigest.FromBytes(publicKeyContent)

	// store public key
	publicKeyPath := path.Join(configDir, name.String())

	return os.WriteFile(publicKeyPath, publicKeyContent, defaultFilePerms)
}

func validatePublicKey(publicKeyContent []byte) (bool, error) {
	_, err := cryptoutils.UnmarshalPEMToPublicKey(publicKeyContent)
	if err != nil {
		return false, fmt.Errorf("%w: %w", zerr.ErrInvalidPublicKeyContent, err)
	}

	return true, nil
}
