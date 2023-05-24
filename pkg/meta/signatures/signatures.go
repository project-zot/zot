package signatures

import (
	"encoding/json"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
)

const (
	CosignSignature   = "cosign"
	NotationSignature = "notation"
	defaultDirPerms   = 0o700
)

func InitCosignAndNotationDirs(rootDir string) error {
	err := InitCosignDir(rootDir)
	if err != nil {
		return err
	}

	err = InitNotationDir(rootDir)

	return err
}

func VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, manifestContent []byte,
	repo string,
) (string, time.Time, bool, error) {
	var manifest ispec.Manifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return "", time.Time{}, false, err
	}

	desc := ispec.Descriptor{
		MediaType: manifest.MediaType,
		Digest:    manifestDigest,
		Size:      int64(len(manifestContent)),
	}

	if manifestDigest.String() == "" {
		return "", time.Time{}, false, zerr.ErrBadManifestDigest
	}

	switch signatureType {
	case CosignSignature:
		author, isValid, err := VerifyCosignSignature(repo, manifestDigest, sigKey, rawSignature)

		return author, time.Time{}, isValid, err
	case NotationSignature:
		return VerifyNotationSignature(desc, manifestDigest.String(), rawSignature, sigKey)
	default:
		return "", time.Time{}, false, zerr.ErrInvalidSignatureType
	}
}
