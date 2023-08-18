//go:build !imagetrust
// +build !imagetrust

package imagetrust

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
)

func InitCosignAndNotationDirs(rootDir string) error {
	return nil
}

func InitCosignDir(rootDir string) error {
	return nil
}

func InitNotationDir(rootDir string) error {
	return nil
}

func VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, manifestContent []byte,
	repo string,
) (string, time.Time, bool, error) {
	return "", time.Time{}, false, nil
}
