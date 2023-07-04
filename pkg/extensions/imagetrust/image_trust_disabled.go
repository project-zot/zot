//go:build !imagetrust
// +build !imagetrust

package imagetrust

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
)

func NewLocalImageTrustStore(dir string) (*imageTrustDisabled, error) {
	return &imageTrustDisabled{}, nil
}

func NewAWSImageTrustStore(region, endpoint string) (*imageTrustDisabled, error) {
	return &imageTrustDisabled{}, nil
}

type imageTrustDisabled struct{}

func (imgTrustStore *imageTrustDisabled) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, manifestContent []byte,
	repo string,
) (string, time.Time, bool, error) {
	return "", time.Time{}, false, nil
}
