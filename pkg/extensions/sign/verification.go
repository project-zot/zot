package sign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/storage"
)

const sig = "dev.cosignproject.cosign/signature"

func isSigned(tags []string) bool {
	for _, tag := range tags {
		if strings.Contains(tag, "sig") {
			return true
		}
	}
	return false
}

func VerifyRepo(repo string, is storage.ImageStore, keyPath string) error {
	tags, err := is.GetImageTags(repo)

	if err != nil {
		return err
	}

	ok := isSigned(tags)

	if ok {
		verifier, err := GenerateVerifier(keyPath)
		if err != nil {
			return err
		}

		if err = VerifySignature(repo, is, verifier); err != nil {
			return err
		}
		return nil
	} else {
		return errors.ErrNoSignatureProvided
	}
}

func GenerateVerifier(keyPath string) (signature.Verifier, error) {
	keyRef := keyPath
	var pubKey signature.Verifier
	pubKey, err := sigs.PublicKeyFromKeyRef(context.TODO(), keyRef)

	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func VerifySignature(repo string, is storage.ImageStore, verifier signature.Verifier) error {

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return err
	}

	var index ispec.Index
	err = json.Unmarshal(buf, &index)
	if err != nil {
		return err
	}

	var sigManifest ispec.Manifest
	buf, err = is.GetBlobContent(repo, string(index.Manifests[1].Digest))

	if err != nil {
		return err
	}

	err = json.Unmarshal(buf, &sigManifest)

	b64sig := sigManifest.Layers[0].Annotations[sig]

	signature, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return err
	}

	payload, err := is.GetBlobContent(repo, string(sigManifest.Layers[0].Digest))
	if err != nil {
		return err
	}

	var ctx context.Context
	return verifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx))
}
