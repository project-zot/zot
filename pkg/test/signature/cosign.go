package signature

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
)

func GetCosignSignatureTagForManifest(manifest ispec.Manifest) (string, error) {
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}

	manifestDigest := godigest.FromBytes(manifestBlob)

	return GetCosignSignatureTagForDigest(manifestDigest), nil
}

func GetCosignSignatureTagForDigest(manifestDigest godigest.Digest) string {
	return manifestDigest.Algorithm().String() + "-" + manifestDigest.Encoded() + ".sig"
}

func SignImageUsingCosign(repoTag, port string, withReferrers bool) error {
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

	signOpts := options.SignOptions{
		Registry:          options.RegistryOptions{AllowInsecure: true},
		AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=1.0"}},
		Upload:            true,
	}

	if withReferrers {
		signOpts.RegistryExperimental = options.RegistryExperimentalOptions{
			RegistryReferrersMode: options.RegistryReferrersModeOCI11,
		}
	}

	// sign the image
	return sign.SignCmd(context.TODO(),
		&options.RootOptions{Verbose: true, Timeout: timeoutPeriod * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		signOpts,
		[]string{imageURL})
}
