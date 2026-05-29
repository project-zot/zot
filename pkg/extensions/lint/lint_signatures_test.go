//go:build lint

package lint_test

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/lint"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
)

func TestMandatorySignaturesFunction(t *testing.T) {
	Convey("mandatory signatures check passes with trusted signature", t, func() {
		enable := true
		lintConfig := &extconf.LintConfig{
			BaseConfig:          extconf.BaseConfig{Enable: &enable},
			MandatorySignatures: []string{"zot-test"},
		}

		dir := t.TempDir()
		testStoreCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
		err := WriteImageToFileSystem(CreateRandomImage(), "zot-test", "0.0.1", testStoreCtlr)
		So(err, ShouldBeNil)

		manifestDigest, err := appendCosignSignatureManifest(dir, "zot-test")
		So(err, ShouldBeNil)

		linter := lint.NewLinter(lintConfig, log.NewTestLogger())
		linter.SetSignatureVerifier(mockImageTrustStore{trusted: true}, true)

		imgStore := local.NewImageStore(dir, false, false,
			log.NewTestLogger(), monitoring.NewMetricsServer(false, log.NewTestLogger()), linter, nil, nil, nil)

		pass, err := linter.CheckMandatorySignatures("zot-test", manifestDigest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("mandatory signatures check rejects unsigned images", t, func() {
		enable := true
		lintConfig := &extconf.LintConfig{
			BaseConfig:          extconf.BaseConfig{Enable: &enable},
			MandatorySignatures: []string{"zot-test"},
		}

		dir := t.TempDir()
		testStoreCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
		err := WriteImageToFileSystem(CreateRandomImage(), "zot-test", "0.0.1", testStoreCtlr)
		So(err, ShouldBeNil)

		indexContent, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)

		var index ispec.Index
		err = json.Unmarshal(indexContent, &index)
		So(err, ShouldBeNil)

		linter := lint.NewLinter(lintConfig, log.NewTestLogger())
		linter.SetSignatureVerifier(mockImageTrustStore{trusted: true}, true)

		imgStore := local.NewImageStore(dir, false, false,
			log.NewTestLogger(), monitoring.NewMetricsServer(false, log.NewTestLogger()), linter, nil, nil, nil)

		pass, err := linter.CheckMandatorySignatures("zot-test", index.Manifests[0].Digest, imgStore)
		So(err, ShouldNotBeNil)
		So(pass, ShouldBeFalse)
	})

	Convey("mandatory signatures check is skipped for non-matching repositories", t, func() {
		enable := true
		lintConfig := &extconf.LintConfig{
			BaseConfig:          extconf.BaseConfig{Enable: &enable},
			MandatorySignatures: []string{"another-repo"},
		}

		dir := t.TempDir()
		testStoreCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
		err := WriteImageToFileSystem(CreateRandomImage(), "zot-test", "0.0.1", testStoreCtlr)
		So(err, ShouldBeNil)

		indexContent, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)

		var index ispec.Index
		err = json.Unmarshal(indexContent, &index)
		So(err, ShouldBeNil)

		linter := lint.NewLinter(lintConfig, log.NewTestLogger())
		linter.SetSignatureVerifier(mockImageTrustStore{trusted: true}, true)

		imgStore := local.NewImageStore(dir, false, false,
			log.NewTestLogger(), monitoring.NewMetricsServer(false, log.NewTestLogger()), linter, nil, nil, nil)

		pass, err := linter.CheckMandatorySignatures("zot-test", index.Manifests[0].Digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	for _, wildcard := range []string{"*", "**"} {
		wildcard := wildcard

		Convey("mandatory signatures check rejects unsigned images for wildcard repository list "+wildcard, t, func() {
			enable := true
			lintConfig := &extconf.LintConfig{
				BaseConfig:          extconf.BaseConfig{Enable: &enable},
				MandatorySignatures: []string{wildcard},
			}

			dir := t.TempDir()
			testStoreCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
			err := WriteImageToFileSystem(CreateRandomImage(), "zot-test", "0.0.1", testStoreCtlr)
			So(err, ShouldBeNil)

			indexContent, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
			So(err, ShouldBeNil)

			var index ispec.Index
			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			linter := lint.NewLinter(lintConfig, log.NewTestLogger())
			linter.SetSignatureVerifier(mockImageTrustStore{trusted: true}, true)

			imgStore := local.NewImageStore(dir, false, false,
				log.NewTestLogger(), monitoring.NewMetricsServer(false, log.NewTestLogger()), linter, nil, nil, nil)

			pass, err := linter.CheckMandatorySignatures("zot-test", index.Manifests[0].Digest, imgStore)
			So(err, ShouldNotBeNil)
			So(pass, ShouldBeFalse)
		})
	}
}

type mockImageTrustStore struct {
	trusted bool
}

func (its mockImageTrustStore) VerifySignature(signatureType string, rawSignature []byte, sigKey string,
	manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta, repo string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	return "author", time.Time{}, its.trusted, nil
}

func appendCosignSignatureManifest(rootDir, repo string) (godigest.Digest, error) {
	indexPath := path.Join(rootDir, repo, "index.json")

	indexContent, err := os.ReadFile(indexPath)
	if err != nil {
		return "", err
	}

	var index ispec.Index
	if err = json.Unmarshal(indexContent, &index); err != nil {
		return "", err
	}

	manifestDigest := index.Manifests[0].Digest

	sigLayerContent := []byte("signature")
	sigLayerDigest := godigest.FromBytes(sigLayerContent)
	sigLayerPath := filepath.Join(rootDir, repo, "blobs", sigLayerDigest.Algorithm().String(), sigLayerDigest.Encoded())
	if err = os.WriteFile(sigLayerPath, sigLayerContent, 0o600); err != nil {
		return "", err
	}

	signatureManifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    godigest.FromBytes([]byte("sig-config")),
			Size:      int64(len([]byte("sig-config"))),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
				Digest:    sigLayerDigest,
				Size:      int64(len(sigLayerContent)),
				Annotations: map[string]string{
					zcommon.CosignSigKey: "c2lnbmF0dXJl",
				},
			},
		},
		Subject: &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    manifestDigest,
		},
		ArtifactType: zcommon.ArtifactTypeCosign,
	}
	signatureManifest.SchemaVersion = 2

	signatureManifestContent, err := json.Marshal(signatureManifest)
	if err != nil {
		return "", err
	}

	signatureManifestDigest := godigest.FromBytes(signatureManifestContent)
	signatureManifestPath := filepath.Join(rootDir, repo, "blobs",
		signatureManifestDigest.Algorithm().String(), signatureManifestDigest.Encoded())
	if err = os.WriteFile(signatureManifestPath, signatureManifestContent, 0o600); err != nil {
		return "", err
	}

	index.Manifests = append(index.Manifests, ispec.Descriptor{
		MediaType:    ispec.MediaTypeImageManifest,
		Digest:       signatureManifestDigest,
		Size:         int64(len(signatureManifestContent)),
		ArtifactType: zcommon.ArtifactTypeCosign,
	})

	indexContent, err = json.Marshal(index)
	if err != nil {
		return "", err
	}

	if err = os.WriteFile(indexPath, indexContent, 0o600); err != nil {
		return "", err
	}

	return manifestDigest, nil
}
