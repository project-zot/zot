package storage_test

// CheckIsImageSignature is a pure function (no storage backend dependency) used by
// pkg/meta/hooks.go to classify a pushed/deleted manifest as a signature or not -
// previously entirely untested despite being live production code on the metadata
// indexing path for every manifest push.

import (
	"encoding/json"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/storage"
)

func TestCheckIsImageSignature(t *testing.T) {
	t.Run("invalid manifest JSON returns an error", func(t *testing.T) {
		_, _, _, err := storage.CheckIsImageSignature("repo", []byte("not json"), "tag")
		if err == nil {
			t.Fatal("expected an error for invalid JSON")
		}
	})

	t.Run("plain manifest with no subject is not a signature", func(t *testing.T) {
		manifest := ispec.Manifest{Config: ispec.DescriptorEmptyJSON}
		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, "1.0")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if isSig {
			t.Fatal("expected not a signature")
		}

		if sigType != "" || digest != "" {
			t.Fatalf("expected empty type/digest, got %q/%q", sigType, digest)
		}
	})

	t.Run("notation artifact type with a subject is a notation signature", func(t *testing.T) {
		subjectDigest := godigest.FromString("subject-manifest")

		manifest := ispec.Manifest{
			ArtifactType: zcommon.ArtifactTypeNotation,
			Config:       ispec.DescriptorEmptyJSON,
			Subject:      &ispec.Descriptor{Digest: subjectDigest},
		}
		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, "sha256-abc.sig")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if !isSig || sigType != storage.NotationType || digest != subjectDigest {
			t.Fatalf("expected notation signature for subject %s, got isSig=%v type=%q digest=%q",
				subjectDigest, isSig, sigType, digest)
		}
	})

	t.Run("cosign artifact type with a subject is an OCI 1.1 cosign signature", func(t *testing.T) {
		subjectDigest := godigest.FromString("subject-manifest")

		manifest := ispec.Manifest{
			ArtifactType: zcommon.ArtifactTypeCosign,
			Config:       ispec.DescriptorEmptyJSON,
			Subject:      &ispec.Descriptor{Digest: subjectDigest},
		}
		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, "1.0")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if !isSig || sigType != storage.CosignType || digest != subjectDigest {
			t.Fatalf("expected cosign signature for subject %s, got isSig=%v type=%q digest=%q",
				subjectDigest, isSig, sigType, digest)
		}
	})

	t.Run("legacy cosign tag pattern is a cosign signature keyed off the tag", func(t *testing.T) {
		signedDigest := godigest.FromString("legacy-signed-manifest")

		manifest := ispec.Manifest{Config: ispec.DescriptorEmptyJSON}
		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		reference := "sha256-" + signedDigest.Encoded() + ".sig"

		isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, reference)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if !isSig || sigType != storage.CosignType || digest != signedDigest {
			t.Fatalf("expected legacy cosign signature for %s, got isSig=%v type=%q digest=%q",
				signedDigest, isSig, sigType, digest)
		}
	})
}
