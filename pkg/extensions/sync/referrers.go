//go:build sync
// +build sync

package sync

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/referrer"

	"zotregistry.dev/zot/pkg/common"
)

const (
	cosignSignatureTagSuffix = "sig"
	SBOMTagSuffix            = "sbom"
)

func hasSignatureReferrers(refs referrer.ReferrerList) bool {
	for _, desc := range refs.Descriptors {
		tag := desc.Annotations[ispec.AnnotationRefName]

		if common.IsCosignSignature(tag) {
			return true
		}

		if desc.ArtifactType == common.ArtifactTypeNotation {
			return true
		}

		if desc.ArtifactType == common.ArtifactTypeCosign {
			return true
		}
	}

	return false
}
