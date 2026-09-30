//go:build sync

package sync

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/referrer"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/common"
)

func TestHasSignatureReferrers(t *testing.T) {
	Convey("cosign bundle attestations do not count as signatures", t, func() {
		bundle := func(predicateType string) descriptor.Descriptor {
			return descriptor.Descriptor{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: common.ArtifactTypeCosignBundle,
				Annotations:  map[string]string{common.CosignBundlePredicateTypeAnnotation: predicateType},
			}
		}

		attestations := referrer.ReferrerList{Descriptors: []descriptor.Descriptor{
			bundle("https://spdx.dev/Document"),
			bundle("https://cosign.sigstore.dev/attestation/vuln/v1"),
		}}
		So(hasSignatureReferrers(attestations), ShouldBeFalse)

		signed := referrer.ReferrerList{Descriptors: append(attestations.Descriptors,
			bundle(common.CosignSignPredicateType))}
		So(hasSignatureReferrers(signed), ShouldBeTrue)
	})
}
