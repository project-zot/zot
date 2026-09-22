package common_test

import (
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	notreg "github.com/notaryproject/notation-go/registry"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/common"
)

func TestCommon(t *testing.T) {
	Convey("test Contains()", t, func() {
		first := []string{"apple", "biscuit"}
		So(slices.Contains(first, "apple"), ShouldBeTrue)
		So(slices.Contains(first, "peach"), ShouldBeFalse)
		So(slices.Contains([]string{}, "apple"), ShouldBeFalse)
	})

	Convey("test MarshalThroughStruct()", t, func() {
		cfg := config.New()

		newCfg := struct {
			DistSpecVersion string
		}{}

		_, err := common.MarshalThroughStruct(cfg, &newCfg)
		So(err, ShouldBeNil)
		So(newCfg.DistSpecVersion, ShouldEqual, cfg.DistSpecVersion)

		// negative
		obj := make(chan int)
		toObj := config.New()

		_, err = common.MarshalThroughStruct(obj, &toObj)
		So(err, ShouldNotBeNil)

		_, err = common.MarshalThroughStruct(toObj, &obj)
		So(err, ShouldNotBeNil)
	})

	Convey("test dirExists()", t, func() {
		exists := common.DirExists("testdir")
		So(exists, ShouldBeFalse)

		tempDir := t.TempDir()

		file, err := os.Create(path.Join(tempDir, "file.txt"))
		So(err, ShouldBeNil)

		isDir := common.DirExists(file.Name())
		So(isDir, ShouldBeFalse)
	})

	Convey("Test ArtifactTypeNotation const has same value as in notaryproject", t, func() {
		So(common.ArtifactTypeNotation, ShouldEqual, notreg.ArtifactTypeNotation)
	})

	Convey("Test IsArtifactTypeCosign", t, func() {
		So(common.IsArtifactTypeCosign(common.ArtifactTypeCosign), ShouldBeTrue)
		So(common.IsArtifactTypeCosign(common.ArtifactTypeCosignBundle), ShouldBeTrue)
		So(common.IsArtifactTypeCosign(common.ArtifactTypeNotation), ShouldBeFalse)
		So(common.IsArtifactTypeCosign("application/example"), ShouldBeFalse)
	})

	Convey("Test IsCosignSignatureArtifact", t, func() {
		predicate := func(predicateType string) map[string]string {
			return map[string]string{common.CosignBundlePredicateTypeAnnotation: predicateType}
		}

		So(common.IsCosignSignatureArtifact(common.ArtifactTypeCosign, nil), ShouldBeTrue)
		// bundles written by `cosign sign`, or without the annotation, are signatures
		So(common.IsCosignSignatureArtifact(common.ArtifactTypeCosignBundle, nil), ShouldBeTrue)
		So(common.IsCosignSignatureArtifact(common.ArtifactTypeCosignBundle,
			predicate(common.CosignSignPredicateType)), ShouldBeTrue)
		// bundles written by `cosign attest` are attestations
		So(common.IsCosignSignatureArtifact(common.ArtifactTypeCosignBundle,
			predicate("https://spdx.dev/Document")), ShouldBeFalse)
		So(common.IsCosignSignatureArtifact(common.ArtifactTypeCosignBundle,
			predicate("https://cosign.sigstore.dev/attestation/vuln/v1")), ShouldBeFalse)
		So(common.IsCosignSignatureArtifact(common.ArtifactTypeCosignBundle, predicate("")), ShouldBeFalse)
		So(common.IsCosignSignatureArtifact(common.ArtifactTypeNotation, nil), ShouldBeFalse)
		So(common.IsCosignSignatureArtifact("application/example",
			predicate(common.CosignSignPredicateType)), ShouldBeFalse)
	})

	Convey("Test legacy cosign tag predicates match only the exact tag shape", t, func() {
		hex := strings.Repeat("a", 64)

		So(common.IsCosignSignature("sha256-"+hex+".sig"), ShouldBeTrue)
		So(common.IsCosignSBOM("sha256-"+hex+".sbom"), ShouldBeTrue)
		So(common.IsCosignTag("sha256-"+hex+".sig"), ShouldBeTrue)
		So(common.IsCosignTag("sha256-"+hex+".sbom"), ShouldBeTrue)

		for _, tag := range []string{
			"sha256-abc.sig", // short digest
			"sha256-" + strings.Repeat("a", 65) + ".sig",  // long digest
			"sha256-" + strings.Repeat("z", 64) + ".sig",  // non-hex digest
			"sha256-" + strings.Repeat("A", 64) + ".sig",  // uppercase hex is not a valid sha256 encoding
			"sha256-not-a-valid-digest.sig",               // hyphenated garbage
			"v1-sha256-" + hex + ".sig",                   // unanchored prefix
			"sha256-" + hex + ".sig.bak",                  // unanchored suffix
			"sha512-" + strings.Repeat("a", 128) + ".sig", // other algorithms were never matched
		} {
			So(common.IsCosignSignature(tag), ShouldBeFalse)
			So(common.IsCosignTag(tag), ShouldBeFalse)
		}

		So(common.IsCosignSBOM("sha256-abc.sbom"), ShouldBeFalse)
		So(common.IsCosignSBOM("sha256-"+hex+".sbom.bak"), ShouldBeFalse)
	})

	Convey("Test GetLocalIPs", t, func() {
		localIPs, err := common.GetLocalIPs()
		So(err, ShouldBeNil)
		So(localIPs, ShouldNotBeEmpty)
		So(localIPs, ShouldContain, "127.0.0.1")
	})

	Convey("Test GetLocalSockets IPv4", t, func() {
		localSockets, err := common.GetLocalSockets("8765")
		So(err, ShouldBeNil)
		So(localSockets, ShouldNotBeEmpty)
		So(localSockets, ShouldContain, "127.0.0.1:8765")

		for _, socket := range localSockets {
			lastColonIndex := strings.LastIndex(socket, ":")
			So(socket[lastColonIndex+1:], ShouldEqual, "8765")
		}
	})

	Convey("Test GetLocalSockets IPv6", t, func() {
		localSockets, err := common.GetLocalSockets("8766")
		So(err, ShouldBeNil)
		So(localSockets, ShouldNotBeEmpty)
		So(localSockets, ShouldContain, "[::1]:8766")

		for _, socket := range localSockets {
			lastColonIndex := strings.LastIndex(socket, ":")
			So(socket[lastColonIndex+1:], ShouldEqual, "8766")
		}
	})

	Convey("Test GetIPFromHostName with valid hostname", t, func() {
		addrs, err := common.GetIPFromHostName("github.com")

		// we can't check the actual addresses here as they can change
		So(err, ShouldBeNil)
		So(addrs, ShouldNotBeEmpty)
	})

	Convey("Test GetIPFromHostName with non-existent hostname", t, func() {
		addrs, err := common.GetIPFromHostName("thisdoesnotexist")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "lookup thisdoesnotexist")
		So(addrs, ShouldBeEmpty)
	})

	Convey("Test AreSocketsEqual with equal IPv4 sockets", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.1:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with equal IPv6 sockets", t, func() {
		result, err := common.AreSocketsEqual("[::1]:9000", "[0000:0000:0000:0000:0000:0000:0000:0001]:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with different IPv4 socket ports", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.1:9001")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with different IPv4 socket hosts", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.2:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with 2 equal host names", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "localhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with 2 different host names", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "notlocalhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with hostname and IP address", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "127.0.0.1:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with IP address and hostname", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "localhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with invalid first socket", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1", "localhost:9000")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with invalid second socket", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "127.0.0.1")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})
}
