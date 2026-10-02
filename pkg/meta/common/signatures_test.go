package common_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/common"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

type verifyFunc func(signatureType string, layerDigest godigest.Digest, sigKey string, manifestDigest godigest.Digest,
	imageMeta mTypes.ImageMeta, repo string) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error)

func (verify verifyFunc) VerifySignatureLayer(signatureType string, layerDigest godigest.Digest, sigKey string,
	manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta, repo string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	return verify(signatureType, layerDigest, sigKey, manifestDigest, imageMeta, repo)
}

func manifestSignatures(sigType string, signatures ...*proto_go.SignatureInfo) *proto_go.ManifestSignatures {
	return &proto_go.ManifestSignatures{Map: map[string]*proto_go.SignaturesInfo{
		sigType: {List: signatures},
	}}
}

func signature(manifestDigest string, layers ...*proto_go.LayersInfo) *proto_go.SignatureInfo {
	return &proto_go.SignatureInfo{SignatureManifestDigest: manifestDigest, LayersInfo: layers}
}

func TestVerifyManifestSignatures(t *testing.T) {
	Convey("VerifyManifestSignatures", t, func() {
		ctx := context.Background()
		manifestDigest := godigest.FromString("manifest")
		expiry := time.Now().Add(time.Hour)

		// layers named "trusted" verify, "unavailable" cannot be loaded, "toolarge" are not signatures, anything else
		// does not verify
		trustStore := verifyFunc(func(signatureType string, layerDigest godigest.Digest, sigKey string,
			manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta, repo string,
		) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
			switch layerDigest {
			case "trusted":
				return "author", expiry, true, nil
			case "unavailable":
				return "", time.Time{}, false, fmt.Errorf("%w: timeout", zerr.ErrSignatureLayerUnavailable)
			case "toolarge":
				return "", time.Time{}, false, zerr.ErrSignatureLayerTooLarge
			default:
				return "", time.Time{}, false, nil
			}
		})

		signatures := manifestSignatures("cosign",
			signature("sig1", &proto_go.LayersInfo{LayerDigest: "trusted"}),
			signature("sig2", &proto_go.LayersInfo{
				LayerDigest: "untrusted", Signer: "stale", Date: timestamppb.New(expiry.Add(-time.Hour)),
			}),
			signature("sig3", &proto_go.LayersInfo{LayerDigest: "unavailable", Signer: "previous"}),
			signature("sig4", &proto_go.LayersInfo{LayerDigest: "toolarge", Signer: "stale"}),
		)

		Convey("returns signer and expiry of each verified layer, leaving the signatures unchanged", func() {
			snapshot := proto.Clone(signatures).(*proto_go.ManifestSignatures) //nolint: forcetypeassert

			validity, err := common.VerifyManifestSignatures(ctx, trustStore, "repo", manifestDigest, mTypes.ImageMeta{},
				signatures, log.NewTestLogger())
			So(err, ShouldBeNil)
			So(proto.Equal(signatures, snapshot), ShouldBeTrue)

			common.ApplySignaturesValidity(snapshot, validity)

			list := snapshot.GetMap()["cosign"].GetList()
			So(list[0].GetLayersInfo()[0].GetSigner(), ShouldEqual, "author")
			So(list[0].GetLayersInfo()[0].GetDate().AsTime().Unix(), ShouldEqual, expiry.Unix())
			So(list[1].GetLayersInfo()[0].GetSigner(), ShouldBeEmpty)
			// a layer that could not be loaded has no result, and keeps its stored validity
			So(list[2].GetLayersInfo()[0].GetSigner(), ShouldEqual, "previous")
			// a layer too large to be a signature is not trusted
			So(list[3].GetLayersInfo()[0].GetSigner(), ShouldBeEmpty)

			Convey("a layer that could not be loaded does not overwrite a result stored since", func() {
				current := manifestSignatures("cosign",
					signature("sig3", &proto_go.LayersInfo{LayerDigest: "unavailable", Signer: "newer"}),
				)

				common.ApplySignaturesValidity(current, validity)

				So(current.GetMap()["cosign"].GetList()[0].GetLayersInfo()[0].GetSigner(), ShouldEqual, "newer")
			})

			Convey("a layer verified without an expiry date keeps the date stored since", func() {
				newerDate := timestamppb.New(expiry.Add(time.Hour))
				current := manifestSignatures("cosign",
					signature("sig2", &proto_go.LayersInfo{LayerDigest: "untrusted", Signer: "newer", Date: newerDate}),
				)

				common.ApplySignaturesValidity(current, validity)

				layerInfo := current.GetMap()["cosign"].GetList()[0].GetLayersInfo()[0]
				So(layerInfo.GetSigner(), ShouldBeEmpty)
				So(layerInfo.GetDate().AsTime().Unix(), ShouldEqual, newerDate.AsTime().Unix())
			})
		})

		Convey("stops when the context is done", func() {
			cancelledCtx, cancel := context.WithCancel(ctx)
			cancel()

			_, err := common.VerifyManifestSignatures(cancelledCtx, trustStore, "repo", manifestDigest, mTypes.ImageMeta{},
				signatures, log.NewTestLogger())
			So(err, ShouldEqual, context.Canceled)
		})

		Convey("tolerates missing signatures", func() {
			validity, err := common.VerifyManifestSignatures(ctx, trustStore, "repo", manifestDigest, mTypes.ImageMeta{},
				nil, log.NewTestLogger())
			So(err, ShouldBeNil)
			So(validity, ShouldBeEmpty)
		})

		Convey("tells apart layers of the same digest signed with different keys", func() {
			// a cosign signature manifest holds one layer per signature, and every signature of the same image has the
			// same payload, so the layers share their digest and only differ in their signature annotation
			trustByKey := verifyFunc(func(signatureType string, layerDigest godigest.Digest, sigKey string,
				manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta, repo string,
			) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
				if sigKey == "trusted-key" {
					return "author", time.Time{}, true, nil
				}

				return "", time.Time{}, false, nil
			})

			sharedPayload := manifestSignatures("cosign",
				signature("sig1",
					&proto_go.LayersInfo{LayerDigest: "payload", SignatureKey: "trusted-key"},
					&proto_go.LayersInfo{LayerDigest: "payload", SignatureKey: "unknown-key"},
				),
			)

			validity, err := common.VerifyManifestSignatures(ctx, trustByKey, "repo", manifestDigest, mTypes.ImageMeta{},
				sharedPayload, log.NewTestLogger())
			So(err, ShouldBeNil)

			common.ApplySignaturesValidity(sharedPayload, validity)

			layers := sharedPayload.GetMap()["cosign"].GetList()[0].GetLayersInfo()
			So(layers[0].GetSigner(), ShouldEqual, "author")
			So(layers[1].GetSigner(), ShouldBeEmpty)
		})
	})
}

func TestApplySignaturesValidity(t *testing.T) {
	Convey("ApplySignaturesValidity", t, func() {
		ctx := context.Background()
		date := time.Now().Add(time.Hour)

		trustStore := verifyFunc(func(signatureType string, layerDigest godigest.Digest, sigKey string,
			manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta, repo string,
		) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
			return "author", date, true, nil
		})

		verified := manifestSignatures("notation",
			signature("sig1", &proto_go.LayersInfo{LayerDigest: "layer1"}),
			signature("removed", &proto_go.LayersInfo{LayerDigest: "layer2"}),
			signature("changed", &proto_go.LayersInfo{LayerDigest: "old-layer"}),
		)

		validity, err := common.VerifyManifestSignatures(ctx, trustStore, "repo", godigest.FromString("manifest"),
			mTypes.ImageMeta{}, verified, log.NewTestLogger())
		So(err, ShouldBeNil)

		current := manifestSignatures("notation",
			signature("sig1", &proto_go.LayersInfo{LayerDigest: "layer1", Signer: "stale"}),
			signature("added", &proto_go.LayersInfo{LayerDigest: "layer3", Signer: "kept"}),
			signature("changed", &proto_go.LayersInfo{LayerDigest: "new-layer", Signer: "kept"}),
		)

		common.ApplySignaturesValidity(current, validity)

		list := current.GetMap()["notation"].GetList()
		So(list, ShouldHaveLength, 3)
		So(list[0].GetLayersInfo()[0].GetSigner(), ShouldEqual, "author")
		So(list[0].GetLayersInfo()[0].GetDate().AsTime().Unix(), ShouldEqual, date.Unix())
		So(list[1].GetLayersInfo()[0].GetSigner(), ShouldEqual, "kept")
		So(list[2].GetLayersInfo()[0].GetSigner(), ShouldEqual, "kept")

		Convey("tolerates missing signatures or results", func() {
			So(func() { common.ApplySignaturesValidity(nil, validity) }, ShouldNotPanic)
			So(func() { common.ApplySignaturesValidity(current, nil) }, ShouldNotPanic)
		})
	})
}

func TestStripSignatureLayerContent(t *testing.T) {
	Convey("StripSignatureLayerContent drops stored layer content and nothing else", t, func() {
		repoMeta := &proto_go.RepoMeta{
			Name: "repo",
			Signatures: map[string]*proto_go.ManifestSignatures{
				"manifest": manifestSignatures("cosign", signature("sig", &proto_go.LayersInfo{
					LayerDigest: "layer", LayerContent: make([]byte, 1<<20), SignatureKey: "key", Signer: "author",
				})),
				"empty": nil,
			},
		}

		common.StripSignatureLayerContent(repoMeta)

		layer := repoMeta.GetSignatures()["manifest"].GetMap()["cosign"].GetList()[0].GetLayersInfo()[0]
		So(layer.GetLayerContent(), ShouldBeNil)
		So(layer.GetLayerDigest(), ShouldEqual, "layer")
		So(layer.GetSignatureKey(), ShouldEqual, "key")
		So(layer.GetSigner(), ShouldEqual, "author")

		So(func() { common.StripSignatureLayerContent(nil) }, ShouldNotPanic)
	})
}
