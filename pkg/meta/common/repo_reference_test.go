package common_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"zotregistry.dev/zot/v2/pkg/meta/common"
	mConvert "zotregistry.dev/zot/v2/pkg/meta/convert"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func newRepoMeta() *proto_go.RepoMeta {
	return &proto_go.RepoMeta{
		Name:       "repo",
		Tags:       map[string]*proto_go.TagDescriptor{"": {}},
		Statistics: map[string]*proto_go.DescriptorStatistics{"": {}},
		Signatures: map[string]*proto_go.ManifestSignatures{"": {}},
		Referrers:  map[string]*proto_go.ReferrersInfo{"": {}},
	}
}

func newRepoBlobs() *proto_go.RepoBlobs {
	return &proto_go.RepoBlobs{Blobs: map[string]*proto_go.BlobInfo{"": {}}}
}

func applyReference(repoMeta *proto_go.RepoMeta, repoBlobs *proto_go.RepoBlobs, reference string,
	imageMeta mTypes.ImageMeta, userid string, opts ...mTypes.SetRepoReferenceOption,
) bool {
	return common.ApplyReferenceToRepoMeta(repoMeta, repoBlobs, reference, imageMeta,
		mConvert.GetProtoImageMeta(imageMeta), userid, mTypes.ApplySetRepoReferenceOptions(opts...))
}

func sortAggregates(repoMeta *proto_go.RepoMeta) {
	slices.Sort(repoMeta.Vendors)
	slices.SortFunc(repoMeta.Platforms, func(a, b *proto_go.Platform) int {
		return strings.Compare(a.OS+"/"+a.Architecture, b.OS+"/"+b.Architecture)
	})
}

type fixtureRef struct {
	reference  string
	imageMeta  mTypes.ImageMeta
	wantRecalc bool
}

func perReferenceFixture() []fixtureRef {
	vendorAnnotations := map[string]string{ispec.AnnotationVendor: "acme"}

	newImage := func(arch string, annotations map[string]string) image.Image {
		return image.CreateImageWith().RandomLayers(1, 20).PlatformConfig(arch, "linux").
			Annotations(annotations).Build()
	}

	tag1, tag2, tag3 := newImage("amd64", nil), newImage("arm64", vendorAnnotations), newImage("s390x", nil)
	child1, child2, child3 := newImage("amd64", nil), newImage("arm64", vendorAnnotations), newImage("ppc64le", nil)
	index := image.CreateMultiarchWith().Images([]image.Image{child1, child2, child3}).Build()
	referrer := image.CreateImageWith().RandomLayers(1, 20).DefaultConfig().Subject(tag1.DescriptorRef()).Build()

	return []fixtureRef{
		{reference: "t1", imageMeta: tag1.AsImageMeta(), wantRecalc: true},
		{reference: "t2", imageMeta: tag2.AsImageMeta(), wantRecalc: true},
		{reference: "t3", imageMeta: tag3.AsImageMeta(), wantRecalc: true},
		{reference: "t1-again", imageMeta: tag1.AsImageMeta(), wantRecalc: true},
		{reference: "t3", imageMeta: tag2.AsImageMeta(), wantRecalc: true},
		{reference: child1.DigestStr(), imageMeta: child1.AsImageMeta(), wantRecalc: false},
		{reference: child2.DigestStr(), imageMeta: child2.AsImageMeta(), wantRecalc: false},
		{reference: "multi", imageMeta: index.AsImageMeta(), wantRecalc: true},
		{reference: child3.DigestStr(), imageMeta: child3.AsImageMeta(), wantRecalc: true},
		{reference: referrer.DigestStr(), imageMeta: referrer.AsImageMeta(), wantRecalc: false},
	}
}

func TestPerReferenceUpdateWithDeferredRecalc(t *testing.T) {
	refs := perReferenceFixture()

	// reference run: the update used by callers which recalculate after every reference
	wantMeta, wantBlobs := newRepoMeta(), newRepoBlobs()

	for _, ref := range refs {
		if !strings.HasPrefix(ref.reference, "sha256:") {
			wantMeta.Tags[ref.reference] = &proto_go.TagDescriptor{
				Digest:    ref.imageMeta.Digest.String(),
				MediaType: ref.imageMeta.MediaType,
			}
		}

		common.AddImageMetaToRepoMeta(wantMeta, wantBlobs, ref.reference, ref.imageMeta)
	}

	// helper run: per-reference update, one aggregate recalculation at the end
	gotMeta, gotBlobs := newRepoMeta(), newRepoBlobs()
	recalcNeeded := false

	for i, ref := range refs {
		needed := applyReference(gotMeta, gotBlobs, ref.reference, ref.imageMeta, "",
			mTypes.WithPushTimestamp(time.Unix(1700000000, 0)))
		if needed != ref.wantRecalc {
			t.Errorf("ref %d (%s): recalc needed = %t, want %t", i, ref.reference, needed, ref.wantRecalc)
		}

		recalcNeeded = recalcNeeded || needed
	}

	if recalcNeeded {
		common.RecalculateRepoAggregates(gotMeta, gotBlobs)
	}

	// Statistics, Signatures and Referrers are written by the helper only; the reference run never
	// touches them
	wantMeta.Statistics, wantMeta.Signatures, wantMeta.Referrers = nil, nil, nil
	gotMeta.Statistics, gotMeta.Signatures, gotMeta.Referrers = nil, nil, nil

	sortAggregates(wantMeta)
	sortAggregates(gotMeta)

	if !proto.Equal(wantMeta, gotMeta) {
		t.Errorf("RepoMeta differs:\nwant %v\ngot  %v", wantMeta, gotMeta)
	}

	if !proto.Equal(wantBlobs, gotBlobs) {
		t.Errorf("RepoBlobs differ:\nwant %v\ngot  %v", wantBlobs, gotBlobs)
	}
}

func TestPerReferenceUpdateStatisticsAndTagTimestamps(t *testing.T) {
	pushed := time.Unix(1700000000, 0).UTC()
	existingPush := timestamppb.New(time.Unix(1600000000, 0))
	existingTagged := timestamppb.New(time.Unix(1650000000, 0))

	img := image.CreateRandomImage()
	imageMeta := img.AsImageMeta()
	digest := imageMeta.Digest.String()

	statsOf := func(t *testing.T, repoMeta *proto_go.RepoMeta) *proto_go.DescriptorStatistics {
		t.Helper()

		stats := repoMeta.Statistics[digest]
		if stats == nil {
			t.Fatalf("no statistics for %s", digest)
		}

		return stats
	}

	t.Run("no statistics get the push timestamp and user", func(t *testing.T) {
		repoMeta := newRepoMeta()

		applyReference(repoMeta, newRepoBlobs(), "tag", imageMeta, "alice", mTypes.WithPushTimestamp(pushed))

		stats := statsOf(t, repoMeta)
		if !stats.PushTimestamp.AsTime().Equal(pushed) || stats.PushedBy != "alice" {
			t.Errorf("stats = %v, want push timestamp %v and pushedBy alice", stats, pushed)
		}
	})

	t.Run("zero push timestamp is replaced, user is set", func(t *testing.T) {
		repoMeta := newRepoMeta()
		repoMeta.Statistics[digest] = &proto_go.DescriptorStatistics{PushTimestamp: timestamppb.New(time.Time{})}

		applyReference(repoMeta, newRepoBlobs(), "tag", imageMeta, "alice", mTypes.WithPushTimestamp(pushed))

		stats := statsOf(t, repoMeta)
		if !stats.PushTimestamp.AsTime().Equal(pushed) || stats.PushedBy != "alice" {
			t.Errorf("stats = %v, want push timestamp %v and pushedBy alice", stats, pushed)
		}
	})

	t.Run("set push timestamp and user are kept", func(t *testing.T) {
		repoMeta := newRepoMeta()
		repoMeta.Statistics[digest] = &proto_go.DescriptorStatistics{PushTimestamp: existingPush, PushedBy: "bob"}

		applyReference(repoMeta, newRepoBlobs(), "tag", imageMeta, "alice", mTypes.WithPushTimestamp(pushed))

		stats := statsOf(t, repoMeta)
		if !stats.PushTimestamp.AsTime().Equal(existingPush.AsTime()) || stats.PushedBy != "bob" {
			t.Errorf("stats = %v, want push timestamp %v and pushedBy bob", stats, existingPush.AsTime())
		}
	})

	t.Run("existing tag keeps its TaggedTimestamp", func(t *testing.T) {
		repoMeta := newRepoMeta()
		repoMeta.Tags["tag"] = &proto_go.TagDescriptor{Digest: digest, TaggedTimestamp: existingTagged}

		applyReference(repoMeta, newRepoBlobs(), "tag", imageMeta, "", mTypes.WithPushTimestamp(pushed))

		got := repoMeta.Tags["tag"].TaggedTimestamp
		if got == nil || !got.AsTime().Equal(existingTagged.AsTime()) {
			t.Errorf("TaggedTimestamp = %v, want %v", got, existingTagged.AsTime())
		}
	})

	t.Run("new tag with push timestamp has no TaggedTimestamp", func(t *testing.T) {
		repoMeta := newRepoMeta()

		applyReference(repoMeta, newRepoBlobs(), "tag", imageMeta, "", mTypes.WithPushTimestamp(pushed))

		if got := repoMeta.Tags["tag"].TaggedTimestamp; got != nil {
			t.Errorf("TaggedTimestamp = %v, want nil", got)
		}
	})

	t.Run("new tag without push timestamp gets a TaggedTimestamp", func(t *testing.T) {
		repoMeta := newRepoMeta()

		applyReference(repoMeta, newRepoBlobs(), "tag", imageMeta, "")

		if got := repoMeta.Tags["tag"].TaggedTimestamp; got == nil {
			t.Error("TaggedTimestamp = nil, want a timestamp")
		}
	})
}

func TestPerReferenceUpdateCountsReferrerAppliedTwice(t *testing.T) {
	subject := image.CreateRandomImage()
	referrer := image.CreateImageWith().RandomLayers(1, 20).DefaultConfig().Subject(subject.DescriptorRef()).Build()
	referrerMeta := referrer.AsImageMeta()

	repoMeta, repoBlobs := newRepoMeta(), newRepoBlobs()

	applyReference(repoMeta, repoBlobs, referrer.DigestStr(), referrerMeta, "")
	applyReference(repoMeta, repoBlobs, "tagged-referrer", referrerMeta, "")

	list := repoMeta.Referrers[subject.DigestStr()].GetList()
	if len(list) != 1 {
		t.Fatalf("referrers of the subject = %v, want one entry", list)
	}

	if list[0].Digest != referrer.DigestStr() || list[0].Count != 2 {
		t.Errorf("referrer entry = %v, want digest %s with count 2", list[0], referrer.DigestStr())
	}
}
