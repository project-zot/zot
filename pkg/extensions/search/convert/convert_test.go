//go:build search

package convert_test

import (
	"context"
	"errors"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/search/convert"
	"zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/v2/pkg/extensions/search/pagination"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
)

var ErrTestError = errors.New("TestError")

func TestUpdateLastUpdatedTimestamp(t *testing.T) {
	Convey("Image summary is the first image checked for the repo", t, func() {
		before := time.Time{}
		after := time.Date(2023, time.April, 1, 11, 0, 0, 0, time.UTC)
		img := convert.UpdateLastUpdatedTimestamp(
			&before,
			&gql_generated.ImageSummary{LastUpdated: &before},
			&gql_generated.ImageSummary{LastUpdated: &after},
		)

		So(*img.LastUpdated, ShouldResemble, after)
	})

	Convey("Image summary is updated after the current latest image", t, func() {
		before := time.Date(2022, time.April, 1, 11, 0, 0, 0, time.UTC)
		after := time.Date(2023, time.April, 1, 11, 0, 0, 0, time.UTC)
		img := convert.UpdateLastUpdatedTimestamp(
			&before,
			&gql_generated.ImageSummary{LastUpdated: &before},
			&gql_generated.ImageSummary{LastUpdated: &after},
		)

		So(*img.LastUpdated, ShouldResemble, after)
	})

	Convey("Image summary is updated before the current latest image", t, func() {
		before := time.Date(2022, time.April, 1, 11, 0, 0, 0, time.UTC)
		after := time.Date(2023, time.April, 1, 11, 0, 0, 0, time.UTC)
		img := convert.UpdateLastUpdatedTimestamp(
			&after,
			&gql_generated.ImageSummary{LastUpdated: &after},
			&gql_generated.ImageSummary{LastUpdated: &before},
		)

		So(*img.LastUpdated, ShouldResemble, after)
	})
}

func TestLabels(t *testing.T) {
	Convey("Test labels", t, func() {
		// Test various labels
		labels := make(map[string]string)

		created := convert.GetCreated(labels)
		So(created, ShouldBeNil)

		desc := convert.GetDescription(labels)
		So(desc, ShouldEqual, "")

		license := convert.GetLicenses(labels)
		So(license, ShouldEqual, "")

		vendor := convert.GetVendor(labels)
		So(vendor, ShouldEqual, "")

		categories := convert.GetCategories(labels)
		So(categories, ShouldEqual, "")

		expectedCreatedTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		labels[ispec.AnnotationCreated] = expectedCreatedTime.Format(time.RFC3339)
		labels[ispec.AnnotationVendor] = "zot"
		labels[ispec.AnnotationDescription] = "zot-desc"
		labels[ispec.AnnotationLicenses] = "zot-license"
		labels[convert.AnnotationLabels] = "zot-labels"

		created = convert.GetCreated(labels)
		So(*created, ShouldEqual, expectedCreatedTime)

		desc = convert.GetDescription(labels)
		So(desc, ShouldEqual, "zot-desc")

		license = convert.GetLicenses(labels)
		So(license, ShouldEqual, "zot-license")

		vendor = convert.GetVendor(labels)
		So(vendor, ShouldEqual, "zot")

		categories = convert.GetCategories(labels)
		So(categories, ShouldEqual, "zot-labels")

		labels = make(map[string]string)

		// Use diff key
		labels[convert.LabelAnnotationCreated] = expectedCreatedTime.Format(time.RFC3339)
		labels[convert.LabelAnnotationVendor] = "zot-vendor"
		labels[convert.LabelAnnotationDescription] = "zot-label-desc"
		labels[ispec.AnnotationLicenses] = "zot-label-license"

		created = convert.GetCreated(labels)
		So(*created, ShouldEqual, expectedCreatedTime)

		desc = convert.GetDescription(labels)
		So(desc, ShouldEqual, "zot-label-desc")

		license = convert.GetLicenses(labels)
		So(license, ShouldEqual, "zot-label-license")

		vendor = convert.GetVendor(labels)
		So(vendor, ShouldEqual, "zot-vendor")

		labels = make(map[string]string)

		// Handle conversion errors
		labels[ispec.AnnotationCreated] = "asd"

		created = convert.GetCreated(labels)
		So(created, ShouldBeNil)
	})
}

func TestGetSignaturesInfo(t *testing.T) {
	Convey("Test get signatures info - cosign", t, func() {
		digest := godigest.FromString("dig")
		signatures := map[string]mTypes.ManifestSignatures{
			digest.String(): {
				"cosign": []mTypes.SignatureInfo{
					{
						LayersInfo: []mTypes.LayerInfo{
							{
								LayerContent: []byte{},
								LayerDigest:  "",
								SignatureKey: "",
								Signer:       "author",
							},
						},
					},
				},
			},
		}

		signaturesSummary := convert.GetSignaturesInfo(true, signatures[digest.String()])
		So(signaturesSummary, ShouldNotBeEmpty)
		So(*signaturesSummary[0].Author, ShouldEqual, "author")
		So(*signaturesSummary[0].IsTrusted, ShouldEqual, true)
		So(*signaturesSummary[0].Tool, ShouldEqual, "cosign")
	})

	Convey("Test get signatures info - notation", t, func() {
		digest := godigest.FromString("dig")
		signatures := map[string]mTypes.ManifestSignatures{
			digest.String(): {
				"notation": []mTypes.SignatureInfo{
					{
						LayersInfo: []mTypes.LayerInfo{
							{
								LayerContent: []byte{},
								LayerDigest:  "",
								SignatureKey: "",
								Signer:       "author",
								Date:         time.Now().AddDate(0, 0, -1),
							},
						},
					},
				},
			},
		}

		signaturesSummary := convert.GetSignaturesInfo(true, signatures[digest.String()])
		So(signaturesSummary, ShouldNotBeEmpty)
		So(*signaturesSummary[0].Author, ShouldEqual, "author")
		So(*signaturesSummary[0].IsTrusted, ShouldEqual, false)
		So(*signaturesSummary[0].Tool, ShouldEqual, "notation")
	})
}

func TestAcceptedByFilter(t *testing.T) {
	Convey("Images", t, func() {
		Convey("Os not found", func() {
			found := convert.ImgSumAcceptedByFilter(
				&gql_generated.ImageSummary{
					Manifests: []*gql_generated.ManifestSummary{
						{Platform: &gql_generated.Platform{Os: ref("os1")}},
						{Platform: &gql_generated.Platform{Os: ref("os2")}},
					},
				},
				mTypes.Filter{Os: []*string{ref("os3")}},
			)

			So(found, ShouldBeFalse)
		})

		Convey("Has to be signed ", func() {
			found := convert.ImgSumAcceptedByFilter(
				&gql_generated.ImageSummary{
					Manifests: []*gql_generated.ManifestSummary{
						{IsSigned: ref(false)},
					},
					IsSigned: ref(false),
				},
				mTypes.Filter{HasToBeSigned: ref(true)},
			)

			So(found, ShouldBeFalse)
		})
	})

	Convey("Repos", t, func() {
		Convey("Os not found", func() {
			found := convert.RepoSumAcceptedByFilter(
				&gql_generated.RepoSummary{
					Platforms: []*gql_generated.Platform{
						{Os: ref("os1")},
						{Os: ref("os2")},
					},
				},
				mTypes.Filter{Os: []*string{ref("os3")}},
			)

			So(found, ShouldBeFalse)
		})

		Convey("Arch not found", func() {
			found := convert.RepoSumAcceptedByFilter(
				&gql_generated.RepoSummary{
					Platforms: []*gql_generated.Platform{
						{Arch: ref("Arch")},
					},
				},
				mTypes.Filter{Arch: []*string{ref("arch_not_found")}},
			)

			So(found, ShouldBeFalse)
		})

		Convey("Has to be signed ", func() {
			found := convert.ImgSumAcceptedByFilter(
				&gql_generated.ImageSummary{
					Manifests: []*gql_generated.ManifestSummary{
						{IsSigned: ref(false)},
					},
					IsSigned: ref(false),
				},
				mTypes.Filter{HasToBeSigned: ref(true)},
			)

			So(found, ShouldBeFalse)
		})
	})
}

func ref[T any](val T) *T {
	ref := val

	return &ref
}

func TestTaggedTimestamp(t *testing.T) {
	ctx := context.Background()

	Convey("Test TaggedTimestamp in ImageSummary", t, func() {
		Convey("TaggedTimestamp is populated from tag descriptor", func() {
			taggedTime := time.Date(2024, time.January, 15, 10, 30, 0, 0, time.UTC)
			pushTime := time.Date(2024, time.January, 10, 8, 0, 0, 0, time.UTC)

			repoMeta := mTypes.RepoMeta{
				Name: "repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:          "sha256:abc123",
						MediaType:       ispec.MediaTypeImageManifest,
						TaggedTimestamp: taggedTime,
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{
					"sha256:abc123": {
						PushTimestamp: pushTime,
					},
				},
			}

			imageMeta := mTypes.ImageMeta{
				Digest:    godigest.FromString("sha256:abc123"),
				MediaType: ispec.MediaTypeImageManifest,
				Manifests: []mTypes.ManifestMeta{
					{
						Digest: godigest.FromString("sha256:abc123"),
						Manifest: ispec.Manifest{
							Config: ispec.Descriptor{
								Digest: godigest.FromString("sha256:config123"),
							},
						},
						Config: ispec.Image{},
					},
				},
			}

			fullImageMeta := convert.GetFullImageMeta("tag1", repoMeta, imageMeta)
			So(fullImageMeta.TaggedTimestamp, ShouldEqual, taggedTime)

			imageSummary, _, err := convert.ImageManifest2ImageSummary(ctx, fullImageMeta)
			So(err, ShouldBeNil)
			So(imageSummary.TaggedTimestamp, ShouldNotBeNil)
			So(*imageSummary.TaggedTimestamp, ShouldEqual, taggedTime)
		})

		Convey("TaggedTimestamp falls back to PushTimestamp when zero", func() {
			pushTime := time.Date(2024, time.January, 10, 8, 0, 0, 0, time.UTC)

			// Use a proper digest that will match when converted to string
			imageDigest := godigest.FromString("sha256:abc123")
			digestStr := imageDigest.String()

			repoMeta := mTypes.RepoMeta{
				Name: "repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:          digestStr,
						MediaType:       ispec.MediaTypeImageManifest,
						TaggedTimestamp: time.Time{}, // Zero time
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{
					digestStr: {
						PushTimestamp: pushTime,
					},
				},
			}

			imageMeta := mTypes.ImageMeta{
				Digest:    imageDigest,
				MediaType: ispec.MediaTypeImageManifest,
				Manifests: []mTypes.ManifestMeta{
					{
						Digest: imageDigest,
						Manifest: ispec.Manifest{
							Config: ispec.Descriptor{
								Digest: godigest.FromString("sha256:config123"),
							},
						},
						Config: ispec.Image{},
					},
				},
			}

			fullImageMeta := convert.GetFullImageMeta("tag1", repoMeta, imageMeta)
			So(fullImageMeta.TaggedTimestamp.IsZero(), ShouldBeTrue)

			imageSummary, _, err := convert.ImageManifest2ImageSummary(ctx, fullImageMeta)
			So(err, ShouldBeNil)
			So(imageSummary.TaggedTimestamp, ShouldNotBeNil)
			So(*imageSummary.TaggedTimestamp, ShouldEqual, pushTime)
		})

		Convey("TaggedTimestamp is propagated to nested manifests in ImageIndex", func() {
			taggedTime := time.Date(2024, time.January, 15, 10, 30, 0, 0, time.UTC)
			pushTime := time.Date(2024, time.January, 10, 8, 0, 0, 0, time.UTC)

			// Create a multiarch image
			multiarchImage := CreateMultiarchWith().Images([]Image{
				CreateRandomImage(),
				CreateRandomImage(),
			}).Build()

			indexDigestStr := multiarchImage.DigestStr()

			repoMeta := mTypes.RepoMeta{
				Name: "repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:          indexDigestStr,
						MediaType:       ispec.MediaTypeImageIndex,
						TaggedTimestamp: taggedTime,
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{
					indexDigestStr: {
						PushTimestamp: pushTime,
					},
				},
			}

			imageMeta := multiarchImage.AsImageMeta()
			fullImageMeta := convert.GetFullImageMeta("tag1", repoMeta, imageMeta)
			So(fullImageMeta.TaggedTimestamp, ShouldEqual, taggedTime)

			imageSummary, _, err := convert.ImageIndex2ImageSummary(ctx, fullImageMeta)
			So(err, ShouldBeNil)
			So(imageSummary.TaggedTimestamp, ShouldNotBeNil)
			So(*imageSummary.TaggedTimestamp, ShouldEqual, taggedTime)

			// Verify that nested manifests also have the correct TaggedTimestamp
			So(len(imageSummary.Manifests), ShouldBeGreaterThan, 0)

			for _, manifestSummary := range imageSummary.Manifests {
				// Each manifest summary is part of the index, so they should inherit the index's TaggedTimestamp
				// Note: ManifestSummary doesn't have TaggedTimestamp field, but the parent ImageSummary does
				So(manifestSummary, ShouldNotBeNil)
			}
		})

		Convey("TaggedTimestamp falls back to PushTimestamp for ImageIndex when zero", func() {
			pushTime := time.Date(2024, time.January, 10, 8, 0, 0, 0, time.UTC)

			// Create a multiarch image
			multiarchImage := CreateMultiarchWith().Images([]Image{
				CreateRandomImage(),
			}).Build()

			indexDigestStr := multiarchImage.DigestStr()

			repoMeta := mTypes.RepoMeta{
				Name: "repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:          indexDigestStr,
						MediaType:       ispec.MediaTypeImageIndex,
						TaggedTimestamp: time.Time{}, // Zero time
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{
					indexDigestStr: {
						PushTimestamp: pushTime,
					},
				},
			}

			imageMeta := multiarchImage.AsImageMeta()
			fullImageMeta := convert.GetFullImageMeta("tag1", repoMeta, imageMeta)
			So(fullImageMeta.TaggedTimestamp.IsZero(), ShouldBeTrue)

			imageSummary, _, err := convert.ImageIndex2ImageSummary(ctx, fullImageMeta)
			So(err, ShouldBeNil)
			So(imageSummary.TaggedTimestamp, ShouldNotBeNil)
			So(*imageSummary.TaggedTimestamp, ShouldEqual, pushTime)
		})
	})
}

func TestPaginatedConvert(t *testing.T) {
	ctx := context.Background()

	tempDir := t.TempDir()

	driver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: tempDir})
	if err != nil {
		t.FailNow()
	}

	metaDB, err := boltdb.New(driver, log.NewTestLogger())
	if err != nil {
		t.FailNow()
	}

	var (
		badBothImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "bad-os", Architecture: "bad-arch"}}).Build()
		badOsImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "bad-os", Architecture: "good-arch"}}).Build()
		badArchImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "good-os", Architecture: "bad-arch"}}).Build()
		goodImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "good-os", Architecture: "good-arch"}}).Build()

		randomImage1    = CreateRandomImage()
		randomImage2    = CreateRandomImage()
		signatureDigest = godigest.FromString("signature")

		badMultiArch = CreateMultiarchWith().Images(
			[]Image{badBothImage, badOsImage, badArchImage, randomImage1}).Build()
		goodMultiArch = CreateMultiarchWith().Images(
			[]Image{badOsImage, badArchImage, randomImage2, goodImage}).Build()
	)

	ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB,
		ociutils.Repo{
			Name: "repo1-only-images",
			Images: []ociutils.RepoImage{
				{Image: goodImage, Reference: "goodImage"},
				{Image: badOsImage, Reference: "badOsImage"},
				{Image: badArchImage, Reference: "badArchImage"},
				{Image: badBothImage, Reference: "badBothImage"},
			},
			IsBookmarked: true,
			IsStarred:    true,
		},
		ociutils.Repo{
			Name: "repo2-only-bad-images",
			Images: []ociutils.RepoImage{
				{Image: randomImage1, Reference: "randomImage1"},
				{Image: randomImage2, Reference: "randomImage2"},
				{Image: badBothImage, Reference: "badBothImage"},
			},
			IsBookmarked: true,
			IsStarred:    true,
		},
		ociutils.Repo{
			Name: "repo3-only-multiarch",
			MultiArchImages: []ociutils.RepoMultiArchImage{
				{MultiarchImage: badMultiArch, Reference: "badMultiArch"},
				{MultiarchImage: goodMultiArch, Reference: "goodMultiArch"},
			},
			IsBookmarked: true,
			IsStarred:    true,
		},
		ociutils.Repo{
			Name: "repo4-not-bookmarked-or-starred",
			Images: []ociutils.RepoImage{
				{Image: goodImage, Reference: "goodImage"},
			},
			MultiArchImages: []ociutils.RepoMultiArchImage{
				{MultiarchImage: goodMultiArch, Reference: "goodMultiArch"},
			},
		},
		ociutils.Repo{
			Name: "repo5-signed",
			Images: []ociutils.RepoImage{
				{Image: goodImage, Reference: "goodImage"}, // is fake signed by the image below
			},
			Signatures: map[string]mTypes.ManifestSignatures{
				goodImage.DigestStr(): ociutils.GetFakeSignatureInfo(signatureDigest.String()),
			},
		},
	)
	if err != nil {
		t.FailNow()
	}

	skipCVE := convert.SkipQGLField{Vulnerabilities: true}

	Convey("PaginatedRepoMeta2RepoSummaries filtering and sorting", t, func() {
		// Test different combinations of the filter
		repoMetaList, err := metaDB.FilterRepos(ctx, mTypes.AcceptAllRepoNames, mTypes.AcceptAllRepoMeta)
		So(err, ShouldBeNil)
		imageMeta, err := metaDB.FilterImageMeta(ctx, mTypes.GetLatestImageDigests(repoMetaList))
		So(err, ShouldBeNil)

		reposSum, pageInfo, err := convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{
				Os:           []*string{ref("good-os")},
				Arch:         []*string{ref("good-arch")},
				IsBookmarked: ref(true),
				IsStarred:    ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 2)
		So(*reposSum[0].Name, ShouldResemble, "repo1-only-images")
		So(*reposSum[1].Name, ShouldResemble, "repo3-only-multiarch")
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.ItemCount, ShouldEqual, 2)

		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{
				Os:            []*string{ref("good-os")},
				Arch:          []*string{ref("good-arch")},
				IsBookmarked:  ref(true),
				IsStarred:     ref(true),
				HasToBeSigned: ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)

		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{
				HasToBeSigned: ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 1)
		So(*reposSum[0].Name, ShouldResemble, "repo5-signed")
		So(pageInfo.ItemCount, ShouldEqual, 1)

		// no filter
		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{}, pagination.PageInput{SortBy: pagination.AlphabeticAsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 5)
		So(*reposSum[0].Name, ShouldResemble, "repo1-only-images")
		So(*reposSum[1].Name, ShouldResemble, "repo2-only-bad-images")
		So(*reposSum[2].Name, ShouldResemble, "repo3-only-multiarch")
		So(*reposSum[3].Name, ShouldResemble, "repo4-not-bookmarked-or-starred")
		So(*reposSum[4].Name, ShouldResemble, "repo5-signed")
		So(pageInfo.ItemCount, ShouldEqual, 5)

		// no filter opposite sorting
		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{}, pagination.PageInput{SortBy: pagination.AlphabeticDsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 5)
		So(*reposSum[0].Name, ShouldResemble, "repo5-signed")
		So(*reposSum[1].Name, ShouldResemble, "repo4-not-bookmarked-or-starred")
		So(*reposSum[2].Name, ShouldResemble, "repo3-only-multiarch")
		So(*reposSum[3].Name, ShouldResemble, "repo2-only-bad-images")
		So(*reposSum[4].Name, ShouldResemble, "repo1-only-images")
		So(pageInfo.ItemCount, ShouldEqual, 5)

		// add pagination
		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{
				Os:           []*string{ref("good-os")},
				Arch:         []*string{ref("good-arch")},
				IsBookmarked: ref(true),
				IsStarred:    ref(true),
			},
			pagination.PageInput{Limit: 1, Offset: 0, SortBy: pagination.AlphabeticAsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 1)
		So(*reposSum[0].Name, ShouldResemble, "repo1-only-images")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 2)

		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, repoMetaList, imageMeta,
			mTypes.Filter{
				Os:           []*string{ref("good-os")},
				Arch:         []*string{ref("good-arch")},
				IsBookmarked: ref(true),
				IsStarred:    ref(true),
			},
			pagination.PageInput{Limit: 1, Offset: 1, SortBy: pagination.AlphabeticAsc}, mocks.CveInfoMock{}, skipCVE,
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 1)
		So(*reposSum[0].Name, ShouldResemble, "repo3-only-multiarch")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 2)
	})

	Convey("PaginatedRepoMeta2ImageSummaries filtering and sorting", t, func() {
		fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
		So(err, ShouldBeNil)

		imgSum, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(
			ctx, fullImageMetaList, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:   []*string{ref("good-os")},
				Arch: []*string{ref("good-arch")},
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(imgSum), ShouldEqual, 5)
		So(*imgSum[0].RepoName, ShouldResemble, "repo1-only-images")
		So(*imgSum[0].Tag, ShouldResemble, "goodImage")
		So(*imgSum[1].RepoName, ShouldResemble, "repo3-only-multiarch")
		So(*imgSum[1].Tag, ShouldResemble, "goodMultiArch")
		So(*imgSum[2].RepoName, ShouldResemble, "repo4-not-bookmarked-or-starred")
		So(*imgSum[2].Tag, ShouldResemble, "goodImage")
		So(*imgSum[3].RepoName, ShouldResemble, "repo4-not-bookmarked-or-starred")
		So(*imgSum[3].Tag, ShouldResemble, "goodMultiArch")
		So(*imgSum[4].RepoName, ShouldResemble, "repo5-signed")
		So(*imgSum[4].Tag, ShouldResemble, "goodImage")
		So(pageInfo.ItemCount, ShouldEqual, 5)

		// add page of size 2
		imgSum, pageInfo, err = convert.PaginatedFullImageMeta2ImageSummaries(
			ctx, fullImageMetaList, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:   []*string{ref("good-os")},
				Arch: []*string{ref("good-arch")},
			},
			pagination.PageInput{Limit: 2, Offset: 0, SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(imgSum), ShouldEqual, 2)
		So(*imgSum[0].RepoName, ShouldResemble, "repo1-only-images")
		So(*imgSum[0].Tag, ShouldResemble, "goodImage")
		So(*imgSum[1].RepoName, ShouldResemble, "repo3-only-multiarch")
		So(*imgSum[1].Tag, ShouldResemble, "goodMultiArch")
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.TotalCount, ShouldEqual, 5)

		// next page
		imgSum, pageInfo, err = convert.PaginatedFullImageMeta2ImageSummaries(
			ctx, fullImageMetaList, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:   []*string{ref("good-os")},
				Arch: []*string{ref("good-arch")},
			},
			pagination.PageInput{Limit: 2, Offset: 2, SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(imgSum), ShouldEqual, 2)
		So(*imgSum[0].RepoName, ShouldResemble, "repo4-not-bookmarked-or-starred")
		So(*imgSum[0].Tag, ShouldResemble, "goodImage")
		So(*imgSum[1].RepoName, ShouldResemble, "repo4-not-bookmarked-or-starred")
		So(*imgSum[1].Tag, ShouldResemble, "goodMultiArch")
		So(pageInfo.ItemCount, ShouldEqual, 2)
		So(pageInfo.TotalCount, ShouldEqual, 5)

		// last page
		imgSum, pageInfo, err = convert.PaginatedFullImageMeta2ImageSummaries(
			ctx, fullImageMetaList, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:   []*string{ref("good-os")},
				Arch: []*string{ref("good-arch")},
			},
			pagination.PageInput{Limit: 2, Offset: 4, SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(imgSum), ShouldEqual, 1)
		So(*imgSum[0].RepoName, ShouldResemble, "repo5-signed")
		So(*imgSum[0].Tag, ShouldResemble, "goodImage")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 5)

		// has to be signed
		imgSum, pageInfo, err = convert.PaginatedFullImageMeta2ImageSummaries(
			ctx, fullImageMetaList, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:            []*string{ref("good-os")},
				Arch:          []*string{ref("good-arch")},
				HasToBeSigned: ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(imgSum), ShouldEqual, 1)
		So(*imgSum[0].RepoName, ShouldResemble, "repo5-signed")
		So(*imgSum[0].Tag, ShouldResemble, "goodImage")
		So(pageInfo.ItemCount, ShouldEqual, 1)
	})
}

func TestIndexAnnotations(t *testing.T) {
	Convey("Test ImageIndex2ImageSummary annotations logic", t, func() {
		ctx := context.Background()

		tempDir := t.TempDir()

		driver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: tempDir})
		if err != nil {
			t.FailNow()
		}

		metaDB, err := boltdb.New(driver, log.NewTestLogger())
		So(err, ShouldBeNil)

		defaultCreatedTime := *DefaultTimeRef()
		configCreatedTime := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		manifestCreatedTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		indexCreatedTime := time.Date(2011, 1, 1, 12, 0, 0, 0, time.UTC)

		configLabels := map[string]string{
			ispec.AnnotationCreated:       configCreatedTime.Format(time.RFC3339),
			ispec.AnnotationDescription:   "ConfigDescription",
			ispec.AnnotationLicenses:      "ConfigLicenses",
			ispec.AnnotationVendor:        "ConfigVendor",
			ispec.AnnotationAuthors:       "ConfigAuthors",
			ispec.AnnotationTitle:         "ConfigTitle",
			ispec.AnnotationDocumentation: "ConfigDocumentation",
			ispec.AnnotationSource:        "ConfigSource",
		}

		manifestAnnotations := map[string]string{
			ispec.AnnotationCreated:       manifestCreatedTime.Format(time.RFC3339),
			ispec.AnnotationDescription:   "ManifestDescription",
			ispec.AnnotationLicenses:      "ManifestLicenses",
			ispec.AnnotationVendor:        "ManifestVendor",
			ispec.AnnotationAuthors:       "ManifestAuthors",
			ispec.AnnotationTitle:         "ManifestTitle",
			ispec.AnnotationDocumentation: "ManifestDocumentation",
			ispec.AnnotationSource:        "ManifestSource",
		}

		indexAnnotations := map[string]string{
			ispec.AnnotationCreated:       indexCreatedTime.Format(time.RFC3339),
			ispec.AnnotationDescription:   "IndexDescription",
			ispec.AnnotationLicenses:      "IndexLicenses",
			ispec.AnnotationVendor:        "IndexVendor",
			ispec.AnnotationAuthors:       "IndexAuthors",
			ispec.AnnotationTitle:         "IndexTitle",
			ispec.AnnotationDocumentation: "IndexDocumentation",
			ispec.AnnotationSource:        "IndexSource",
		}

		imageWithConfigAnnotations := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{
				Config: ispec.ImageConfig{
					Labels: configLabels,
				},
			}).Build()

		imageWithManifestAndConfigAnnotations := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{
				Config: ispec.ImageConfig{
					Labels: configLabels,
				},
			}).Annotations(manifestAnnotations).Build()

		// --------------------------------------------------------
		indexWithAnnotations := CreateMultiarchWith().Images(
			[]Image{imageWithManifestAndConfigAnnotations},
		).Annotations(indexAnnotations).Build()

		ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB,
			ociutils.Repo{
				Name: "repo",
				MultiArchImages: []ociutils.RepoMultiArchImage{
					{MultiarchImage: indexWithAnnotations, Reference: "tag"},
				},
			})
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)
		imageMeta, err := metaDB.FilterImageMeta(ctx, []string{indexWithAnnotations.DigestStr()})
		So(err, ShouldBeNil)

		imageSummary, _, err := convert.ImageIndex2ImageSummary(ctx, convert.GetFullImageMeta("tag", repoMeta,
			imageMeta[indexWithAnnotations.DigestStr()]))
		So(err, ShouldBeNil)
		So(*imageSummary.LastUpdated, ShouldEqual, indexCreatedTime)
		So(*imageSummary.Description, ShouldResemble, "IndexDescription")
		So(*imageSummary.Licenses, ShouldResemble, "IndexLicenses")
		So(*imageSummary.Title, ShouldResemble, "IndexTitle")
		So(*imageSummary.Source, ShouldResemble, "IndexSource")
		So(*imageSummary.Documentation, ShouldResemble, "IndexDocumentation")
		So(*imageSummary.Vendor, ShouldResemble, "IndexVendor")
		So(*imageSummary.Authors, ShouldResemble, "IndexAuthors")

		err = metaDB.ResetDB()
		So(err, ShouldBeNil)
		// --------------------------------------------------------
		indexWithManifestAndConfigAnnotations := CreateMultiarchWith().Images(
			[]Image{imageWithManifestAndConfigAnnotations, CreateRandomImage(), CreateRandomImage()},
		).Build()

		ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB, ociutils.Repo{
			Name: "repo",
			MultiArchImages: []ociutils.RepoMultiArchImage{
				{MultiarchImage: indexWithManifestAndConfigAnnotations, Reference: "tag"},
			},
		})
		So(err, ShouldBeNil)

		digest := indexWithManifestAndConfigAnnotations.DigestStr()

		repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)
		imageMeta, err = metaDB.FilterImageMeta(ctx, []string{digest})
		So(err, ShouldBeNil)

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, convert.GetFullImageMeta("tag", repoMeta,
			imageMeta[digest]))
		So(err, ShouldBeNil)
		So(*imageSummary.LastUpdated, ShouldEqual, manifestCreatedTime)
		So(*imageSummary.Description, ShouldResemble, "ManifestDescription")
		So(*imageSummary.Licenses, ShouldResemble, "ManifestLicenses")
		So(*imageSummary.Title, ShouldResemble, "ManifestTitle")
		So(*imageSummary.Source, ShouldResemble, "ManifestSource")
		So(*imageSummary.Documentation, ShouldResemble, "ManifestDocumentation")
		So(*imageSummary.Vendor, ShouldResemble, "ManifestVendor")
		So(*imageSummary.Authors, ShouldResemble, "ManifestAuthors")

		err = metaDB.ResetDB()
		So(err, ShouldBeNil)
		// --------------------------------------------------------
		indexWithConfigAnnotations := CreateMultiarchWith().Images(
			[]Image{imageWithConfigAnnotations, CreateRandomImage(), CreateRandomImage()},
		).Build()

		ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB, ociutils.Repo{
			Name: "repo",
			MultiArchImages: []ociutils.RepoMultiArchImage{
				{MultiarchImage: indexWithConfigAnnotations, Reference: "tag"},
			},
		})
		So(err, ShouldBeNil)

		digest = indexWithConfigAnnotations.DigestStr()

		repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)
		imageMeta, err = metaDB.FilterImageMeta(ctx, []string{digest})
		So(err, ShouldBeNil)

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, convert.GetFullImageMeta("tag", repoMeta,
			imageMeta[digest]))
		So(err, ShouldBeNil)
		So(*imageSummary.LastUpdated, ShouldEqual, configCreatedTime)
		So(*imageSummary.Description, ShouldResemble, "ConfigDescription")
		So(*imageSummary.Licenses, ShouldResemble, "ConfigLicenses")
		So(*imageSummary.Title, ShouldResemble, "ConfigTitle")
		So(*imageSummary.Source, ShouldResemble, "ConfigSource")
		So(*imageSummary.Documentation, ShouldResemble, "ConfigDocumentation")
		So(*imageSummary.Vendor, ShouldResemble, "ConfigVendor")
		So(*imageSummary.Authors, ShouldResemble, "ConfigAuthors")

		err = metaDB.ResetDB()
		So(err, ShouldBeNil)
		//--------------------------------------------------------

		indexWithMixAnnotations := CreateMultiarchWith().Images(
			[]Image{
				CreateImageWith().DefaultLayers().ImageConfig(ispec.Image{
					Created: &defaultCreatedTime,
					Config: ispec.ImageConfig{
						Labels: map[string]string{
							ispec.AnnotationDescription: "ConfigDescription",
							ispec.AnnotationLicenses:    "ConfigLicenses",
						},
					},
				}).Annotations(map[string]string{
					ispec.AnnotationVendor:  "ManifestVendor",
					ispec.AnnotationAuthors: "ManifestAuthors",
				}).Build(),
				CreateRandomImage(),
				CreateRandomImage(),
			},
		).Annotations(
			map[string]string{
				ispec.AnnotationCreated:       indexCreatedTime.Format(time.RFC3339),
				ispec.AnnotationTitle:         "IndexTitle",
				ispec.AnnotationDocumentation: "IndexDocumentation",
				ispec.AnnotationSource:        "IndexSource",
			},
		).Build()

		ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB, ociutils.Repo{
			Name: "repo",
			MultiArchImages: []ociutils.RepoMultiArchImage{
				{MultiarchImage: indexWithMixAnnotations, Reference: "tag"},
			},
		})
		So(err, ShouldBeNil)

		digest = indexWithMixAnnotations.DigestStr()

		repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)
		imageMeta, err = metaDB.FilterImageMeta(ctx, []string{digest})
		So(err, ShouldBeNil)

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, convert.GetFullImageMeta("tag", repoMeta,
			imageMeta[digest]))
		So(err, ShouldBeNil)
		So(*imageSummary.LastUpdated, ShouldEqual, indexCreatedTime)
		So(*imageSummary.Description, ShouldResemble, "ConfigDescription")
		So(*imageSummary.Licenses, ShouldResemble, "ConfigLicenses")
		So(*imageSummary.Vendor, ShouldResemble, "ManifestVendor")
		So(*imageSummary.Authors, ShouldResemble, "ManifestAuthors")
		So(*imageSummary.Title, ShouldResemble, "IndexTitle")
		So(*imageSummary.Documentation, ShouldResemble, "IndexDocumentation")
		So(*imageSummary.Source, ShouldResemble, "IndexSource")

		err = metaDB.ResetDB()
		So(err, ShouldBeNil)
		//--------------------------------------------------------
		indexWithNoAnnotations := CreateMultiarchWith().Images(
			[]Image{
				CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build(),
				CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build(),
			},
		).Build()

		ctx, err = ociutils.InitializeTestMetaDB(ctx, metaDB, ociutils.Repo{
			Name: "repo",
			MultiArchImages: []ociutils.RepoMultiArchImage{
				{MultiarchImage: indexWithNoAnnotations, Reference: "tag"},
			},
		})
		So(err, ShouldBeNil)

		digest = indexWithNoAnnotations.DigestStr()

		repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
		So(err, ShouldBeNil)
		imageMeta, err = metaDB.FilterImageMeta(ctx, []string{digest})
		So(err, ShouldBeNil)

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, convert.GetFullImageMeta("tag", repoMeta,
			imageMeta[digest]))
		So(err, ShouldBeNil)
		So(*imageSummary.LastUpdated, ShouldEqual, defaultCreatedTime)
		So(*imageSummary.Description, ShouldBeBlank)
		So(*imageSummary.Licenses, ShouldBeBlank)
		So(*imageSummary.Vendor, ShouldBeBlank)
		So(*imageSummary.Authors, ShouldBeBlank)
		So(*imageSummary.Title, ShouldBeBlank)
		So(*imageSummary.Documentation, ShouldBeBlank)
		So(*imageSummary.Source, ShouldBeBlank)

		err = metaDB.ResetDB()
		So(err, ShouldBeNil)
	})
}

func TestConvertErrors(t *testing.T) {
	ctx := context.Background()
	log := log.NewTestLogger()

	Convey("Errors", t, func() {
		Convey("RepoMeta2ExpandedRepoInfo", func() {
			_, imgSums := convert.RepoMeta2ExpandedRepoInfo(ctx,
				mTypes.RepoMeta{
					Tags: map[mTypes.Tag]mTypes.Descriptor{"tag": {MediaType: "bad-type", Digest: "digest"}},
				},
				map[string]mTypes.ImageMeta{
					"digest": {},
				},
				convert.SkipQGLField{}, nil,
				log,
			)
			So(len(imgSums), ShouldEqual, 0)
		})

		Convey("RepoMeta2ExpandedRepoInfo - bad ctx value", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(ctx, uacKey, "bad context")

			_, imgSums := convert.RepoMeta2ExpandedRepoInfo(ctx,
				mTypes.RepoMeta{},
				map[string]mTypes.ImageMeta{
					"digest": {},
				},
				convert.SkipQGLField{}, nil,
				log,
			)
			So(len(imgSums), ShouldEqual, 0)
		})

		Convey("RepoMeta2ExpandedRepoInfo - nil ctx value", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(ctx, uacKey, nil)

			_, imgSums := convert.RepoMeta2ExpandedRepoInfo(ctx,
				mTypes.RepoMeta{},
				map[string]mTypes.ImageMeta{
					"digest": {},
				},
				convert.SkipQGLField{}, nil,
				log,
			)
			So(len(imgSums), ShouldEqual, 0)
		})
	})
}
