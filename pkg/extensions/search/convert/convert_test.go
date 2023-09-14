//go:build search

package convert_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/search/convert"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/extensions/search/pagination"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/test"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestConvertErrors(t *testing.T) {
	Convey("ImageIndex2ImageSummary errors", t, func() {
		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		_, _, err := convert.ImageIndex2ImageSummary(
			ctx,
			"repo",
			"tag",
			godigest.FromString("indexDigest"),
			mTypes.RepoMetadata{},
			mTypes.IndexData{
				IndexBlob: []byte("bad json"),
			},
			map[string]mTypes.ManifestMetadata{},
		)
		So(err, ShouldNotBeNil)
	})

	Convey("ImageIndex2ImageSummary cve scanning", t, func() {
		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		_, _, err := convert.ImageIndex2ImageSummary(
			ctx,
			"repo",
			"tag",
			godigest.FromString("indexDigest"),
			mTypes.RepoMetadata{},
			mTypes.IndexData{
				IndexBlob: []byte("{}"),
			},
			map[string]mTypes.ManifestMetadata{},
		)
		So(err, ShouldBeNil)
	})

	Convey("ImageManifest2ImageSummary", t, func() {
		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)
		configBlob, err := json.Marshal(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os",
				Architecture: "arch",
				Variant:      "var",
			},
		})
		So(err, ShouldBeNil)

		_, _, err = convert.ImageManifest2ImageSummary(
			ctx,
			"repo",
			"tag",
			godigest.FromString("manifestDigest"),
			mTypes.RepoMetadata{},
			mTypes.ManifestMetadata{
				ManifestBlob: []byte("{}"),
				ConfigBlob:   configBlob,
			},
		)
		So(err, ShouldBeNil)
	})

	Convey("ImageManifest2ManifestSummary", t, func() {
		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		// with bad config json, shouldn't error when unmarshaling
		_, _, _, err := convert.ImageManifest2ManifestSummary(
			ctx,
			"repo",
			"tag",
			ispec.Descriptor{
				Digest:    "dig",
				MediaType: ispec.MediaTypeImageManifest,
			},
			mTypes.RepoMetadata{
				Tags:       map[string]mTypes.Descriptor{},
				Statistics: map[string]mTypes.DescriptorStatistics{},
				Signatures: map[string]mTypes.ManifestSignatures{},
				Referrers:  map[string][]mTypes.ReferrerInfo{},
			},
			mTypes.ManifestMetadata{
				ManifestBlob: []byte(`{}`),
				ConfigBlob:   []byte("bad json"),
			},
			nil,
		)
		So(err, ShouldBeNil)

		// CVE scan using platform
		configBlob, err := json.Marshal(ispec.Image{
			Platform: ispec.Platform{
				OS:           "os",
				Architecture: "arch",
				Variant:      "var",
			},
		})
		So(err, ShouldBeNil)

		_, _, _, err = convert.ImageManifest2ManifestSummary(
			ctx,
			"repo",
			"tag",
			ispec.Descriptor{
				Digest:    "dig",
				MediaType: ispec.MediaTypeImageManifest,
			},
			mTypes.RepoMetadata{
				Tags:       map[string]mTypes.Descriptor{},
				Statistics: map[string]mTypes.DescriptorStatistics{},
				Signatures: map[string]mTypes.ManifestSignatures{"dig": {"cosine": []mTypes.SignatureInfo{{}}}},
				Referrers:  map[string][]mTypes.ReferrerInfo{},
			},
			mTypes.ManifestMetadata{
				ManifestBlob: []byte("{}"),
				ConfigBlob:   configBlob,
			},
			nil,
		)
		So(err, ShouldBeNil)
	})

	Convey("RepoMeta2ExpandedRepoInfo", t, func() {
		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		// with bad config json, error while unmarshaling
		_, imageSummaries := convert.RepoMeta2ExpandedRepoInfo(
			ctx,
			mTypes.RepoMetadata{
				Tags: map[string]mTypes.Descriptor{
					"tag1": {Digest: "dig", MediaType: ispec.MediaTypeImageManifest},
				},
			},
			map[string]mTypes.ManifestMetadata{
				"dig": {
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("bad json"),
				},
			},
			map[string]mTypes.IndexData{},
			convert.SkipQGLField{
				Vulnerabilities: false,
			},
			mocks.CveInfoMock{
				GetCVESummaryForImageMediaFn: func(repo, digest, mediaType string) (cvemodel.ImageCVESummary, error) {
					return cvemodel.ImageCVESummary{}, ErrTestError
				},
			}, log.NewLogger("debug", ""),
		)
		So(len(imageSummaries), ShouldEqual, 1)

		// cveInfo present no error
		_, imageSummaries = convert.RepoMeta2ExpandedRepoInfo(
			ctx,
			mTypes.RepoMetadata{
				Tags: map[string]mTypes.Descriptor{
					"tag1": {Digest: "dig", MediaType: ispec.MediaTypeImageManifest},
				},
			},
			map[string]mTypes.ManifestMetadata{
				"dig": {
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				},
			},
			map[string]mTypes.IndexData{},
			convert.SkipQGLField{
				Vulnerabilities: false,
			},
			mocks.CveInfoMock{
				GetCVESummaryForImageMediaFn: func(repo, digest, mediaType string) (cvemodel.ImageCVESummary, error) {
					return cvemodel.ImageCVESummary{}, ErrTestError
				},
			}, log.NewLogger("debug", ""),
		)
		So(len(imageSummaries), ShouldEqual, 1)
	})
}

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

		desc := convert.GetDescription(labels)
		So(desc, ShouldEqual, "")

		license := convert.GetLicenses(labels)
		So(license, ShouldEqual, "")

		vendor := convert.GetVendor(labels)
		So(vendor, ShouldEqual, "")

		categories := convert.GetCategories(labels)
		So(categories, ShouldEqual, "")

		labels[ispec.AnnotationVendor] = "zot"
		labels[ispec.AnnotationDescription] = "zot-desc"
		labels[ispec.AnnotationLicenses] = "zot-license"
		labels[convert.AnnotationLabels] = "zot-labels"

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
		labels[convert.LabelAnnotationVendor] = "zot-vendor"
		labels[convert.LabelAnnotationDescription] = "zot-label-desc"
		labels[ispec.AnnotationLicenses] = "zot-label-license"

		desc = convert.GetDescription(labels)
		So(desc, ShouldEqual, "zot-label-desc")

		license = convert.GetLicenses(labels)
		So(license, ShouldEqual, "zot-label-license")

		vendor = convert.GetVendor(labels)
		So(vendor, ShouldEqual, "zot-vendor")
	})
}

func TestGetSignaturesInfo(t *testing.T) {
	Convey("Test get signatures info - cosign", t, func() {
		indexDigest := godigest.FromString("123")
		repoMeta := mTypes.RepoMetadata{
			Signatures: map[string]mTypes.ManifestSignatures{string(indexDigest): {"cosign": []mTypes.SignatureInfo{{
				LayersInfo: []mTypes.LayerInfo{{LayerContent: []byte{}, LayerDigest: "", SignatureKey: "", Signer: "author"}},
			}}}},
		}

		signaturesSummary := convert.GetSignaturesInfo(true, repoMeta, indexDigest)
		So(signaturesSummary, ShouldNotBeEmpty)
		So(*signaturesSummary[0].Author, ShouldEqual, "author")
		So(*signaturesSummary[0].IsTrusted, ShouldEqual, true)
		So(*signaturesSummary[0].Tool, ShouldEqual, "cosign")
	})

	Convey("Test get signatures info - notation", t, func() {
		indexDigest := godigest.FromString("123")
		repoMeta := mTypes.RepoMetadata{
			Signatures: map[string]mTypes.ManifestSignatures{string(indexDigest): {"notation": []mTypes.SignatureInfo{{
				LayersInfo: []mTypes.LayerInfo{
					{
						LayerContent: []byte{},
						LayerDigest:  "",
						SignatureKey: "",
						Signer:       "author",
						Date:         time.Now().AddDate(0, 0, -1),
					},
				},
			}}}},
		}

		signaturesSummary := convert.GetSignaturesInfo(true, repoMeta, indexDigest)
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

func TestPaginatedConvert(t *testing.T) {
	ctx := context.Background()

	var (
		badBothImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "bad-os", Architecture: "bad-arch"}}).Build()
		badOsImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "bad-os", Architecture: "good-arch"}}).Build()
		badArchImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "good-os", Architecture: "bad-arch"}}).Build()
		goodImage = CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Platform: ispec.Platform{OS: "good-os", Architecture: "good-arch"}}).Build()

		randomImage1 = CreateRandomImage()
		randomImage2 = CreateRandomImage()

		badMultiArch = CreateMultiarchWith().Images(
			[]Image{badBothImage, badOsImage, badArchImage, randomImage1}).Build()
		goodMultiArch = CreateMultiarchWith().Images(
			[]Image{badOsImage, badArchImage, randomImage2, goodImage}).Build()
	)

	reposMeta, manifestMetaMap, indexDataMap := test.GetMetadataForRepos(
		test.Repo{
			Name: "repo1-only-images",
			Images: []test.RepoImage{
				{Image: goodImage, Tag: "goodImage"},
				{Image: badOsImage, Tag: "badOsImage"},
				{Image: badArchImage, Tag: "badArchImage"},
				{Image: badBothImage, Tag: "badBothImage"},
			},
			IsBookmarked: true,
			IsStarred:    true,
		},
		test.Repo{
			Name: "repo2-only-bad-images",
			Images: []test.RepoImage{
				{Image: randomImage1, Tag: "randomImage1"},
				{Image: randomImage2, Tag: "randomImage2"},
				{Image: badBothImage, Tag: "badBothImage"},
			},
			IsBookmarked: true,
			IsStarred:    true,
		},
		test.Repo{
			Name: "repo3-only-multiarch",
			MultiArchImages: []test.RepoMultiArchImage{
				{MultiarchImage: badMultiArch, Tag: "badMultiArch"},
				{MultiarchImage: goodMultiArch, Tag: "goodMultiArch"},
			},
			IsBookmarked: true,
			IsStarred:    true,
		},
		test.Repo{
			Name: "repo4-not-bookmarked-or-starred",
			Images: []test.RepoImage{
				{Image: goodImage, Tag: "goodImage"},
			},
			MultiArchImages: []test.RepoMultiArchImage{
				{MultiarchImage: goodMultiArch, Tag: "goodMultiArch"},
			},
		},
		test.Repo{
			Name: "repo5-signed",
			Images: []test.RepoImage{
				{Image: goodImage, Tag: "goodImage"}, // is fake signed by the image below
				{Image: CreateFakeTestSignature(goodImage.DescriptorRef())},
			},
		},
	)

	skipCVE := convert.SkipQGLField{Vulnerabilities: true}

	Convey("PaginatedRepoMeta2RepoSummaries filtering and sorting", t, func() {
		// Test different combinations of the filter

		reposSum, pageInfo, err := convert.PaginatedRepoMeta2RepoSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:           []*string{ref("good-os")},
				Arch:         []*string{ref("good-arch")},
				IsBookmarked: ref(true),
				IsStarred:    ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 2)
		So(*reposSum[0].Name, ShouldResemble, "repo1-only-images")
		So(*reposSum[1].Name, ShouldResemble, "repo3-only-multiarch")
		So(pageInfo.ItemCount, ShouldEqual, 2)

		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:            []*string{ref("good-os")},
				Arch:          []*string{ref("good-arch")},
				IsBookmarked:  ref(true),
				IsStarred:     ref(true),
				HasToBeSigned: ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 0)
		So(pageInfo.ItemCount, ShouldEqual, 0)

		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				HasToBeSigned: ref(true),
			},
			pagination.PageInput{SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 1)
		So(*reposSum[0].Name, ShouldResemble, "repo5-signed")
		So(pageInfo.ItemCount, ShouldEqual, 1)

		// no filter
		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{}, pagination.PageInput{SortBy: pagination.AlphabeticAsc},
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
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{}, pagination.PageInput{SortBy: pagination.AlphabeticDsc},
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
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:           []*string{ref("good-os")},
				Arch:         []*string{ref("good-arch")},
				IsBookmarked: ref(true),
				IsStarred:    ref(true),
			},
			pagination.PageInput{Limit: 1, Offset: 0, SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 1)
		So(*reposSum[0].Name, ShouldResemble, "repo1-only-images")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 2)

		reposSum, pageInfo, err = convert.PaginatedRepoMeta2RepoSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
			mTypes.Filter{
				Os:           []*string{ref("good-os")},
				Arch:         []*string{ref("good-arch")},
				IsBookmarked: ref(true),
				IsStarred:    ref(true),
			},
			pagination.PageInput{Limit: 1, Offset: 1, SortBy: pagination.AlphabeticAsc},
		)
		So(err, ShouldBeNil)
		So(len(reposSum), ShouldEqual, 1)
		So(*reposSum[0].Name, ShouldResemble, "repo3-only-multiarch")
		So(pageInfo.ItemCount, ShouldEqual, 1)
		So(pageInfo.TotalCount, ShouldEqual, 2)
	})

	Convey("PaginatedRepoMeta2ImageSummaries filtering and sorting", t, func() {
		imgSum, pageInfo, err := convert.PaginatedRepoMeta2ImageSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
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
		imgSum, pageInfo, err = convert.PaginatedRepoMeta2ImageSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
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
		imgSum, pageInfo, err = convert.PaginatedRepoMeta2ImageSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
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
		imgSum, pageInfo, err = convert.PaginatedRepoMeta2ImageSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
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
		imgSum, pageInfo, err = convert.PaginatedRepoMeta2ImageSummaries(
			ctx, reposMeta, manifestMetaMap, indexDataMap, skipCVE, mocks.CveInfoMock{},
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

		configLabels := map[string]string{
			ispec.AnnotationDescription:   "ConfigDescription",
			ispec.AnnotationLicenses:      "ConfigLicenses",
			ispec.AnnotationVendor:        "ConfigVendor",
			ispec.AnnotationAuthors:       "ConfigAuthors",
			ispec.AnnotationTitle:         "ConfigTitle",
			ispec.AnnotationDocumentation: "ConfigDocumentation",
			ispec.AnnotationSource:        "ConfigSource",
		}

		manifestAnnotations := map[string]string{
			ispec.AnnotationDescription:   "ManifestDescription",
			ispec.AnnotationLicenses:      "ManifestLicenses",
			ispec.AnnotationVendor:        "ManifestVendor",
			ispec.AnnotationAuthors:       "ManifestAuthors",
			ispec.AnnotationTitle:         "ManifestTitle",
			ispec.AnnotationDocumentation: "ManifestDocumentation",
			ispec.AnnotationSource:        "ManifestSource",
		}

		indexAnnotations := map[string]string{
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

		repoMeta, manifestMetadata, indexData := test.GetMetadataForRepos(test.Repo{
			Name: "repo",
			MultiArchImages: []test.RepoMultiArchImage{
				{MultiarchImage: indexWithAnnotations, Tag: "tag"},
			},
		})

		digest := indexWithAnnotations.Digest()

		imageSummary, _, err := convert.ImageIndex2ImageSummary(ctx, "repo", "tag", digest, repoMeta[0],
			indexData[digest.String()], manifestMetadata)
		So(err, ShouldBeNil)
		So(*imageSummary.Description, ShouldResemble, "IndexDescription")
		So(*imageSummary.Licenses, ShouldResemble, "IndexLicenses")
		So(*imageSummary.Title, ShouldResemble, "IndexTitle")
		So(*imageSummary.Source, ShouldResemble, "IndexSource")
		So(*imageSummary.Documentation, ShouldResemble, "IndexDocumentation")
		So(*imageSummary.Vendor, ShouldResemble, "IndexVendor")
		So(*imageSummary.Authors, ShouldResemble, "IndexAuthors")

		// --------------------------------------------------------
		indexWithManifestAndConfigAnnotations := CreateMultiarchWith().Images(
			[]Image{imageWithManifestAndConfigAnnotations, CreateRandomImage(), CreateRandomImage()},
		).Build()

		repoMeta, manifestMetadata, indexData = test.GetMetadataForRepos(test.Repo{
			Name:            "repo",
			MultiArchImages: []test.RepoMultiArchImage{{MultiarchImage: indexWithManifestAndConfigAnnotations}},
		})
		digest = indexWithManifestAndConfigAnnotations.Digest()

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, "repo", "tag", digest,
			repoMeta[0], indexData[digest.String()], manifestMetadata)
		So(err, ShouldBeNil)
		So(*imageSummary.Description, ShouldResemble, "ManifestDescription")
		So(*imageSummary.Licenses, ShouldResemble, "ManifestLicenses")
		So(*imageSummary.Title, ShouldResemble, "ManifestTitle")
		So(*imageSummary.Source, ShouldResemble, "ManifestSource")
		So(*imageSummary.Documentation, ShouldResemble, "ManifestDocumentation")
		So(*imageSummary.Vendor, ShouldResemble, "ManifestVendor")
		So(*imageSummary.Authors, ShouldResemble, "ManifestAuthors")
		// --------------------------------------------------------
		indexWithConfigAnnotations := CreateMultiarchWith().Images(
			[]Image{imageWithConfigAnnotations, CreateRandomImage(), CreateRandomImage()},
		).Build()

		repoMeta, manifestMetadata, indexData = test.GetMetadataForRepos(test.Repo{
			Name:            "repo",
			MultiArchImages: []test.RepoMultiArchImage{{MultiarchImage: indexWithConfigAnnotations, Tag: "tag"}},
		})
		digest = indexWithConfigAnnotations.Digest()

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, "repo", "tag", digest,
			repoMeta[0], indexData[digest.String()], manifestMetadata)
		So(err, ShouldBeNil)
		So(*imageSummary.Description, ShouldResemble, "ConfigDescription")
		So(*imageSummary.Licenses, ShouldResemble, "ConfigLicenses")
		So(*imageSummary.Title, ShouldResemble, "ConfigTitle")
		So(*imageSummary.Source, ShouldResemble, "ConfigSource")
		So(*imageSummary.Documentation, ShouldResemble, "ConfigDocumentation")
		So(*imageSummary.Vendor, ShouldResemble, "ConfigVendor")
		So(*imageSummary.Authors, ShouldResemble, "ConfigAuthors")
		//--------------------------------------------------------

		indexWithMixAnnotations := CreateMultiarchWith().Images(
			[]Image{
				CreateImageWith().DefaultLayers().ImageConfig(ispec.Image{
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
				ispec.AnnotationTitle:         "IndexTitle",
				ispec.AnnotationDocumentation: "IndexDocumentation",
				ispec.AnnotationSource:        "IndexSource",
			},
		).Build()

		repoMeta, manifestMetadata, indexData = test.GetMetadataForRepos(test.Repo{
			Name:            "repo",
			MultiArchImages: []test.RepoMultiArchImage{{MultiarchImage: indexWithMixAnnotations, Tag: "tag"}},
		})
		digest = indexWithMixAnnotations.Digest()

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, "repo", "tag", digest,
			repoMeta[0], indexData[digest.String()], manifestMetadata)
		So(err, ShouldBeNil)
		So(*imageSummary.Description, ShouldResemble, "ConfigDescription")
		So(*imageSummary.Licenses, ShouldResemble, "ConfigLicenses")
		So(*imageSummary.Vendor, ShouldResemble, "ManifestVendor")
		So(*imageSummary.Authors, ShouldResemble, "ManifestAuthors")
		So(*imageSummary.Title, ShouldResemble, "IndexTitle")
		So(*imageSummary.Documentation, ShouldResemble, "IndexDocumentation")
		So(*imageSummary.Source, ShouldResemble, "IndexSource")

		//--------------------------------------------------------
		indexWithNoAnnotations := CreateRandomMultiarch()

		repoMeta, manifestMetadata, indexData = test.GetMetadataForRepos(test.Repo{
			Name:            "repo",
			MultiArchImages: []test.RepoMultiArchImage{{MultiarchImage: indexWithNoAnnotations, Tag: "tag"}},
		})
		digest = indexWithNoAnnotations.Digest()

		imageSummary, _, err = convert.ImageIndex2ImageSummary(ctx, "repo", "tag", digest,
			repoMeta[0], indexData[digest.String()], manifestMetadata)
		So(err, ShouldBeNil)
		So(*imageSummary.Description, ShouldBeBlank)
		So(*imageSummary.Licenses, ShouldBeBlank)
		So(*imageSummary.Vendor, ShouldBeBlank)
		So(*imageSummary.Authors, ShouldBeBlank)
		So(*imageSummary.Title, ShouldBeBlank)
		So(*imageSummary.Documentation, ShouldBeBlank)
		So(*imageSummary.Source, ShouldBeBlank)
	})
}

func TestDownloadCount(t *testing.T) {
	Convey("manifest", t, func() {
		repoMeta, manifestMetaMap, indexDataMap := test.GetMetadataForRepos(
			test.Repo{
				Name: "repo",
				Images: []test.RepoImage{
					{
						Image: CreateRandomImage(),
						Tag:   "10-downloads",
						Statistics: mTypes.DescriptorStatistics{
							DownloadCount: 10,
						},
					},
				},
			},
		)

		repoSummary := convert.RepoMeta2RepoSummary(context.Background(), repoMeta[0], manifestMetaMap, indexDataMap)
		So(*repoSummary.DownloadCount, ShouldEqual, 10)
		So(*repoSummary.NewestImage.DownloadCount, ShouldEqual, 10)
	})

	Convey("index", t, func() {
		img1, img2, img3 := CreateRandomImage(), CreateRandomImage(), CreateRandomImage()
		multiArch := CreateMultiarchWith().Images([]Image{img1, img2, img3}).Build()

		repoMeta, manifestMetaMap, indexDataMap := test.GetMetadataForRepos(
			test.Repo{
				Name: "repo",
				MultiArchImages: []test.RepoMultiArchImage{
					{
						MultiarchImage: multiArch,
						Tag:            "160-multiarch",
						ImageStatistics: map[string]mTypes.DescriptorStatistics{
							img1.DigestStr():      {DownloadCount: 10},
							img2.DigestStr():      {DownloadCount: 20},
							img3.DigestStr():      {DownloadCount: 30},
							multiArch.DigestStr(): {DownloadCount: 100},
						},
					},
				},
			},
		)

		repoSummary := convert.RepoMeta2RepoSummary(context.Background(), repoMeta[0], manifestMetaMap, indexDataMap)
		So(*repoSummary.DownloadCount, ShouldEqual, 100)
		So(*repoSummary.NewestImage.DownloadCount, ShouldEqual, 100)
	})

	Convey("index + manifest mixed", t, func() {
		img1 := CreateRandomImage()
		img2 := CreateRandomImage()
		img3 := CreateImageWith().DefaultLayers().ImageConfig(
			ispec.Image{Created: DateRef(2020, 1, 1, 1, 1, 1, 0, time.UTC)},
		).Build()

		multiArch := CreateMultiarchWith().Images([]Image{img1, img2, img3}).Build()

		repoMeta, manifestMetaMap, indexDataMap := test.GetMetadataForRepos(
			test.Repo{
				Name: "repo",
				Images: []test.RepoImage{
					{
						Image:      CreateRandomImage(),
						Tag:        "5-downloads",
						Statistics: mTypes.DescriptorStatistics{DownloadCount: 5},
					},
				},
				MultiArchImages: []test.RepoMultiArchImage{
					{
						MultiarchImage: multiArch,
						Tag:            "160-multiarch",
						ImageStatistics: map[string]mTypes.DescriptorStatistics{
							img1.DigestStr():      {DownloadCount: 10},
							img2.DigestStr():      {DownloadCount: 20},
							img3.DigestStr():      {DownloadCount: 30},
							multiArch.DigestStr(): {DownloadCount: 100},
						},
					},
				},
			},
		)

		repoSummary := convert.RepoMeta2RepoSummary(context.Background(), repoMeta[0], manifestMetaMap, indexDataMap)
		So(*repoSummary.DownloadCount, ShouldEqual, 105)
		So(*repoSummary.NewestImage.DownloadCount, ShouldEqual, 100)
	})
}
