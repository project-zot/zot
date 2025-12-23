//go:build search

package cveinfo

import (
	"errors"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var ErrTestError = errors.New("test error")

func TestUtils(t *testing.T) {
	Convey("Utils", t, func() {
		Convey("cve.ContainsStr for package list", func() {
			cve := cvemodel.CVE{
				PackageList: []cvemodel.Package{
					{
						Name:             "NameTest",
						PackagePath:      "/usr/bin/artifacts/dummy.jar",
						FixedVersion:     "FixedVersionTest",
						InstalledVersion: "InstalledVersionTest",
					},
					{
						Name:             "NameTest",
						PackagePath:      "/usr/local/artifacts/dummy.gem",
						FixedVersion:     "FixedVersionTest",
						InstalledVersion: "InstalledVersionTest",
					},
				},
			}

			So(cve.ContainsStr("NameTest"), ShouldBeTrue)
			So(cve.ContainsStr("FixedVersionTest"), ShouldBeTrue)
			So(cve.ContainsStr("InstalledVersionTest"), ShouldBeTrue)
			So(cve.ContainsStr("/usr/bin/artifacts/dummy.jar"), ShouldBeTrue)
			So(cve.ContainsStr("dummy.jar"), ShouldBeTrue)
			So(cve.ContainsStr("/usr/local/artifacts/dummy.gem"), ShouldBeTrue)
			So(cve.ContainsStr("dummy.gem"), ShouldBeTrue)
		})
		Convey("getConfigAndDigest", func() {
			_, _, err := getConfigAndDigest(mocks.MetaDBMock{}, "bad-digest")
			So(err, ShouldNotBeNil)

			_, _, err = getConfigAndDigest(mocks.MetaDBMock{
				GetImageMetaFn: func(digest digest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, ErrTestError
				},
			}, ispec.DescriptorEmptyJSON.Digest.String())
			So(err, ShouldNotBeNil)

			// bad media type of config
			_, _, err = getConfigAndDigest(mocks.MetaDBMock{
				GetImageMetaFn: func(digest digest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{Manifests: []types.ManifestMeta{
						{Manifest: ispec.Manifest{Config: ispec.Descriptor{MediaType: "bad-type"}}},
					}}, nil
				},
			}, ispec.DescriptorEmptyJSON.Digest.String())
			So(err, ShouldNotBeNil)
		})
		Convey("getIndexContent", func() {
			_, err := getIndexContent(mocks.MetaDBMock{}, "bad-digest")
			So(err, ShouldNotBeNil)

			_, err = getIndexContent(mocks.MetaDBMock{
				GetImageMetaFn: func(digest digest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, ErrTestError
				},
			}, ispec.DescriptorEmptyJSON.Digest.String())
			So(err, ShouldNotBeNil)

			// nil index
			_, err = getIndexContent(mocks.MetaDBMock{
				GetImageMetaFn: func(digest digest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, nil
				},
			}, ispec.DescriptorEmptyJSON.Digest.String())
			So(err, ShouldNotBeNil)
		})

		Convey("mostRecentUpdate", func() {
			// empty
			timestamp := mostRecentUpdate([]cvemodel.DescriptorInfo{})
			So(timestamp, ShouldResemble, time.Time{})

			timestamp = mostRecentUpdate([]cvemodel.DescriptorInfo{
				{
					Timestamp: time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC),
				},
				{
					Timestamp: time.Date(2005, 1, 1, 1, 1, 1, 1, time.UTC),
				},
			})
			So(timestamp, ShouldResemble, time.Date(2005, 1, 1, 1, 1, 1, 1, time.UTC))
		})

		Convey("GetFixedTags", func() {
			tags := GetFixedTags(
				[]cvemodel.TagInfo{
					{},
				},
				[]cvemodel.TagInfo{
					{
						Descriptor: cvemodel.Descriptor{
							MediaType: ispec.MediaTypeImageManifest,
						},
						Timestamp: time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC),
					},
					{
						Descriptor: cvemodel.Descriptor{
							MediaType: ispec.MediaTypeImageIndex,
						},
						Manifests: []cvemodel.DescriptorInfo{
							{
								Timestamp: time.Date(2002, 1, 1, 1, 1, 1, 1, time.UTC),
							},
							{
								Timestamp: time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC),
							},
						},
					},
					{
						Descriptor: cvemodel.Descriptor{
							MediaType: "bad Type",
						},
					},
				})
			So(tags, ShouldBeEmpty)
		})

		Convey("shouldIncludeCVE filtering logic", func() {
			baseCVE := cvemodel.CVE{
				ID:          "CVE-2024-0001",
				Severity:    "HIGH",
				Title:       "Test CVE 1",
				Description: "Description contains keyword",
			}

			Convey("includes CVE when all filters pass", func() {
				// No filters
				So(shouldIncludeCVE(baseCVE, "", "", ""), ShouldBeTrue)

				// Matching searchedCVE
				So(shouldIncludeCVE(baseCVE, "CVE-2024", "", ""), ShouldBeTrue)
				So(shouldIncludeCVE(baseCVE, "keyword", "", ""), ShouldBeTrue)

				// Matching severity
				So(shouldIncludeCVE(baseCVE, "", "", "HIGH"), ShouldBeTrue)
			})

			Convey("excludes CVE when severity doesn't match", func() {
				So(shouldIncludeCVE(baseCVE, "", "", "LOW"), ShouldBeFalse)
				So(shouldIncludeCVE(baseCVE, "", "", "MEDIUM"), ShouldBeFalse)
				So(shouldIncludeCVE(baseCVE, "", "", "CRITICAL"), ShouldBeFalse)
			})

			Convey("excludes CVE when it contains excluded string", func() {
				So(shouldIncludeCVE(baseCVE, "", "keyword", ""), ShouldBeFalse)
				So(shouldIncludeCVE(baseCVE, "", "CVE-2024", ""), ShouldBeFalse)
				So(shouldIncludeCVE(baseCVE, "", "Test CVE", ""), ShouldBeFalse)
			})

			Convey("excludes CVE when searchedCVE doesn't match", func() {
				So(shouldIncludeCVE(baseCVE, "CVE-2023", "", ""), ShouldBeFalse)
				So(shouldIncludeCVE(baseCVE, "notfound", "", ""), ShouldBeFalse)
			})

			Convey("handles multiple filters combined", func() {
				// All filters match - should include
				So(shouldIncludeCVE(baseCVE, "CVE-2024", "", "HIGH"), ShouldBeTrue)

				// Severity matches but excluded - should exclude
				So(shouldIncludeCVE(baseCVE, "", "keyword", "HIGH"), ShouldBeFalse)

				// Searched matches but severity doesn't - should exclude
				So(shouldIncludeCVE(baseCVE, "CVE-2024", "", "LOW"), ShouldBeFalse)

				// Everything matches but excluded - should exclude
				So(shouldIncludeCVE(baseCVE, "CVE-2024", "Test", "HIGH"), ShouldBeFalse)
			})
		})
	})
}
