package cveinfo

import (
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
)

func TestUtils(t *testing.T) {
	Convey("Utils", t, func() {
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
	})
}
