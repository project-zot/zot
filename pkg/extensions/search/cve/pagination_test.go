//go:build search
// +build search

package cveinfo_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	cveinfo "zotregistry.dev/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

func TestCVEPagination(t *testing.T) {
	Convey("CVE Pagination", t, func() {
		params := boltdb.DBParameters{
			RootDir: t.TempDir(),
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		// Create metadb data for scannable image with vulnerabilities
		timeStamp11 := time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC)

		image := CreateImageWith().
			Layers([]Layer{{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    ispec.DescriptorEmptyJSON.Digest,
				Blob:      ispec.DescriptorEmptyJSON.Data,
			}}).ImageConfig(ispec.Image{Created: &timeStamp11}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo1", "0.1.0", image.AsImageMeta())
		So(err, ShouldBeNil)

		timeStamp12 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)

		image2 := CreateImageWith().
			Layers([]Layer{{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    ispec.DescriptorEmptyJSON.Digest,
				Blob:      ispec.DescriptorEmptyJSON.Data,
			}}).ImageConfig(ispec.Image{Created: &timeStamp12}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo1", "1.0.0", image2.AsImageMeta())
		So(err, ShouldBeNil)

		// MetaDB loaded with initial data, mock the scanner
		severityToInt := map[string]int{
			"UNKNOWN":  0,
			"LOW":      1,
			"MEDIUM":   2,
			"HIGH":     3,
			"CRITICAL": 4,
		}

		intToSeverity := make(map[int]string, len(severityToInt))
		for k, v := range severityToInt {
			intToSeverity[v] = k
		}

		// Setup test CVE data in mock scanner
		scanner := mocks.CveScannerMock{
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				cveMap := map[string]cvemodel.CVE{}

				if image == "repo1:0.1.0" {
					for i := 0; i < 5; i++ {
						cveMap[fmt.Sprintf("CVE%d", i)] = cvemodel.CVE{
							ID:          fmt.Sprintf("CVE%d", i),
							Severity:    intToSeverity[i%5],
							Title:       fmt.Sprintf("Title for CVE%d", i),
							Description: fmt.Sprintf("Description for CVE%d", i),
						}
					}
				}

				if image == "repo1:1.0.0" {
					for i := 0; i < 30; i++ {
						cveMap[fmt.Sprintf("CVE%d", i)] = cvemodel.CVE{
							ID:          fmt.Sprintf("CVE%d", i),
							Severity:    intToSeverity[i%5],
							Title:       fmt.Sprintf("Title for CVE%d", i),
							Description: fmt.Sprintf("Description for CVE%d", i),
						}
					}
				}

				// By default the image has no vulnerabilities
				return cveMap, nil
			},
		}

		log := log.NewLogger("debug", "")
		cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, MetaDB: metaDB}

		ctx := context.Background()

		Convey("create new paginator errors", func() {
			paginator, err := cveinfo.NewCvePageFinder(-1, 10, cveinfo.AlphabeticAsc)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)

			paginator, err = cveinfo.NewCvePageFinder(2, -1, cveinfo.AlphabeticAsc)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)

			paginator, err = cveinfo.NewCvePageFinder(2, 1, "wrong sorting criteria")
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})

		Convey("Reset", func() {
			paginator, err := cveinfo.NewCvePageFinder(1, 0, cveinfo.AlphabeticAsc)
			So(err, ShouldBeNil)
			So(paginator, ShouldNotBeNil)

			paginator.Add(cvemodel.CVE{})
			paginator.Add(cvemodel.CVE{})
			paginator.Add(cvemodel.CVE{})

			paginator.Reset()

			result, _ := paginator.Page()
			So(result, ShouldBeEmpty)
		})

		Convey("Page", func() {
			Convey("defaults", func() {
				// By default expect unlimitted results sorted by severity
				cves, cveSummary, pageInfo, err := cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "",
					"", cvemodel.PageInput{})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 5)
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}

				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "1.0.0", "", "", "",
					cvemodel.PageInput{})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				So(cveSummary.Count, ShouldEqual, 30)
				So(cveSummary.UnknownCount, ShouldEqual, 6)
				So(cveSummary.LowCount, ShouldEqual, 6)
				So(cveSummary.MediumCount, ShouldEqual, 6)
				So(cveSummary.HighCount, ShouldEqual, 6)
				So(cveSummary.CriticalCount, ShouldEqual, 6)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				previousSeverity = 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}
			})

			Convey("no limit or offset", func() {
				cveIds := []string{}
				for i := 0; i < 30; i++ {
					cveIds = append(cveIds, fmt.Sprintf("CVE%d", i))
				}

				cves, cveSummary, pageInfo, err := cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "",
					cvemodel.PageInput{SortBy: cveinfo.AlphabeticAsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 5)
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i])
				}

				sort.Strings(cveIds)
				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "1.0.0", "", "", "",
					cvemodel.PageInput{SortBy: cveinfo.AlphabeticAsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				So(cveSummary.Count, ShouldEqual, 30)
				So(cveSummary.UnknownCount, ShouldEqual, 6)
				So(cveSummary.LowCount, ShouldEqual, 6)
				So(cveSummary.MediumCount, ShouldEqual, 6)
				So(cveSummary.HighCount, ShouldEqual, 6)
				So(cveSummary.CriticalCount, ShouldEqual, 6)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i])
				}

				sort.Sort(sort.Reverse(sort.StringSlice(cveIds)))
				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "1.0.0", "", "", "",
					cvemodel.PageInput{SortBy: cveinfo.AlphabeticDsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				So(cveSummary.Count, ShouldEqual, 30)
				So(cveSummary.UnknownCount, ShouldEqual, 6)
				So(cveSummary.LowCount, ShouldEqual, 6)
				So(cveSummary.MediumCount, ShouldEqual, 6)
				So(cveSummary.HighCount, ShouldEqual, 6)
				So(cveSummary.CriticalCount, ShouldEqual, 6)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i])
				}

				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "1.0.0", "", "", "",
					cvemodel.PageInput{SortBy: cveinfo.SeverityDsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				So(cveSummary.Count, ShouldEqual, 30)
				So(cveSummary.UnknownCount, ShouldEqual, 6)
				So(cveSummary.LowCount, ShouldEqual, 6)
				So(cveSummary.MediumCount, ShouldEqual, 6)
				So(cveSummary.HighCount, ShouldEqual, 6)
				So(cveSummary.CriticalCount, ShouldEqual, 6)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}
			})

			Convey("limit < len(cves)", func() {
				cveIds := []string{}
				for i := 0; i < 30; i++ {
					cveIds = append(cveIds, fmt.Sprintf("CVE%d", i))
				}

				cves, cveSummary, pageInfo, err := cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "", cvemodel.PageInput{
					Limit:  3,
					Offset: 1,
					SortBy: cveinfo.AlphabeticAsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 3)
				So(pageInfo.ItemCount, ShouldEqual, 3)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE1") // CVE0 is first ID and is not part of the page
				So(cves[1].ID, ShouldEqual, "CVE2")
				So(cves[2].ID, ShouldEqual, "CVE3")
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")

				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "", cvemodel.PageInput{
					Limit:  2,
					Offset: 1,
					SortBy: cveinfo.AlphabeticDsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE3")
				So(cves[1].ID, ShouldEqual, "CVE2")
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")

				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "", cvemodel.PageInput{
					Limit:  3,
					Offset: 1,
					SortBy: cveinfo.SeverityDsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 3)
				So(pageInfo.ItemCount, ShouldEqual, 3)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}

				sort.Strings(cveIds)
				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "1.0.0", "", "", "", cvemodel.PageInput{
					Limit:  5,
					Offset: 20,
					SortBy: cveinfo.AlphabeticAsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 5)
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				So(cveSummary.Count, ShouldEqual, 30)
				So(cveSummary.UnknownCount, ShouldEqual, 6)
				So(cveSummary.LowCount, ShouldEqual, 6)
				So(cveSummary.MediumCount, ShouldEqual, 6)
				So(cveSummary.HighCount, ShouldEqual, 6)
				So(cveSummary.CriticalCount, ShouldEqual, 6)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i+20])
				}
			})

			Convey("limit > len(cves)", func() {
				cves, cveSummary, pageInfo, err := cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "", cvemodel.PageInput{
					Limit:  6,
					Offset: 3,
					SortBy: cveinfo.AlphabeticAsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE3")
				So(cves[1].ID, ShouldEqual, "CVE4")
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")

				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "", cvemodel.PageInput{
					Limit:  6,
					Offset: 3,
					SortBy: cveinfo.AlphabeticDsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE1")
				So(cves[1].ID, ShouldEqual, "CVE0")
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")

				cves, cveSummary, pageInfo, err = cveInfo.GetCVEListForImage(ctx, "repo1", "0.1.0", "", "", "", cvemodel.PageInput{
					Limit:  6,
					Offset: 3,
					SortBy: cveinfo.SeverityDsc,
				},
				)
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cveSummary.Count, ShouldEqual, 5)
				So(cveSummary.UnknownCount, ShouldEqual, 1)
				So(cveSummary.LowCount, ShouldEqual, 1)
				So(cveSummary.MediumCount, ShouldEqual, 1)
				So(cveSummary.HighCount, ShouldEqual, 1)
				So(cveSummary.CriticalCount, ShouldEqual, 1)
				So(cveSummary.MaxSeverity, ShouldEqual, "CRITICAL")
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}
			})
		})
	})
}
