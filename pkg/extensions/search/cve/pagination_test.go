//go:build search
// +build search

package cveinfo_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	"zotregistry.io/zot/pkg/test/mocks"
)

func TestCVEPagination(t *testing.T) {
	Convey("CVE Pagination", t, func() {
		repoDB, err := bolt.NewBoltDBWrapper(bolt.DBParameters{
			RootDir: t.TempDir(),
		})
		So(err, ShouldBeNil)

		// Create repodb data for scannable image with vulnerabilities
		timeStamp11 := time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob11, err := json.Marshal(ispec.Image{
			Created: &timeStamp11,
		})
		So(err, ShouldBeNil)

		manifestBlob11, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob11),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta11 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob11,
			ConfigBlob:   configBlob11,
		}

		digest11 := godigest.FromBytes(manifestBlob11)
		err = repoDB.SetManifestMeta("repo1", digest11, repoMeta11)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoTag("repo1", "0.1.0", digest11, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		timeStamp12 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)

		configBlob12, err := json.Marshal(ispec.Image{
			Created: &timeStamp12,
		})
		So(err, ShouldBeNil)

		manifestBlob12, err := json.Marshal(ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Size:      0,
				Digest:    godigest.FromBytes(configBlob12),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta12 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob12,
			ConfigBlob:   configBlob12,
		}

		digest12 := godigest.FromBytes(manifestBlob12)
		err = repoDB.SetManifestMeta("repo1", digest12, repoMeta12)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoTag("repo1", "1.0.0", digest12, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		// RepoDB loaded with initial data, mock the scanner
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
			ScanImageFn: func(image string) (map[string]cvemodel.CVE, error) {
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
			CompareSeveritiesFn: func(severity1, severity2 string) int {
				return severityToInt[severity2] - severityToInt[severity1]
			},
		}

		log := log.NewLogger("debug", "")
		cveInfo := cveinfo.BaseCveInfo{Log: log, Scanner: scanner, RepoDB: repoDB}

		Convey("create new paginator errors", func() {
			paginator, err := cveinfo.NewCvePageFinder(-1, 10, cveinfo.AlphabeticAsc, cveInfo)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)

			paginator, err = cveinfo.NewCvePageFinder(2, -1, cveinfo.AlphabeticAsc, cveInfo)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)

			paginator, err = cveinfo.NewCvePageFinder(2, 1, "wrong sorting criteria", cveInfo)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})

		Convey("Reset", func() {
			paginator, err := cveinfo.NewCvePageFinder(1, 0, cveinfo.AlphabeticAsc, cveInfo)
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
				cves, pageInfo, err := cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 5)
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}

				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:1.0.0", cveinfo.PageInput{})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
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

				cves, pageInfo, err := cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{SortBy: cveinfo.AlphabeticAsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 5)
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i])
				}

				sort.Strings(cveIds)
				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:1.0.0", cveinfo.PageInput{SortBy: cveinfo.AlphabeticAsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i])
				}

				sort.Sort(sort.Reverse(sort.StringSlice(cveIds)))
				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:1.0.0", cveinfo.PageInput{SortBy: cveinfo.AlphabeticDsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i])
				}

				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:1.0.0", cveinfo.PageInput{SortBy: cveinfo.SeverityDsc})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 30)
				So(pageInfo.ItemCount, ShouldEqual, 30)
				So(pageInfo.TotalCount, ShouldEqual, 30)
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

				cves, pageInfo, err := cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{
					Limit:  3,
					Offset: 1,
					SortBy: cveinfo.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 3)
				So(pageInfo.ItemCount, ShouldEqual, 3)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE1") // CVE0 is first ID and is not part of the page
				So(cves[1].ID, ShouldEqual, "CVE2")
				So(cves[2].ID, ShouldEqual, "CVE3")

				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{
					Limit:  2,
					Offset: 1,
					SortBy: cveinfo.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE3")
				So(cves[1].ID, ShouldEqual, "CVE2")

				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{
					Limit:  3,
					Offset: 1,
					SortBy: cveinfo.SeverityDsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 3)
				So(pageInfo.ItemCount, ShouldEqual, 3)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}

				sort.Strings(cveIds)
				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:1.0.0", cveinfo.PageInput{
					Limit:  5,
					Offset: 20,
					SortBy: cveinfo.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 5)
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 30)
				for i, cve := range cves {
					So(cve.ID, ShouldEqual, cveIds[i+20])
				}
			})

			Convey("limit > len(cves)", func() {
				cves, pageInfo, err := cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{
					Limit:  6,
					Offset: 3,
					SortBy: cveinfo.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE3")
				So(cves[1].ID, ShouldEqual, "CVE4")

				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{
					Limit:  6,
					Offset: 3,
					SortBy: cveinfo.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				So(cves[0].ID, ShouldEqual, "CVE1")
				So(cves[1].ID, ShouldEqual, "CVE0")

				cves, pageInfo, err = cveInfo.GetCVEListForImage("repo1:0.1.0", cveinfo.PageInput{
					Limit:  6,
					Offset: 3,
					SortBy: cveinfo.SeverityDsc,
				})
				So(err, ShouldBeNil)
				So(len(cves), ShouldEqual, 2)
				So(pageInfo.ItemCount, ShouldEqual, 2)
				So(pageInfo.TotalCount, ShouldEqual, 5)
				previousSeverity := 4
				for _, cve := range cves {
					So(severityToInt[cve.Severity], ShouldBeLessThanOrEqualTo, previousSeverity)
					previousSeverity = severityToInt[cve.Severity]
				}
			})
		})
	})
}
