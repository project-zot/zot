//go:build search
// +build search

//
//nolint:dupl
package client

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/cobra"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
)

func TestSearchAllImages(t *testing.T) {
	Convey("SearchAllImages", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getAllImagesFn: func(ctx context.Context, config SearchConfig, username, password string,
				channel chan stringResult, wtgrp *sync.WaitGroup,
			) {
				str, err := getMockImageStruct().stringPlainText(10, 10, 10, false)

				channel <- stringResult{StrValue: str, Err: err}
			},
		})

		err := SearchAllImages(searchConfig)
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})
}

func TestSearchAllImagesGQL(t *testing.T) {
	Convey("SearchAllImagesGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesGQLFn: func(ctx context.Context, config SearchConfig, username, password, imageName string,
			) (*common.ImageListResponse, error) {
				return &common.ImageListResponse{ImageList: common.ImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{
						Results: []common.ImageSummary{getMockImageSummary()},
					},
				}}, nil
			},
		})

		err := SearchAllImagesGQL(searchConfig)
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchAllImagesGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesGQLFn: func(ctx context.Context, config SearchConfig, username, password, imageName string,
			) (*common.ImageListResponse, error) {
				return &common.ImageListResponse{ImageList: common.ImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{
						Results: []common.ImageSummary{getMockImageSummary()},
					},
				}}, zerr.ErrInjected
			},
		})

		err := SearchAllImagesGQL(searchConfig)
		So(err, ShouldNotBeNil)
	})
}

func TestSearchImageByName(t *testing.T) {
	Convey("SearchImageByName", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImageByNameFn: func(ctx context.Context, config SearchConfig, username string, password string, imageName string,
				channel chan stringResult, wtgrp *sync.WaitGroup,
			) {
				str, err := getMockImageStruct().stringPlainText(10, 10, 10, false)

				channel <- stringResult{StrValue: str, Err: err}
			},
		})

		err := SearchImageByName(searchConfig, "repo")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchImageByName error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImageByNameFn: func(ctx context.Context, config SearchConfig, username string, password string, imageName string,
				channel chan stringResult, wtgrp *sync.WaitGroup,
			) {
				channel <- stringResult{StrValue: "", Err: zerr.ErrInjected}
			},
		})

		err := SearchImageByName(searchConfig, "repo")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchImageByNameGQL(t *testing.T) {
	Convey("SearchImageByNameGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesGQLFn: func(ctx context.Context, config SearchConfig, username, password, imageName string,
			) (*common.ImageListResponse, error) {
				return &common.ImageListResponse{ImageList: common.ImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{
						Results: []common.ImageSummary{getMockImageSummary()},
					},
				}}, nil
			},
		})

		err := SearchImageByNameGQL(searchConfig, "repo")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchImageByNameGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesGQLFn: func(ctx context.Context, config SearchConfig, username, password, imageName string,
			) (*common.ImageListResponse, error) {
				return &common.ImageListResponse{ImageList: common.ImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{
						Results: []common.ImageSummary{getMockImageSummary()},
					},
				}}, zerr.ErrInjected
			},
		})

		err := SearchImageByNameGQL(searchConfig, "repo")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchImagesByDigest(t *testing.T) {
	Convey("SearchImagesByDigest", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesByDigestFn: func(ctx context.Context, config SearchConfig, username string, password string, digest string,
				rch chan stringResult, wtgrp *sync.WaitGroup,
			) {
				str, err := getMockImageStruct().stringPlainText(10, 10, 10, false)

				rch <- stringResult{StrValue: str, Err: err}
			},
		})

		err := SearchImagesByDigest(searchConfig, godigest.FromString("str").String())
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchImagesByDigest error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesByDigestFn: func(ctx context.Context, config SearchConfig, username string, password string, digest string,
				rch chan stringResult, wtgrp *sync.WaitGroup,
			) {
				rch <- stringResult{StrValue: "", Err: zerr.ErrInjected}
			},
		})

		err := SearchImagesByDigest(searchConfig, godigest.FromString("str").String())
		So(err, ShouldNotBeNil)
	})
}

func TestSearchDerivedImageListGQL(t *testing.T) {
	Convey("SearchDerivedImageListGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getDerivedImageListGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				derivedImage string) (*common.DerivedImageListResponse, error,
			) {
				return &common.DerivedImageListResponse{DerivedImageList: common.DerivedImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{
						Results: []common.ImageSummary{
							getMockImageSummary(),
						},
					},
				}}, nil
			},
		})

		err := SearchDerivedImageListGQL(searchConfig, "repo:tag")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchDerivedImageListGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getDerivedImageListGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				derivedImage string) (*common.DerivedImageListResponse, error,
			) {
				return &common.DerivedImageListResponse{DerivedImageList: common.DerivedImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{Results: []common.ImageSummary{}},
				}}, zerr.ErrInjected
			},
		})

		err := SearchDerivedImageListGQL(searchConfig, "repo:tag")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchBaseImageListGQL(t *testing.T) {
	Convey("SearchBaseImageListGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getBaseImageListGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				derivedImage string) (*common.BaseImageListResponse, error,
			) {
				return &common.BaseImageListResponse{BaseImageList: common.BaseImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{Results: []common.ImageSummary{
						getMockImageSummary(),
					}},
				}}, nil
			},
		})

		err := SearchBaseImageListGQL(searchConfig, "repo:tag")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchBaseImageListGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getBaseImageListGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				derivedImage string) (*common.BaseImageListResponse, error,
			) {
				return &common.BaseImageListResponse{BaseImageList: common.BaseImageList{
					PaginatedImagesResult: common.PaginatedImagesResult{Results: []common.ImageSummary{}},
				}}, zerr.ErrInjected
			},
		})

		err := SearchBaseImageListGQL(searchConfig, "repo:tag")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchImagesForDigestGQL(t *testing.T) {
	Convey("SearchImagesForDigestGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesForDigestGQLFn: func(ctx context.Context, config SearchConfig, username string,
				password string, digest string) (*common.ImagesForDigest, error,
			) {
				return &common.ImagesForDigest{ImagesForDigestList: common.ImagesForDigestList{
					PaginatedImagesResult: common.PaginatedImagesResult{
						Results: []common.ImageSummary{getMockImageSummary()},
					},
				}}, nil
			},
		})

		err := SearchImagesForDigestGQL(searchConfig, "digest")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchImagesForDigestGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getImagesForDigestGQLFn: func(ctx context.Context, config SearchConfig, username string,
				password string, digest string) (*common.ImagesForDigest, error,
			) {
				return &common.ImagesForDigest{ImagesForDigestList: common.ImagesForDigestList{
					PaginatedImagesResult: common.PaginatedImagesResult{},
				}}, zerr.ErrInjected
			},
		})

		err := SearchImagesForDigestGQL(searchConfig, "digest")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchCVEForImageGQL(t *testing.T) {
	Convey("SearchCVEForImageGQL normal mode", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getCveByImageGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				imageName string, searchedCVE string) (*cveResult, error,
			) {
				return &cveResult{
					Data: cveData{
						CVEListForImage: cveListForImage{
							CVEList: []cve{
								{
									ID:          "dummyCVEID",
									Description: "Description of the CVE",
									Title:       "Title of that CVE",
									Severity:    "HIGH",
									PackageList: []packageList{
										{
											Name:             "packagename",
											FixedVersion:     "fixedver",
											InstalledVersion: "installedver",
										},
									},
								},
								{
									ID:          "test-cve-id2",
									Description: "Test CVE ID 2",
									Title:       "Test CVE 2",
									Severity:    "HIGH",
									PackageList: []packageList{
										{
											Name:             "packagename",
											PackagePath:      "/usr/bin/dummy.jar",
											FixedVersion:     "fixedver",
											InstalledVersion: "installedver",
										},
										{
											Name:             "packagename",
											PackagePath:      "/usr/bin/dummy.gem",
											FixedVersion:     "fixedver",
											InstalledVersion: "installedver",
										},
									},
								},
							},
							Summary: common.ImageVulnerabilitySummary{
								Count:         2,
								UnknownCount:  0,
								LowCount:      0,
								MediumCount:   0,
								HighCount:     2,
								CriticalCount: 0,
								MaxSeverity:   "HIGH",
							},
						},
					},
				}, nil
			},
		})

		err := SearchCVEForImageGQL(searchConfig, "repo-test", "dummyCVEID")
		So(err, ShouldBeNil)
		bufferContent := buff.String()
		bufferLines := strings.Split(bufferContent, "\n")

		// Expected result - each row indicates a row of the table with reduced spaces
		expected := []string{
			"CRITICAL 0, HIGH 2, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 2",
			"",
			"ID SEVERITY TITLE VULNERABLE PACKAGE PATH INSTALL-VER FIXED-VER",
			"dummyCVEID HIGH Title of that CVE",
			"packagename - installedver fixedver",
			"test-cve-id2 HIGH Test CVE 2",
			"packagename /usr/bin/dummy.jar installedver fixedver",
			"packagename /usr/bin/dummy.gem installedver fixedver",
		}

		space := regexp.MustCompile(`\s+`)

		for lineIndex := 0; lineIndex < len(expected); lineIndex++ {
			line := space.ReplaceAllString(bufferLines[lineIndex], " ")
			So(line, ShouldEqualTrimSpace, expected[lineIndex])
		}
	})

	Convey("SearchCVEForImageGQL verbose mode", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getCveByImageGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				imageName string, searchedCVE string) (*cveResult, error,
			) {
				return &cveResult{
					Data: cveData{
						CVEListForImage: cveListForImage{
							CVEList: []cve{
								{
									ID:          "CVE-100",
									Description: "",
									Title:       "CVE-100 Title",
									Severity:    "HIGH",
									PackageList: []packageList{},
								},
								{
									ID:          "CVE-101",
									Description: "Desc 101\n",
									Title:       "CVE-101 Title",
									Severity:    "HIGH",
									PackageList: []packageList{
										{
											Name:             "Pkg1",
											FixedVersion:     "2.0.0",
											InstalledVersion: "1.0.0",
										},
									},
								},
								{
									ID:          "CVE-102",
									Description: "Desc 102",
									Title:       "CVE-102 Title",
									Severity:    "HIGH",
									PackageList: []packageList{
										{
											Name:             "dummy-java",
											PackagePath:      "/usr/bin/dummy.jar",
											FixedVersion:     "4.0.0",
											InstalledVersion: "3.0.0",
										},
										{
											Name:             "dummy-ruby",
											PackagePath:      "/usr/bin/dummy.gem",
											FixedVersion:     "5.0.0",
											InstalledVersion: "1.0.0",
										},
									},
								},
							},
							Summary: common.ImageVulnerabilitySummary{
								Count:         3,
								UnknownCount:  0,
								LowCount:      0,
								MediumCount:   0,
								HighCount:     3,
								CriticalCount: 0,
								MaxSeverity:   "HIGH",
							},
						},
					},
				}, nil
			},
		})

		searchConfig.Verbose = true
		err := SearchCVEForImageGQL(searchConfig, "repo-test", "dummyCVEID")
		So(err, ShouldBeNil)
		bufferContent := buff.String()
		bufferLines := strings.Split(bufferContent, "\n")

		// Expected result - each row indicates a line in the output
		expected := []string{
			"CRITICAL 0, HIGH 3, MEDIUM 0, LOW 0, UNKNOWN 0, TOTAL 3",
			"",
			"CVE-100",
			"Severity: HIGH",
			"Title: CVE-100 Title",
			"Description:",
			"Not Specified",
			"",
			"Vulnerable Packages:",
			"No Vulnerable Packages",
			"",
			"",
			"CVE-101",
			"Severity: HIGH",
			"Title: CVE-101 Title",
			"Description:",
			"Desc 101",
			"",
			"Vulnerable Packages:",
			" Package Name: Pkg1",
			" Package Path: ",
			" Installed Version: 1.0.0",
			" Fixed Version: 2.0.0",
			"",
			"",
			"CVE-102",
			"Severity: HIGH",
			"Title: CVE-102 Title",
			"Description:",
			"Desc 102",
			"",
			"Vulnerable Packages:",
			" Package Name: dummy-java",
			" Package Path: /usr/bin/dummy.jar",
			" Installed Version: 3.0.0",
			" Fixed Version: 4.0.0",
			"",
			" Package Name: dummy-ruby",
			" Package Path: /usr/bin/dummy.gem",
			" Installed Version: 1.0.0",
			" Fixed Version: 5.0.0",
			"",
			"",
		}

		for index, expectedLine := range expected {
			So(bufferLines[index], ShouldEqual, expectedLine)
		}
	})

	Convey("SearchCVEForImageGQL with injected error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getCveByImageGQLFn: func(ctx context.Context, config SearchConfig, username string, password string,
				imageName string, searchedCVE string) (*cveResult, error,
			) {
				return &cveResult{}, zerr.ErrInjected
			},
		})

		err := SearchCVEForImageGQL(searchConfig, "repo-test", "dummyCVEID")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchImagesByCVEIDGQL(t *testing.T) {
	Convey("SearchImagesByCVEIDGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getTagsForCVEGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				imageName, cveID string) (*common.ImagesForCve, error,
			) {
				return &common.ImagesForCve{
					ImagesForCVEList: common.ImagesForCVEList{
						PaginatedImagesResult: common.PaginatedImagesResult{
							Results: []common.ImageSummary{
								getMockImageSummary(),
							},
						},
					},
				}, nil
			},
		})

		err := SearchImagesByCVEIDGQL(searchConfig, "repo", "CVE-12345")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchImagesByCVEIDGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getTagsForCVEGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				imageName, cveID string) (*common.ImagesForCve, error,
			) {
				return &common.ImagesForCve{
					ImagesForCVEList: common.ImagesForCVEList{
						PaginatedImagesResult: common.PaginatedImagesResult{},
					},
				}, zerr.ErrInjected
			},
		})

		err := SearchImagesByCVEIDGQL(searchConfig, "repo", "CVE-12345")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchFixedTagsGQL(t *testing.T) {
	Convey("SearchFixedTagsGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getFixedTagsForCVEGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				imageName, cveID string) (*common.ImageListWithCVEFixedResponse, error,
			) {
				return &common.ImageListWithCVEFixedResponse{
					ImageListWithCVEFixed: common.ImageListWithCVEFixed{
						PaginatedImagesResult: common.PaginatedImagesResult{
							Results: []common.ImageSummary{getMockImageSummary()},
						},
					},
				}, nil
			},
		})

		err := SearchFixedTagsGQL(searchConfig, "repo", "CVE-12345")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo tag os/arch 8c25cb36 false 100B")
	})

	Convey("SearchFixedTagsGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getFixedTagsForCVEGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				imageName, cveID string) (*common.ImageListWithCVEFixedResponse, error,
			) {
				return &common.ImageListWithCVEFixedResponse{
					ImageListWithCVEFixed: common.ImageListWithCVEFixed{
						PaginatedImagesResult: common.PaginatedImagesResult{},
					},
				}, zerr.ErrInjected
			},
		})

		err := SearchFixedTagsGQL(searchConfig, "repo", "CVE-12345")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchReferrersGQL(t *testing.T) {
	Convey("SearchReferrersGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getReferrersGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				repo, digest string) (*common.ReferrersResp, error,
			) {
				return &common.ReferrersResp{
					ReferrersResult: common.ReferrersResult{
						Referrers: []common.Referrer{{
							MediaType:    ispec.MediaTypeImageManifest,
							Size:         100,
							ArtifactType: "art.type",
							Digest:       godigest.FromString("123").String(),
						}},
					},
				}, nil
			},
		})

		err := SearchReferrersGQL(searchConfig, "repo@"+godigest.FromString("str").String())
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring,
			"art.type 100 B sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
	})

	Convey("SearchReferrersGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getReferrersGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				repo, digest string) (*common.ReferrersResp, error,
			) {
				return &common.ReferrersResp{}, zerr.ErrInjected
			},
		})

		err := SearchReferrersGQL(searchConfig, "repo@"+godigest.FromString("str").String())
		So(err, ShouldNotBeNil)
	})
}

func TestGlobalSearchGQL(t *testing.T) {
	Convey("GlobalSearchGQL", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			globalSearchGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				query string) (*common.GlobalSearch, error,
			) {
				return &common.GlobalSearch{
					Repos: []common.RepoSummary{{
						Name:        "repo",
						Size:        "100",
						LastUpdated: time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC),
					}},
				}, nil
			},
		})

		err := GlobalSearchGQL(searchConfig, "repo")
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring,
			"repo ")
	})

	Convey("GlobalSearchGQL error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			globalSearchGQLFn: func(ctx context.Context, config SearchConfig, username, password,
				query string) (*common.GlobalSearch, error,
			) {
				return &common.GlobalSearch{}, zerr.ErrInjected
			},
		})

		err := GlobalSearchGQL(searchConfig, "repo")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchReferrers(t *testing.T) {
	Convey("SearchReferrers", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getReferrersFn: func(ctx context.Context, config SearchConfig, username string, password string,
				repo string, digest string) (referrersResult, error,
			) {
				return referrersResult([]common.Referrer{
					{
						MediaType:    ispec.MediaTypeImageManifest,
						Size:         100,
						ArtifactType: "art.type",
						Digest:       godigest.FromString("123").String(),
					},
				}), nil
			},
		})

		err := SearchReferrers(searchConfig, "repo@"+godigest.FromString("str").String())
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring,
			"art.type 100 B sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
	})

	Convey("SearchReferrers error", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{
			getReferrersFn: func(ctx context.Context, config SearchConfig, username string, password string,
				repo string, digest string) (referrersResult, error,
			) {
				return referrersResult{}, zerr.ErrInjected
			},
		})

		err := SearchReferrers(searchConfig, "repo@"+godigest.FromString("str").String())
		So(err, ShouldNotBeNil)
	})
}

func TestSearchRepos(t *testing.T) {
	Convey("SearchRepos", t, func() {
		buff := bytes.NewBufferString("")
		searchConfig := getMockSearchConfig(buff, mockService{})

		err := SearchRepos(searchConfig)
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "repo1")
		So(actual, ShouldContainSubstring, "repo2")
	})
}

func getMockSearchConfig(buff *bytes.Buffer, mockService mockService) SearchConfig {
	return SearchConfig{
		ResultWriter:  buff,
		User:          "",
		SearchService: mockService,
		ServURL:       "http://127.0.0.1:8000",
		OutputFormat:  "",
		VerifyTLS:     false,
		FixedFlag:     false,
		Verbose:       false,
		Debug:         false,
	}
}

func getMockImageStruct() imageStruct {
	return imageStruct(common.ImageSummary{
		RepoName: "repo", Tag: "tag",
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    godigest.FromString("str").String(),
		Size:      "100",
		Manifests: []common.ManifestSummary{{
			Size:         "100",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
			Digest:       godigest.FromString("str").String(),
			ConfigDigest: godigest.FromString("str").String(),
		}},
	})
}

func getMockImageSummary() common.ImageSummary {
	return common.ImageSummary{
		RepoName: "repo", Tag: "tag",
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    godigest.FromString("str").String(),
		Size:      "100",
		Manifests: []common.ManifestSummary{{
			Size:         "100",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
			Digest:       godigest.FromString("str").String(),
			ConfigDigest: godigest.FromString("str").String(),
		}},
	}
}

func TestUtils(t *testing.T) {
	Convey("Utils", t, func() {
		ok := haveSameArgs(field{"query", []struct {
			Name string `json:"name"`
		}{
			{Name: "arg1"}, {Name: "arg2"},
		}}, GQLQuery{
			Name: "query", Args: []string{"arg1"},
		})
		So(ok, ShouldBeFalse)

		ok = haveSameArgs(field{"query", []struct {
			Name string `json:"name"`
		}{
			{Name: "arg1"}, {Name: "arg2"},
		}}, GQLQuery{
			Name: "query", Args: []string{"arg1", "arg3"},
		})
		So(ok, ShouldBeFalse)

		err := containsGQLQueryWithParams(
			[]field{
				{Name: "query"},
			},
			[]typeInfo{},
			GQLQuery{Name: "other-name"},
		)
		So(err, ShouldNotBeNil)
	})

	Convey("GetConfigOptions", t, func() {
		// no flags
		cmd := &cobra.Command{}
		isSpinner, verifyTLS, err := GetCliConfigOptions(cmd)
		So(err, ShouldNotBeNil)
		So(isSpinner, ShouldBeFalse)
		So(verifyTLS, ShouldBeFalse)

		// bad showspinner
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":"bad", "verify-tls": false}]}`)
		cmd = &cobra.Command{}
		cmd.Flags().String(ConfigFlag, "imagetest", "")
		isSpinner, verifyTLS, err = GetCliConfigOptions(cmd)
		So(err, ShouldNotBeNil)
		So(isSpinner, ShouldBeFalse)
		So(verifyTLS, ShouldBeFalse)
		os.Remove(configPath)

		// bad verify-tls
		configPath = makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false, "verify-tls": "bad"}]}`)
		cmd = &cobra.Command{}
		cmd.Flags().String(ConfigFlag, "imagetest", "")
		isSpinner, verifyTLS, err = GetCliConfigOptions(cmd)
		So(err, ShouldNotBeNil)
		So(isSpinner, ShouldBeFalse)
		So(verifyTLS, ShouldBeFalse)
		os.Remove(configPath)
	})

	Convey("GetServerURLFromFlags", t, func() {
		cmd := &cobra.Command{}
		cmd.Flags().String(URLFlag, "url", "")
		url, err := GetServerURLFromFlags(cmd)
		So(url, ShouldResemble, "url")
		So(err, ShouldBeNil)

		// err no config or url
		cmd = &cobra.Command{}
		url, err = GetServerURLFromFlags(cmd)
		So(url, ShouldResemble, "")
		So(err, ShouldNotBeNil)

		// err ulr from config is empty
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest"}]}`)
		cmd = &cobra.Command{}
		cmd.Flags().String(ConfigFlag, "imagetest", "")
		url, err = GetServerURLFromFlags(cmd)
		So(url, ShouldResemble, "")
		So(err, ShouldNotBeNil)
		os.Remove(configPath)

		// err reading the server url from config
		configPath = makeConfigFile("{}")
		cmd = &cobra.Command{}
		cmd.Flags().String(ConfigFlag, "imagetest", "")
		url, err = GetServerURLFromFlags(cmd)
		So(url, ShouldResemble, "")
		So(err, ShouldNotBeNil)
		os.Remove(configPath)
	})

	Convey("CheckExtEndPointQuery", t, func() {
		// invalid url
		err := CheckExtEndPointQuery(SearchConfig{
			User:    "",
			ServURL: "bad-url",
		})
		So(err, ShouldNotBeNil)

		// good url but no connection
		err = CheckExtEndPointQuery(SearchConfig{
			User:         "",
			ServURL:      "http://127.0.0.1:5000",
			VerifyTLS:    false,
			Debug:        false,
			ResultWriter: io.Discard,
		})
		So(err, ShouldNotBeNil)
	})
}
