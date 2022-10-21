package cveinfo

import (
	"encoding/json"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/extensions/search/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

type CveInfo interface {
	GetImageListForCVE(repo, cveID string) ([]common.TagInfo, error)
	GetImageListWithCVEFixed(repo, cveID string) ([]common.TagInfo, error)
	GetCVEListForImage(repo, tag string, pageinput PageInput) ([]cvemodel.CVE, PageInfo, error)
	GetCVESummaryForImage(repo, tag string) (ImageCVESummary, error)
	CompareSeverities(severity1, severity2 string) int
	UpdateDB() error
}

type Scanner interface {
	ScanImage(image string) (map[string]cvemodel.CVE, error)
	IsImageFormatScannable(repo, tag string) (bool, error)
	CompareSeverities(severity1, severity2 string) int
	UpdateDB() error
}

type ImageCVESummary struct {
	Count       int
	MaxSeverity string
}

type BaseCveInfo struct {
	Log     log.Logger
	Scanner Scanner
	RepoDB  repodb.RepoDB
}

func NewCVEInfo(storeController storage.StoreController, repoDB repodb.RepoDB,
	dbRepository string, log log.Logger,
) *BaseCveInfo {
	scanner := trivy.NewScanner(storeController, repoDB, dbRepository, log)

	return &BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		RepoDB:  repoDB,
	}
}

func (cveinfo BaseCveInfo) GetImageListForCVE(repo, cveID string) ([]common.TagInfo, error) {
	imgList := make([]common.TagInfo, 0)

	repoMeta, err := cveinfo.RepoDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repo", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return imgList, err
	}

	for tag, descriptor := range repoMeta.Tags {
		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			manifestDigestStr := descriptor.Digest

			manifestDigest := godigest.Digest(manifestDigestStr)

			isValidImage, _ := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
			if !isValidImage {
				continue
			}

			cveMap, err := cveinfo.Scanner.ScanImage(getImageString(repo, tag))
			if err != nil {
				continue
			}

			if _, hasCVE := cveMap[cveID]; hasCVE {
				imgList = append(imgList, common.TagInfo{
					Name: tag,
					Descriptor: common.Descriptor{
						Digest:    manifestDigest,
						MediaType: descriptor.MediaType,
					},
				})
			}
		case ispec.MediaTypeImageIndex:
			indexDigestStr := descriptor.Digest

			indexDigest := godigest.Digest(indexDigestStr)

			isValidImage, _ := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
			if !isValidImage {
				continue
			}

			// At the moment of this implementation trivy can't scan individual images inside a multi-arch when using the
			// --input flag. When this will be possible, we should loop over all images, scan and then search their
			// vulnerabilities.
			cveMap, err := cveinfo.Scanner.ScanImage(getImageString(repo, tag))
			if err != nil {
				continue
			}

			if _, hasCVE := cveMap[cveID]; hasCVE {
				imgList = append(imgList, common.TagInfo{
					Name: tag,
					Descriptor: common.Descriptor{
						Digest:    indexDigest,
						MediaType: descriptor.MediaType,
					},
				})
			}
		default:
			cveinfo.Log.Error().Msg("type not supported")
		}
	}

	return imgList, nil
}

func (cveinfo BaseCveInfo) GetImageListWithCVEFixed(repo, cveID string) ([]common.TagInfo, error) {
	repoMeta, err := cveinfo.RepoDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repo", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return []common.TagInfo{}, err
	}

	vulnerableTags := make([]common.TagInfo, 0)
	allTags := make([]common.TagInfo, 0)

	var hasCVE bool

	for tag, descriptor := range repoMeta.Tags {
		manifestDigestStr := descriptor.Digest

		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			manifestDigest, err := godigest.Parse(manifestDigestStr)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
					Str("cve-id", cveID).Str("digest", manifestDigestStr).Msg("unable to parse digest")

				continue
			}

			manifestMeta, err := cveinfo.RepoDB.GetManifestMeta(repo, manifestDigest)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
					Str("cve-id", cveID).Msg("unable to obtain manifest meta")

				continue
			}

			var configContent ispec.Image

			err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
					Str("cve-id", cveID).Msg("unable to unmashal manifest blob")

				continue
			}

			tagInfo := common.TagInfo{
				Name:       tag,
				Timestamp:  common.GetImageLastUpdated(configContent),
				Descriptor: common.Descriptor{Digest: manifestDigest, MediaType: descriptor.MediaType},
			}

			allTags = append(allTags, tagInfo)

			image := fmt.Sprintf("%s:%s", repo, tag)

			isValidImage, _ := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
			if !isValidImage {
				cveinfo.Log.Debug().Str("image", image).Str("cve-id", cveID).
					Msg("image media type not supported for scanning, adding as a vulnerable image")

				vulnerableTags = append(vulnerableTags, tagInfo)

				continue
			}

			cveMap, err := cveinfo.Scanner.ScanImage(getImageString(repo, tag))
			if err != nil {
				cveinfo.Log.Debug().Str("image", image).Str("cve-id", cveID).
					Msg("scanning failed, adding as a vulnerable image")

				vulnerableTags = append(vulnerableTags, tagInfo)

				continue
			}

			hasCVE = false

			for id := range cveMap {
				if id == cveID {
					hasCVE = true

					break
				}
			}

			if hasCVE {
				vulnerableTags = append(vulnerableTags, tagInfo)
			}
		case ispec.MediaTypeImageIndex:
			panic("not implemented")
		default:
			cveinfo.Log.Info().Msg("media type not supported %s")
		}
	}

	var fixedTags []common.TagInfo

	if len(vulnerableTags) != 0 {
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).Msgf("Vulnerable tags: %v", vulnerableTags)
		fixedTags = common.GetFixedTags(allTags, vulnerableTags)
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).Msgf("Fixed tags: %v", fixedTags)
	} else {
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).
			Msg("image does not contain any tag that have given cve")
		fixedTags = allTags
	}

	return fixedTags, nil
}

func (cveinfo BaseCveInfo) GetCVEListForImage(repo, tag string, pageInput PageInput) (
	[]cvemodel.CVE,
	PageInfo,
	error,
) {
	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
	if !isValidImage {
		return []cvemodel.CVE{}, PageInfo{}, err
	}

	image := getImageString(repo, tag)

	cveMap, err := cveinfo.Scanner.ScanImage(image)
	if err != nil {
		return []cvemodel.CVE{}, PageInfo{}, err
	}

	pageFinder, err := NewCvePageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy, cveinfo)
	if err != nil {
		return []cvemodel.CVE{}, PageInfo{}, err
	}

	for _, cve := range cveMap {
		pageFinder.Add(cve)
	}

	cveList, pageInfo := pageFinder.Page()

	return cveList, pageInfo, nil
}

func (cveinfo BaseCveInfo) GetCVESummaryForImage(repo, tag string,
) (ImageCVESummary, error) {
	// There are several cases, expected returned values below:
	// not scannable / error during scan   - max severity ""            - cve count 0   - Errors
	// scannable no issues found           - max severity "NONE"        - cve count 0   - no Errors
	// scannable issues found              - max severity from Scanner  - cve count >0  - no Errors
	imageCVESummary := ImageCVESummary{
		Count:       0,
		MaxSeverity: "",
	}

	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
	if !isValidImage {
		return imageCVESummary, err
	}

	image := getImageString(repo, tag)

	cveMap, err := cveinfo.Scanner.ScanImage(image)
	if err != nil {
		return imageCVESummary, err
	}

	imageCVESummary.Count = len(cveMap)

	if imageCVESummary.Count == 0 {
		imageCVESummary.MaxSeverity = "NONE"

		return imageCVESummary, nil
	}

	imageCVESummary.MaxSeverity = "UNKNOWN"
	for _, cve := range cveMap {
		if cveinfo.Scanner.CompareSeverities(imageCVESummary.MaxSeverity, cve.Severity) > 0 {
			imageCVESummary.MaxSeverity = cve.Severity
		}
	}

	return imageCVESummary, nil
}

func getImageString(repo, reference string) string {
	image := repo + ":" + reference

	if common.ReferenceIsDigest(reference) {
		image = repo + "@" + reference
	}

	return image
}

func (cveinfo BaseCveInfo) UpdateDB() error {
	return cveinfo.Scanner.UpdateDB()
}

func (cveinfo BaseCveInfo) CompareSeverities(severity1, severity2 string) int {
	return cveinfo.Scanner.CompareSeverities(severity1, severity2)
}
