package cveinfo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

type CveInfo interface {
	GetImageListForCVE(repo, cveID string) ([]cvemodel.TagInfo, error)
	GetImageListWithCVEFixed(repo, cveID string) ([]cvemodel.TagInfo, error)
	GetCVEListForImage(repo, tag string, searchedCVE string, pageinput PageInput) ([]cvemodel.CVE, common.PageInfo, error)
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
	RepoDB  metaTypes.RepoDB
}

func NewCVEInfo(storeController storage.StoreController, repoDB metaTypes.RepoDB,
	dbRepository, javaDBRepository string, log log.Logger,
) *BaseCveInfo {
	scanner := trivy.NewScanner(storeController, repoDB, dbRepository, javaDBRepository, log)

	return &BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		RepoDB:  repoDB,
	}
}

func (cveinfo BaseCveInfo) GetImageListForCVE(repo, cveID string) ([]cvemodel.TagInfo, error) {
	imgList := make([]cvemodel.TagInfo, 0)

	repoMeta, err := cveinfo.RepoDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repository", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return imgList, err
	}

	for tag, descriptor := range repoMeta.Tags {
		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			manifestDigestStr := descriptor.Digest

			manifestDigest := godigest.Digest(manifestDigestStr)

			isScanableImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
			if !isScanableImage || err != nil {
				cveinfo.Log.Info().Str("image", repo+":"+tag).Err(err).Msg("image is not scanable")

				continue
			}

			cveMap, err := cveinfo.Scanner.ScanImage(getImageString(repo, tag))
			if err != nil {
				cveinfo.Log.Info().Str("image", repo+":"+tag).Err(err).Msg("image scan failed")

				continue
			}

			if _, hasCVE := cveMap[cveID]; hasCVE {
				imgList = append(imgList, cvemodel.TagInfo{
					Name: tag,
					Descriptor: cvemodel.Descriptor{
						Digest:    manifestDigest,
						MediaType: descriptor.MediaType,
					},
				})
			}
		default:
			cveinfo.Log.Error().Str("mediaType", descriptor.MediaType).Msg("media type not supported for scanning")
		}
	}

	return imgList, nil
}

func (cveinfo BaseCveInfo) GetImageListWithCVEFixed(repo, cveID string) ([]cvemodel.TagInfo, error) {
	repoMeta, err := cveinfo.RepoDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repository", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return []cvemodel.TagInfo{}, err
	}

	vulnerableTags := make([]cvemodel.TagInfo, 0)
	allTags := make([]cvemodel.TagInfo, 0)

	var hasCVE bool

	for tag, descriptor := range repoMeta.Tags {
		manifestDigestStr := descriptor.Digest

		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			manifestDigest, err := godigest.Parse(manifestDigestStr)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repository", repo).Str("tag", tag).
					Str("cve-id", cveID).Str("digest", manifestDigestStr).Msg("unable to parse digest")

				continue
			}

			manifestMeta, err := cveinfo.RepoDB.GetManifestMeta(repo, manifestDigest)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repository", repo).Str("tag", tag).
					Str("cve-id", cveID).Msg("unable to obtain manifest meta")

				continue
			}

			var configContent ispec.Image

			err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repository", repo).Str("tag", tag).
					Str("cve-id", cveID).Msg("unable to unmashal manifest blob")

				continue
			}

			tagInfo := cvemodel.TagInfo{
				Name:       tag,
				Timestamp:  common.GetImageLastUpdated(configContent),
				Descriptor: cvemodel.Descriptor{Digest: manifestDigest, MediaType: descriptor.MediaType},
			}

			allTags = append(allTags, tagInfo)

			image := fmt.Sprintf("%s:%s", repo, tag)

			isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
			if !isValidImage || err != nil {
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
		default:
			cveinfo.Log.Error().Str("mediaType", descriptor.MediaType).Msg("media type not supported")

			return []cvemodel.TagInfo{},
				fmt.Errorf("media type '%s' is not supported: %w", descriptor.MediaType, errors.ErrNotImplemented)
		}
	}

	var fixedTags []cvemodel.TagInfo

	if len(vulnerableTags) != 0 {
		cveinfo.Log.Info().Str("repository", repo).Str("cve-id", cveID).
			Interface("vulnerableTags", vulnerableTags).Msg("Vulnerable tags")
		fixedTags = GetFixedTags(allTags, vulnerableTags)
		cveinfo.Log.Info().Str("repository", repo).Str("cve-id", cveID).
			Interface("fixedTags", fixedTags).Msg("Fixed tags")
	} else {
		cveinfo.Log.Info().Str("repository", repo).Str("cve-id", cveID).
			Msg("image does not contain any tag that have given cve")
		fixedTags = allTags
	}

	return fixedTags, nil
}

func filterCVEList(cveMap map[string]cvemodel.CVE, searchedCVE string, pageFinder *CvePageFinder) {
	searchedCVE = strings.ToUpper(searchedCVE)

	for _, cve := range cveMap {
		if strings.Contains(strings.ToUpper(cve.Title), searchedCVE) ||
			strings.Contains(strings.ToUpper(cve.ID), searchedCVE) {
			pageFinder.Add(cve)
		}
	}
}

func (cveinfo BaseCveInfo) GetCVEListForImage(repo, tag string, searchedCVE string, pageInput PageInput) (
	[]cvemodel.CVE,
	common.PageInfo,
	error,
) {
	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, tag)
	if !isValidImage {
		return []cvemodel.CVE{}, common.PageInfo{}, err
	}

	image := getImageString(repo, tag)

	cveMap, err := cveinfo.Scanner.ScanImage(image)
	if err != nil {
		return []cvemodel.CVE{}, common.PageInfo{}, err
	}

	pageFinder, err := NewCvePageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy, cveinfo)
	if err != nil {
		return []cvemodel.CVE{}, common.PageInfo{}, err
	}

	filterCVEList(cveMap, searchedCVE, pageFinder)

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

func referenceIsDigest(reference string) bool {
	_, err := godigest.Parse(reference)

	return err == nil
}

func getImageString(repo, reference string) string {
	image := repo + ":" + reference

	if referenceIsDigest(reference) {
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

func GetFixedTags(allTags, vulnerableTags []cvemodel.TagInfo) []cvemodel.TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	earliestVulnerable := vulnerableTags[0]
	vulnerableTagMap := make(map[string]cvemodel.TagInfo, len(vulnerableTags))

	for _, tag := range vulnerableTags {
		vulnerableTagMap[tag.Name] = tag

		if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
			earliestVulnerable = tag
		}
	}

	var fixedTags []cvemodel.TagInfo

	// There are some downsides to this logic
	// We assume there can't be multiple "branches" of the same
	// image built at different times containing different fixes
	// There may be older images which have a fix or
	// newer images which don't
	for _, tag := range allTags {
		if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
			// The vulnerability did not exist at the time this
			// image was built
			continue
		}
		// If the image is old enough for the vulnerability to
		// exist, but it was not detected, it means it contains
		// the fix
		if _, ok := vulnerableTagMap[tag.Name]; !ok {
			fixedTags = append(fixedTags, tag)
		}
	}

	return fixedTags
}
