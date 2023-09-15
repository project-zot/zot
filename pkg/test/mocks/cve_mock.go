package mocks

import (
	"zotregistry.io/zot/pkg/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
)

type CveInfoMock struct {
	GetImageListForCVEFn       func(repo, cveID string) ([]cvemodel.TagInfo, error)
	GetImageListWithCVEFixedFn func(repo, cveID string) ([]cvemodel.TagInfo, error)
	GetCVEListForImageFn       func(repo string, reference string, searchedCVE string, pageInput cvemodel.PageInput,
	) ([]cvemodel.CVE, common.PageInfo, error)
	GetCVESummaryForImageMediaFn func(repo string, digest, mediaType string,
	) (cvemodel.ImageCVESummary, error)
}

func (cveInfo CveInfoMock) GetImageListForCVE(repo, cveID string) ([]cvemodel.TagInfo, error) {
	if cveInfo.GetImageListForCVEFn != nil {
		return cveInfo.GetImageListForCVEFn(repo, cveID)
	}

	return []cvemodel.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetImageListWithCVEFixed(repo, cveID string) ([]cvemodel.TagInfo, error) {
	if cveInfo.GetImageListWithCVEFixedFn != nil {
		return cveInfo.GetImageListWithCVEFixedFn(repo, cveID)
	}

	return []cvemodel.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVEListForImage(repo string, reference string,
	searchedCVE string, pageInput cvemodel.PageInput,
) (
	[]cvemodel.CVE,
	common.PageInfo,
	error,
) {
	if cveInfo.GetCVEListForImageFn != nil {
		return cveInfo.GetCVEListForImageFn(repo, reference, searchedCVE, pageInput)
	}

	return []cvemodel.CVE{}, common.PageInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVESummaryForImageMedia(repo, digest, mediaType string,
) (cvemodel.ImageCVESummary, error) {
	if cveInfo.GetCVESummaryForImageMediaFn != nil {
		return cveInfo.GetCVESummaryForImageMediaFn(repo, digest, mediaType)
	}

	return cvemodel.ImageCVESummary{}, nil
}

type CveScannerMock struct {
	IsImageFormatScannableFn func(repo string, reference string) (bool, error)
	IsImageMediaScannableFn  func(repo string, digest, mediaType string) (bool, error)
	IsResultCachedFn         func(digest string) bool
	GetCachedResultFn        func(digest string) map[string]cvemodel.CVE
	ScanImageFn              func(image string) (map[string]cvemodel.CVE, error)
	UpdateDBFn               func() error
}

func (scanner CveScannerMock) IsImageFormatScannable(repo string, reference string) (bool, error) {
	if scanner.IsImageFormatScannableFn != nil {
		return scanner.IsImageFormatScannableFn(repo, reference)
	}

	return true, nil
}

func (scanner CveScannerMock) IsImageMediaScannable(repo string, digest, mediaType string) (bool, error) {
	if scanner.IsImageMediaScannableFn != nil {
		return scanner.IsImageMediaScannableFn(repo, digest, mediaType)
	}

	return true, nil
}

func (scanner CveScannerMock) IsResultCached(digest string) bool {
	if scanner.IsResultCachedFn != nil {
		return scanner.IsResultCachedFn(digest)
	}

	return false
}

func (scanner CveScannerMock) GetCachedResult(digest string) map[string]cvemodel.CVE {
	if scanner.GetCachedResultFn != nil {
		return scanner.GetCachedResultFn(digest)
	}

	return map[string]cvemodel.CVE{}
}

func (scanner CveScannerMock) ScanImage(image string) (map[string]cvemodel.CVE, error) {
	if scanner.ScanImageFn != nil {
		return scanner.ScanImageFn(image)
	}

	return map[string]cvemodel.CVE{}, nil
}

func (scanner CveScannerMock) UpdateDB() error {
	if scanner.UpdateDBFn != nil {
		return scanner.UpdateDBFn()
	}

	return nil
}
