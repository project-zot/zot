package mocks

import (
	"context"
	"sync"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
)

type CveInfoMock struct {
	GetImageListForCVEFn func(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error)

	GetImageListWithCVEFixedFn func(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error)

	GetCVEListForImageFn func(ctx context.Context, repo, reference, searchedCVE, excludedCVE, severity string,
		pageInput zcommon.PageInput) ([]zcommon.CVE, cvemodel.ImageCVESummary, zcommon.PageInfo, error)

	GetCVESummaryForImageMediaFn func(ctx context.Context, repo string, digest, mediaType string,
	) (cvemodel.ImageCVESummary, error)

	GetCVEDiffListForImagesFn func(ctx context.Context, minuend, subtrahend, searchedCVE string,
		excludedCVE string, pageInput zcommon.PageInput,
	) ([]zcommon.CVE, cvemodel.ImageCVESummary, zcommon.PageInfo, error)
}

func (cveInfo CveInfoMock) GetCVEDiffListForImages(ctx context.Context, minuend, subtrahend, searchedCVE string,
	excludedCVE string, pageInput zcommon.PageInput,
) ([]zcommon.CVE, cvemodel.ImageCVESummary, zcommon.PageInfo, error) {
	if cveInfo.GetCVEDiffListForImagesFn != nil {
		return cveInfo.GetCVEDiffListForImagesFn(ctx, minuend, subtrahend, searchedCVE, excludedCVE, pageInput)
	}

	return []zcommon.CVE{}, cvemodel.ImageCVESummary{}, zcommon.PageInfo{}, nil
}

func (cveInfo CveInfoMock) GetImageListForCVE(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error) {
	if cveInfo.GetImageListForCVEFn != nil {
		return cveInfo.GetImageListForCVEFn(ctx, repo, cveID)
	}

	return []cvemodel.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetImageListWithCVEFixed(ctx context.Context, repo, cveID string,
) ([]cvemodel.TagInfo, error) {
	if cveInfo.GetImageListWithCVEFixedFn != nil {
		return cveInfo.GetImageListWithCVEFixedFn(ctx, repo, cveID)
	}

	return []cvemodel.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVEListForImage(ctx context.Context, repo string, reference string,
	searchedCVE string, excludedCVE string, severity string, pageInput zcommon.PageInput,
) (
	[]zcommon.CVE,
	cvemodel.ImageCVESummary,
	zcommon.PageInfo,
	error,
) {
	if cveInfo.GetCVEListForImageFn != nil {
		return cveInfo.GetCVEListForImageFn(ctx, repo, reference, searchedCVE, excludedCVE, severity, pageInput)
	}

	return []zcommon.CVE{}, cvemodel.ImageCVESummary{}, zcommon.PageInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVESummaryForImageMedia(ctx context.Context, repo, digest, mediaType string,
) (cvemodel.ImageCVESummary, error) {
	if cveInfo.GetCVESummaryForImageMediaFn != nil {
		return cveInfo.GetCVESummaryForImageMediaFn(ctx, repo, digest, mediaType)
	}

	return cvemodel.ImageCVESummary{}, nil
}

type CveScannerMock struct {
	IsImageFormatScannableFn func(repo string, reference string) (bool, error)
	IsImageMediaScannableFn  func(repo string, digest, mediaType string) (bool, error)
	IsResultCachedFn         func(digest string) bool
	GetCachedResultFn        func(digest string) map[string]zcommon.CVE
	ScanImageFn              func(ctx context.Context, image string) (cvemodel.ScanResult, error)
	UpdateDBFn               func(ctx context.Context) error
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

func (scanner CveScannerMock) GetCachedResult(digest string) map[string]zcommon.CVE {
	if scanner.GetCachedResultFn != nil {
		return scanner.GetCachedResultFn(digest)
	}

	return map[string]zcommon.CVE{}
}

func (scanner CveScannerMock) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	if scanner.ScanImageFn != nil {
		return scanner.ScanImageFn(ctx, image)
	}

	return cvemodel.ScanResult{CVEMap: map[string]zcommon.CVE{}}, nil
}

func (scanner CveScannerMock) UpdateDB(ctx context.Context) error {
	if scanner.UpdateDBFn != nil {
		return scanner.UpdateDBFn(ctx)
	}

	return nil
}

type TestCveScanner struct {
	sync.RWMutex

	cveDataStore map[string]map[string]zcommon.CVE
}

func NewTestCveScanner() *TestCveScanner {
	return &TestCveScanner{
		cveDataStore: make(map[string]map[string]zcommon.CVE),
	}
}

func (scanner *TestCveScanner) SetCveDataForImage(digestOrTag string, cveData map[string]zcommon.CVE) {
	scanner.Lock()
	defer scanner.Unlock()
	scanner.cveDataStore[digestOrTag] = cveData
}

func (scanner *TestCveScanner) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	scanner.RLock()
	defer scanner.RUnlock()
	if cveData, exists := scanner.cveDataStore[image]; exists {
		return cvemodel.ScanResult{CVEMap: cveData}, nil
	}

	return cvemodel.ScanResult{CVEMap: map[string]zcommon.CVE{}}, nil
}

func (scanner *TestCveScanner) IsImageFormatScannable(repo string, reference string) (bool, error) {
	return true, nil
}

func (scanner *TestCveScanner) IsImageMediaScannable(repo string, digest, mediaType string) (bool, error) {
	return true, nil
}

func (scanner *TestCveScanner) IsResultCached(digest string) bool {
	scanner.RLock()
	defer scanner.RUnlock()
	_, exists := scanner.cveDataStore[digest]

	return exists
}

func (scanner *TestCveScanner) GetCachedResult(digest string) map[string]zcommon.CVE {
	scanner.RLock()
	defer scanner.RUnlock()
	if cveData, exists := scanner.cveDataStore[digest]; exists {
		return cveData
	}

	return map[string]zcommon.CVE{}
}

func (scanner *TestCveScanner) UpdateDB(ctx context.Context) error {
	return nil
}
