package mocks

import (
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/pkg/extensions/search/common"
)

type OciLayoutUtilsMock struct {
	GetImageManifestsFn         func(image string) ([]ispec.Descriptor, error)
	GetImageBlobManifestFn      func(imageDir string, digest godigest.Digest) (v1.Manifest, error)
	GetImageInfoFn              func(imageDir string, hash v1.Hash) (ispec.Image, error)
	IsValidImageFormatFn        func(image string) (bool, error)
	GetImageTagsWithTimestampFn func(repo string) ([]common.TagInfo, error)
	GetImageLastUpdatedFn       func(imageInfo ispec.Image) time.Time
	GetImagePlatformFn          func(imageInfo ispec.Image) (string, string)
	GetImageVendorFn            func(imageInfo ispec.Image) string
	GetImageManifestSizeFn      func(repo string, manifestDigest godigest.Digest) int64
	GetImageConfigSizeFn        func(repo string, manifestDigest godigest.Digest) int64
	GetRepoLastUpdatedFn        func(repo string) (common.TagInfo, error)
	GetExpandedRepoInfoFn       func(name string) (common.RepoInfo, error)
	GetImageConfigInfoFn        func(repo string, manifestDigest godigest.Digest) (ispec.Image, error)
	CheckManifestSignatureFn    func(name string, digest godigest.Digest) bool
}

func (olum OciLayoutUtilsMock) GetImageManifests(image string) ([]ispec.Descriptor, error) {
	if olum.GetImageManifestsFn != nil {
		return olum.GetImageManifestsFn(image)
	}

	return []ispec.Descriptor{}, nil
}

func (olum OciLayoutUtilsMock) GetImageBlobManifest(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
	if olum.GetImageBlobManifestFn != nil {
		return olum.GetImageBlobManifestFn(imageDir, digest)
	}

	return v1.Manifest{}, nil
}

func (olum OciLayoutUtilsMock) GetImageInfo(imageDir string, hash v1.Hash) (ispec.Image, error) {
	if olum.GetImageInfoFn != nil {
		return olum.GetImageInfoFn(imageDir, hash)
	}

	return ispec.Image{}, nil
}

func (olum OciLayoutUtilsMock) IsValidImageFormat(image string) (bool, error) {
	if olum.IsValidImageFormatFn != nil {
		return olum.IsValidImageFormatFn(image)
	}

	return true, nil
}

func (olum OciLayoutUtilsMock) GetImageTagsWithTimestamp(repo string) ([]common.TagInfo, error) {
	if olum.GetImageTagsWithTimestampFn != nil {
		return olum.GetImageTagsWithTimestampFn(repo)
	}

	return []common.TagInfo{}, nil
}

func (olum OciLayoutUtilsMock) GetImageLastUpdated(imageInfo ispec.Image) time.Time {
	if olum.GetImageLastUpdatedFn != nil {
		return olum.GetImageLastUpdatedFn(imageInfo)
	}

	return time.Time{}
}

func (olum OciLayoutUtilsMock) GetImagePlatform(imageInfo ispec.Image) (string, string) {
	if olum.GetImagePlatformFn != nil {
		return olum.GetImagePlatformFn(imageInfo)
	}

	return "", ""
}

func (olum OciLayoutUtilsMock) GetImageVendor(imageInfo ispec.Image) string {
	if olum.GetImageVendorFn != nil {
		return olum.GetImageVendorFn(imageInfo)
	}

	return ""
}

func (olum OciLayoutUtilsMock) GetImageManifestSize(repo string, manifestDigest godigest.Digest) int64 {
	if olum.GetImageManifestSizeFn != nil {
		return olum.GetImageManifestSizeFn(repo, manifestDigest)
	}

	return 0
}

func (olum OciLayoutUtilsMock) GetImageConfigSize(repo string, manifestDigest godigest.Digest) int64 {
	if olum.GetImageConfigSizeFn != nil {
		return olum.GetImageConfigSizeFn(repo, manifestDigest)
	}

	return 0
}

func (olum OciLayoutUtilsMock) GetRepoLastUpdated(repo string) (common.TagInfo, error) {
	if olum.GetRepoLastUpdatedFn != nil {
		return olum.GetRepoLastUpdatedFn(repo)
	}

	return common.TagInfo{}, nil
}

func (olum OciLayoutUtilsMock) GetExpandedRepoInfo(name string) (common.RepoInfo, error) {
	if olum.GetExpandedRepoInfoFn != nil {
		return olum.GetExpandedRepoInfoFn(name)
	}

	return common.RepoInfo{}, nil
}

func (olum OciLayoutUtilsMock) GetImageConfigInfo(repo string, manifestDigest godigest.Digest) (ispec.Image, error) {
	if olum.GetImageConfigInfoFn != nil {
		return olum.GetImageConfigInfoFn(repo, manifestDigest)
	}

	return ispec.Image{}, nil
}

func (olum OciLayoutUtilsMock) CheckManifestSignature(name string, digest godigest.Digest) bool {
	if olum.CheckManifestSignatureFn != nil {
		return olum.CheckManifestSignatureFn(name, digest)
	}

	return false
}
