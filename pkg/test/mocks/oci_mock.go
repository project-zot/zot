package mocks

import (
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/pkg/common"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
)

type OciLayoutUtilsMock struct {
	GetImageManifestFn          func(repo string, reference string) (ispec.Manifest, godigest.Digest, error)
	GetImageManifestsFn         func(repo string) ([]ispec.Descriptor, error)
	GetImageBlobManifestFn      func(repo string, digest godigest.Digest) (ispec.Manifest, error)
	GetImageInfoFn              func(repo string, digest godigest.Digest) (ispec.Image, error)
	GetImageTagsWithTimestampFn func(repo string) ([]cvemodel.TagInfo, error)
	GetImagePlatformFn          func(imageInfo ispec.Image) (string, string)
	GetImageManifestSizeFn      func(repo string, manifestDigest godigest.Digest) int64
	GetImageConfigSizeFn        func(repo string, manifestDigest godigest.Digest) int64
	GetRepoLastUpdatedFn        func(repo string) (cvemodel.TagInfo, error)
	GetExpandedRepoInfoFn       func(name string) (common.RepoInfo, error)
	GetImageConfigInfoFn        func(repo string, manifestDigest godigest.Digest) (ispec.Image, error)
	CheckManifestSignatureFn    func(name string, digest godigest.Digest) bool
	GetRepositoriesFn           func() ([]string, error)
}

func (olum OciLayoutUtilsMock) GetImageManifest(repo string, reference string,
) (ispec.Manifest, godigest.Digest, error) {
	if olum.GetImageManifestFn != nil {
		return olum.GetImageManifestFn(repo, reference)
	}

	return ispec.Manifest{}, "", nil
}

func (olum OciLayoutUtilsMock) GetRepositories() ([]string, error) {
	if olum.GetRepositoriesFn != nil {
		return olum.GetRepositoriesFn()
	}

	return []string{}, nil
}

func (olum OciLayoutUtilsMock) GetImageManifests(repo string) ([]ispec.Descriptor, error) {
	if olum.GetImageManifestsFn != nil {
		return olum.GetImageManifestsFn(repo)
	}

	return []ispec.Descriptor{}, nil
}

func (olum OciLayoutUtilsMock) GetImageBlobManifest(repo string, digest godigest.Digest) (ispec.Manifest, error) {
	if olum.GetImageBlobManifestFn != nil {
		return olum.GetImageBlobManifestFn(repo, digest)
	}

	return ispec.Manifest{}, nil
}

func (olum OciLayoutUtilsMock) GetImageInfo(repo string, digest godigest.Digest) (ispec.Image, error) {
	if olum.GetImageInfoFn != nil {
		return olum.GetImageInfoFn(repo, digest)
	}

	return ispec.Image{}, nil
}

func (olum OciLayoutUtilsMock) GetImageTagsWithTimestamp(repo string) ([]cvemodel.TagInfo, error) {
	if olum.GetImageTagsWithTimestampFn != nil {
		return olum.GetImageTagsWithTimestampFn(repo)
	}

	return []cvemodel.TagInfo{}, nil
}

func (olum OciLayoutUtilsMock) GetImagePlatform(imageInfo ispec.Image) (string, string) {
	if olum.GetImagePlatformFn != nil {
		return olum.GetImagePlatformFn(imageInfo)
	}

	return "", ""
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

func (olum OciLayoutUtilsMock) GetRepoLastUpdated(repo string) (cvemodel.TagInfo, error) {
	if olum.GetRepoLastUpdatedFn != nil {
		return olum.GetRepoLastUpdatedFn(repo)
	}

	return cvemodel.TagInfo{}, nil
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
