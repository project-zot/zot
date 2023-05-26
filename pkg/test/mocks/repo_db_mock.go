package mocks

import (
	"context"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/common"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
)

type MetaDBMock struct {
	SetRepoDescriptionFn func(repo, description string) error

	IncrementRepoStarsFn func(repo string) error

	DecrementRepoStarsFn func(repo string) error

	GetRepoStarsFn func(repo string) (int, error)

	SetRepoLogoFn func(repo string, logoPath string) error

	SetRepoReferenceFn func(repo string, Reference string, manifestDigest godigest.Digest, mediaType string) error

	DeleteRepoTagFn func(repo string, tag string) error

	GetRepoMetaFn func(repo string) (metaTypes.RepoMetadata, error)

	GetUserRepoMetaFn func(ctx context.Context, repo string) (metaTypes.RepoMetadata, error)

	SetRepoMetaFn func(repo string, repoMeta metaTypes.RepoMetadata) error

	GetMultipleRepoMetaFn func(ctx context.Context, filter func(repoMeta metaTypes.RepoMetadata) bool,
		requestedPage metaTypes.PageInput) ([]metaTypes.RepoMetadata, error)

	GetManifestDataFn func(manifestDigest godigest.Digest) (metaTypes.ManifestData, error)

	SetManifestDataFn func(manifestDigest godigest.Digest, mm metaTypes.ManifestData) error

	GetManifestMetaFn func(repo string, manifestDigest godigest.Digest) (metaTypes.ManifestMetadata, error)

	SetManifestMetaFn func(repo string, manifestDigest godigest.Digest, mm metaTypes.ManifestMetadata) error

	SetIndexDataFn func(digest godigest.Digest, indexData metaTypes.IndexData) error

	GetIndexDataFn func(indexDigest godigest.Digest) (metaTypes.IndexData, error)

	SetReferrerFn func(repo string, referredDigest godigest.Digest, referrer metaTypes.ReferrerInfo) error

	DeleteReferrerFn func(repo string, referredDigest godigest.Digest, referrerDigest godigest.Digest) error

	GetReferrersFn func(repo string, referredDigest godigest.Digest) ([]metaTypes.Descriptor, error)

	GetReferrersInfoFn func(repo string, referredDigest godigest.Digest, artifactTypes []string) (
		[]metaTypes.ReferrerInfo, error)

	IncrementImageDownloadsFn func(repo string, reference string) error

	UpdateSignaturesValidityFn func(repo string, manifestDigest godigest.Digest) error

	AddManifestSignatureFn func(repo string, signedManifestDigest godigest.Digest, sm metaTypes.SignatureMetadata) error

	DeleteSignatureFn func(repo string, signedManifestDigest godigest.Digest, sm metaTypes.SignatureMetadata) error

	SearchReposFn func(ctx context.Context, searchText string, filter metaTypes.Filter,
		requestedPage metaTypes.PageInput,
	) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
		error,
	)

	SearchTagsFn func(ctx context.Context, searchText string, filter metaTypes.Filter, requestedPage metaTypes.PageInput) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
		error,
	)

	FilterReposFn func(ctx context.Context, filter metaTypes.FilterRepoFunc, requestedPage metaTypes.PageInput) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
		error,
	)

	FilterTagsFn func(ctx context.Context, filter metaTypes.FilterFunc,
		requestedPage metaTypes.PageInput,
	) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData,
		common.PageInfo, error,
	)

	SearchDigestsFn func(ctx context.Context, searchText string, requestedPage metaTypes.PageInput) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error)

	SearchLayersFn func(ctx context.Context, searchText string, requestedPage metaTypes.PageInput) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error)

	SearchForAscendantImagesFn func(ctx context.Context, searchText string, requestedPage metaTypes.PageInput) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error)

	SearchForDescendantImagesFn func(ctx context.Context, searchText string, requestedPage metaTypes.PageInput) (
		[]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error)

	GetStarredReposFn func(ctx context.Context) ([]string, error)

	GetBookmarkedReposFn func(ctx context.Context) ([]string, error)

	ToggleStarRepoFn func(ctx context.Context, repo string) (metaTypes.ToggleState, error)

	ToggleBookmarkRepoFn func(ctx context.Context, repo string) (metaTypes.ToggleState, error)

	PatchDBFn func() error
}

func (sdm MetaDBMock) SetRepoDescription(repo, description string) error {
	if sdm.SetRepoDescriptionFn != nil {
		return sdm.SetRepoDescriptionFn(repo, description)
	}

	return nil
}

func (sdm MetaDBMock) IncrementRepoStars(repo string) error {
	if sdm.IncrementRepoStarsFn != nil {
		return sdm.IncrementRepoStarsFn(repo)
	}

	return nil
}

func (sdm MetaDBMock) DecrementRepoStars(repo string) error {
	if sdm.DecrementRepoStarsFn != nil {
		return sdm.DecrementRepoStarsFn(repo)
	}

	return nil
}

func (sdm MetaDBMock) GetRepoStars(repo string) (int, error) {
	if sdm.GetRepoStarsFn != nil {
		return sdm.GetRepoStarsFn(repo)
	}

	return 0, nil
}

func (sdm MetaDBMock) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if sdm.SetRepoReferenceFn != nil {
		return sdm.SetRepoReferenceFn(repo, reference, manifestDigest, mediaType)
	}

	return nil
}

func (sdm MetaDBMock) DeleteRepoTag(repo string, tag string) error {
	if sdm.DeleteRepoTagFn != nil {
		return sdm.DeleteRepoTagFn(repo, tag)
	}

	return nil
}

func (sdm MetaDBMock) GetRepoMeta(repo string) (metaTypes.RepoMetadata, error) {
	if sdm.GetRepoMetaFn != nil {
		return sdm.GetRepoMetaFn(repo)
	}

	return metaTypes.RepoMetadata{}, nil
}

func (sdm MetaDBMock) GetUserRepoMeta(ctx context.Context, repo string) (metaTypes.RepoMetadata, error) {
	if sdm.GetUserRepoMetaFn != nil {
		return sdm.GetUserRepoMetaFn(ctx, repo)
	}

	return metaTypes.RepoMetadata{}, nil
}

func (sdm MetaDBMock) SetRepoMeta(repo string, repoMeta metaTypes.RepoMetadata) error {
	if sdm.SetRepoMetaFn != nil {
		return sdm.SetRepoMetaFn(repo, repoMeta)
	}

	return nil
}

func (sdm MetaDBMock) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta metaTypes.RepoMetadata) bool,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, error) {
	if sdm.GetMultipleRepoMetaFn != nil {
		return sdm.GetMultipleRepoMetaFn(ctx, filter, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, nil
}

func (sdm MetaDBMock) GetManifestData(manifestDigest godigest.Digest) (metaTypes.ManifestData, error) {
	if sdm.GetManifestDataFn != nil {
		return sdm.GetManifestDataFn(manifestDigest)
	}

	return metaTypes.ManifestData{}, nil
}

func (sdm MetaDBMock) SetManifestData(manifestDigest godigest.Digest, md metaTypes.ManifestData) error {
	if sdm.SetManifestDataFn != nil {
		return sdm.SetManifestDataFn(manifestDigest, md)
	}

	return nil
}

func (sdm MetaDBMock) GetManifestMeta(repo string, manifestDigest godigest.Digest) (metaTypes.ManifestMetadata, error) {
	if sdm.GetManifestMetaFn != nil {
		return sdm.GetManifestMetaFn(repo, manifestDigest)
	}

	return metaTypes.ManifestMetadata{}, nil
}

func (sdm MetaDBMock) SetManifestMeta(repo string, manifestDigest godigest.Digest, mm metaTypes.ManifestMetadata,
) error {
	if sdm.SetManifestMetaFn != nil {
		return sdm.SetManifestMetaFn(repo, manifestDigest, mm)
	}

	return nil
}

func (sdm MetaDBMock) IncrementImageDownloads(repo string, reference string) error {
	if sdm.IncrementImageDownloadsFn != nil {
		return sdm.IncrementImageDownloadsFn(repo, reference)
	}

	return nil
}

func (sdm MetaDBMock) UpdateSignaturesValidity(repo string, manifestDigest godigest.Digest) error {
	if sdm.UpdateSignaturesValidityFn != nil {
		return sdm.UpdateSignaturesValidityFn(repo, manifestDigest)
	}

	return nil
}

func (sdm MetaDBMock) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sm metaTypes.SignatureMetadata,
) error {
	if sdm.AddManifestSignatureFn != nil {
		return sdm.AddManifestSignatureFn(repo, signedManifestDigest, sm)
	}

	return nil
}

func (sdm MetaDBMock) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sm metaTypes.SignatureMetadata,
) error {
	if sdm.DeleteSignatureFn != nil {
		return sdm.DeleteSignatureFn(repo, signedManifestDigest, sm)
	}

	return nil
}

func (sdm MetaDBMock) SearchRepos(ctx context.Context, searchText string, filter metaTypes.Filter,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
	error,
) {
	if sdm.SearchReposFn != nil {
		return sdm.SearchReposFn(ctx, searchText, filter, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{},
		map[string]metaTypes.IndexData{}, common.PageInfo{}, nil
}

func (sdm MetaDBMock) SearchTags(ctx context.Context, searchText string, filter metaTypes.Filter,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
	error,
) {
	if sdm.SearchTagsFn != nil {
		return sdm.SearchTagsFn(ctx, searchText, filter, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{},
		map[string]metaTypes.IndexData{}, common.PageInfo{}, nil
}

func (sdm MetaDBMock) FilterRepos(ctx context.Context, filter metaTypes.FilterRepoFunc,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
	error,
) {
	if sdm.FilterReposFn != nil {
		return sdm.FilterReposFn(ctx, filter, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{},
		map[string]metaTypes.IndexData{}, common.PageInfo{}, nil
}

func (sdm MetaDBMock) FilterTags(ctx context.Context, filter metaTypes.FilterFunc,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, common.PageInfo,
	error,
) {
	if sdm.FilterTagsFn != nil {
		return sdm.FilterTagsFn(ctx, filter, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{},
		map[string]metaTypes.IndexData{}, common.PageInfo{}, nil
}

func (sdm MetaDBMock) SearchDigests(ctx context.Context, searchText string, requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error) {
	if sdm.SearchDigestsFn != nil {
		return sdm.SearchDigestsFn(ctx, searchText, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, nil
}

func (sdm MetaDBMock) SearchLayers(ctx context.Context, searchText string, requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error) {
	if sdm.SearchLayersFn != nil {
		return sdm.SearchLayersFn(ctx, searchText, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, nil
}

func (sdm MetaDBMock) SearchForAscendantImages(ctx context.Context, searchText string,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error) {
	if sdm.SearchForAscendantImagesFn != nil {
		return sdm.SearchForAscendantImagesFn(ctx, searchText, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, nil
}

func (sdm MetaDBMock) SearchForDescendantImages(ctx context.Context, searchText string,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, error) {
	if sdm.SearchForDescendantImagesFn != nil {
		return sdm.SearchForDescendantImagesFn(ctx, searchText, requestedPage)
	}

	return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, nil
}

func (sdm MetaDBMock) SetIndexData(digest godigest.Digest, indexData metaTypes.IndexData) error {
	if sdm.SetIndexDataFn != nil {
		return sdm.SetIndexDataFn(digest, indexData)
	}

	return nil
}

func (sdm MetaDBMock) GetIndexData(indexDigest godigest.Digest) (metaTypes.IndexData, error) {
	if sdm.GetIndexDataFn != nil {
		return sdm.GetIndexDataFn(indexDigest)
	}

	return metaTypes.IndexData{}, nil
}

func (sdm MetaDBMock) PatchDB() error {
	if sdm.PatchDBFn != nil {
		return sdm.PatchDBFn()
	}

	return nil
}

func (sdm MetaDBMock) SetReferrer(repo string, referredDigest godigest.Digest, referrer metaTypes.ReferrerInfo) error {
	if sdm.SetReferrerFn != nil {
		return sdm.SetReferrerFn(repo, referredDigest, referrer)
	}

	return nil
}

func (sdm MetaDBMock) DeleteReferrer(repo string, referredDigest godigest.Digest,
	referrerDigest godigest.Digest,
) error {
	if sdm.DeleteReferrerFn != nil {
		return sdm.DeleteReferrerFn(repo, referredDigest, referrerDigest)
	}

	return nil
}

func (sdm MetaDBMock) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]metaTypes.ReferrerInfo, error) {
	if sdm.GetReferrersInfoFn != nil {
		return sdm.GetReferrersInfoFn(repo, referredDigest, artifactTypes)
	}

	return []metaTypes.ReferrerInfo{}, nil
}

func (sdm MetaDBMock) GetStarredRepos(ctx context.Context) ([]string, error) {
	if sdm.GetStarredReposFn != nil {
		return sdm.GetStarredReposFn(ctx)
	}

	return []string{}, nil
}

func (sdm MetaDBMock) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	if sdm.GetBookmarkedReposFn != nil {
		return sdm.GetBookmarkedReposFn(ctx)
	}

	return []string{}, nil
}

func (sdm MetaDBMock) ToggleStarRepo(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
	if sdm.ToggleStarRepoFn != nil {
		return sdm.ToggleStarRepoFn(ctx, repo)
	}

	return metaTypes.NotChanged, nil
}

func (sdm MetaDBMock) ToggleBookmarkRepo(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
	if sdm.ToggleBookmarkRepoFn != nil {
		return sdm.ToggleBookmarkRepoFn(ctx, repo)
	}

	return metaTypes.NotChanged, nil
}
