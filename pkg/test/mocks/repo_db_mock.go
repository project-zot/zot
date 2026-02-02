package mocks

import (
	"context"
	"time"

	godigest "github.com/opencontainers/go-digest"

	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

type MetaDBMock struct {
	DeleteRepoMetaFn func(repo string) error

	GetRepoLastUpdatedFn func(repo string) time.Time

	GetStarredReposFn func(ctx context.Context) ([]string, error)

	GetBookmarkedReposFn func(ctx context.Context) ([]string, error)

	ToggleStarRepoFn func(ctx context.Context, repo string) (mTypes.ToggleState, error)

	ToggleBookmarkRepoFn func(ctx context.Context, repo string) (mTypes.ToggleState, error)

	GetUserDataFn func(ctx context.Context) (mTypes.UserData, error)

	SetUserDataFn func(ctx context.Context, userProfile mTypes.UserData) error

	SetUserGroupsFn func(ctx context.Context, groups []string) error

	GetUserGroupsFn func(ctx context.Context) ([]string, error)

	DeleteUserDataFn func(ctx context.Context) error

	GetUserAPIKeyInfoFn func(hashedKey string) (string, error)

	IsAPIKeyExpiredFn func(ctx context.Context, hashedKey string) (bool, error)

	GetUserAPIKeysFn func(ctx context.Context) ([]mTypes.APIKeyDetails, error)

	AddUserAPIKeyFn func(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error

	UpdateUserAPIKeyLastUsedFn func(ctx context.Context, hashedKey string) error

	DeleteUserAPIKeyFn func(ctx context.Context, id string) error

	PatchDBFn func() error

	ImageTrustStoreFn func() mTypes.ImageTrustStore

	SetImageTrustStoreFn func(mTypes.ImageTrustStore)

	SetRepoReferenceFn func(ctx context.Context, repo string, reference string, imageMeta mTypes.ImageMeta) error

	SearchReposFn func(ctx context.Context, searchText string,
	) ([]mTypes.RepoMeta, error)

	SearchTagsFn func(ctx context.Context, searchText string) ([]mTypes.FullImageMeta, error)

	GetImageMetaFn func(digest godigest.Digest) (mTypes.ImageMeta, error)

	GetMultipleRepoMetaFn func(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
	) ([]mTypes.RepoMeta, error)

	FilterReposFn func(ctx context.Context, rankName mTypes.FilterRepoNameFunc,
		filterFunc mTypes.FilterFullRepoFunc) ([]mTypes.RepoMeta, error)

	IncrementRepoStarsFn func(repo string) error

	DecrementRepoStarsFn func(repo string) error

	SetRepoMetaFn func(repo string, repoMeta mTypes.RepoMeta) error

	DeleteReferrerFn func(repo string, referredDigest godigest.Digest, referrerDigest godigest.Digest) error

	GetReferrersInfoFn func(repo string, referredDigest godigest.Digest, artifactTypes []string,
	) ([]mTypes.ReferrerInfo, error)

	UpdateStatsOnDownloadFn func(repo string, reference string) error

	UpdateSignaturesValidityFn func(ctx context.Context, crepo string, manifestDigest godigest.Digest) error

	AddManifestSignatureFn func(repo string, signedManifestDigest godigest.Digest, sygMeta mTypes.SignatureMetadata,
	) error

	DeleteSignatureFn func(repo string, signedManifestDigest godigest.Digest, sigMeta mTypes.SignatureMetadata) error

	SetImageMetaFn func(digest godigest.Digest, imageMeta mTypes.ImageMeta) error

	FilterTagsFn func(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
		filterFunc mTypes.FilterFunc) ([]mTypes.FullImageMeta, error)

	GetRepoMetaFn func(ctx context.Context, repo string) (mTypes.RepoMeta, error)

	FilterImageMetaFn func(ctx context.Context, digests []string) (map[string]mTypes.ImageMeta, error)

	RemoveRepoReferenceFn func(repo, reference string, manifestDigest godigest.Digest) error

	GetFullImageMetaFn func(ctx context.Context, repo string, tag string) (mTypes.FullImageMeta, error)

	ResetRepoReferencesFn func(repo string, tagsToKeep map[string]bool) error

	GetAllRepoNamesFn func() ([]string, error)

	ResetDBFn func() error

	CloseFn func() error
}

func (sdm MetaDBMock) DeleteRepoMeta(repo string) error {
	if sdm.DeleteRepoMetaFn != nil {
		return sdm.DeleteRepoMetaFn(repo)
	}

	return nil
}

func (sdm MetaDBMock) GetAllRepoNames() ([]string, error) {
	if sdm.GetAllRepoNamesFn != nil {
		return sdm.GetAllRepoNamesFn()
	}

	return []string{}, nil
}

func (sdm MetaDBMock) GetRepoLastUpdated(repo string) time.Time {
	if sdm.GetRepoLastUpdatedFn != nil {
		return sdm.GetRepoLastUpdatedFn(repo)
	}

	return time.Time{}
}

func (sdm MetaDBMock) ResetDB() error {
	if sdm.ResetDBFn != nil {
		return sdm.ResetDBFn()
	}

	return nil
}

func (sdm MetaDBMock) ImageTrustStore() mTypes.ImageTrustStore {
	if sdm.ImageTrustStoreFn != nil {
		return sdm.ImageTrustStoreFn()
	}

	return nil
}

func (sdm MetaDBMock) SetImageTrustStore(imgTrustStore mTypes.ImageTrustStore) {
	if sdm.SetImageTrustStoreFn != nil {
		sdm.SetImageTrustStoreFn(imgTrustStore)
	}
}

func (sdm MetaDBMock) PatchDB() error {
	if sdm.PatchDBFn != nil {
		return sdm.PatchDBFn()
	}

	return nil
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

func (sdm MetaDBMock) ToggleStarRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	if sdm.ToggleStarRepoFn != nil {
		return sdm.ToggleStarRepoFn(ctx, repo)
	}

	return mTypes.NotChanged, nil
}

func (sdm MetaDBMock) ToggleBookmarkRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	if sdm.ToggleBookmarkRepoFn != nil {
		return sdm.ToggleBookmarkRepoFn(ctx, repo)
	}

	return mTypes.NotChanged, nil
}

func (sdm MetaDBMock) GetUserData(ctx context.Context) (mTypes.UserData, error) {
	if sdm.GetUserDataFn != nil {
		return sdm.GetUserDataFn(ctx)
	}

	return mTypes.UserData{}, nil
}

func (sdm MetaDBMock) SetUserData(ctx context.Context, userProfile mTypes.UserData) error {
	if sdm.SetUserDataFn != nil {
		return sdm.SetUserDataFn(ctx, userProfile)
	}

	return nil
}

func (sdm MetaDBMock) SetUserGroups(ctx context.Context, groups []string) error {
	if sdm.SetUserGroupsFn != nil {
		return sdm.SetUserGroupsFn(ctx, groups)
	}

	return nil
}

func (sdm MetaDBMock) GetUserGroups(ctx context.Context) ([]string, error) {
	if sdm.GetUserGroupsFn != nil {
		return sdm.GetUserGroupsFn(ctx)
	}

	return []string{}, nil
}

func (sdm MetaDBMock) DeleteUserData(ctx context.Context) error {
	if sdm.DeleteUserDataFn != nil {
		return sdm.DeleteUserDataFn(ctx)
	}

	return nil
}

func (sdm MetaDBMock) GetUserAPIKeyInfo(hashedKey string) (string, error) {
	if sdm.GetUserAPIKeyInfoFn != nil {
		return sdm.GetUserAPIKeyInfoFn(hashedKey)
	}

	return "", nil
}

func (sdm MetaDBMock) IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error) {
	if sdm.IsAPIKeyExpiredFn != nil {
		return sdm.IsAPIKeyExpiredFn(ctx, hashedKey)
	}

	return false, nil
}

func (sdm MetaDBMock) GetUserAPIKeys(ctx context.Context) ([]mTypes.APIKeyDetails, error) {
	if sdm.GetUserAPIKeysFn != nil {
		return sdm.GetUserAPIKeysFn(ctx)
	}

	return nil, nil //nolint:nilnil
}

func (sdm MetaDBMock) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	if sdm.AddUserAPIKeyFn != nil {
		return sdm.AddUserAPIKeyFn(ctx, hashedKey, apiKeyDetails)
	}

	return nil
}

func (sdm MetaDBMock) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	if sdm.UpdateUserAPIKeyLastUsedFn != nil {
		return sdm.UpdateUserAPIKeyLastUsedFn(ctx, hashedKey)
	}

	return nil
}

func (sdm MetaDBMock) DeleteUserAPIKey(ctx context.Context, id string) error {
	if sdm.DeleteUserAPIKeyFn != nil {
		return sdm.DeleteUserAPIKeyFn(ctx, id)
	}

	return nil
}

func (sdm MetaDBMock) SetImageMeta(digest godigest.Digest, imageMeta mTypes.ImageMeta) error {
	if sdm.SetImageMetaFn != nil {
		return sdm.SetImageMetaFn(digest, imageMeta)
	}

	return nil
}

func (sdm MetaDBMock) SetRepoReference(ctx context.Context, repo string, reference string,
	imageMeta mTypes.ImageMeta,
) error {
	if sdm.SetRepoReferenceFn != nil {
		return sdm.SetRepoReferenceFn(ctx, repo, reference, imageMeta)
	}

	return nil
}

func (sdm MetaDBMock) SearchRepos(ctx context.Context, searchText string) ([]mTypes.RepoMeta, error) {
	if sdm.SearchReposFn != nil {
		return sdm.SearchReposFn(ctx, searchText)
	}

	return []mTypes.RepoMeta{}, nil
}

func (sdm MetaDBMock) SearchTags(ctx context.Context, searchText string) ([]mTypes.FullImageMeta, error) {
	if sdm.SearchTagsFn != nil {
		return sdm.SearchTagsFn(ctx, searchText)
	}

	return []mTypes.FullImageMeta{}, nil
}

func (sdm MetaDBMock) FilterTags(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
	filterFunc mTypes.FilterFunc,
) ([]mTypes.FullImageMeta, error) {
	if sdm.FilterTagsFn != nil {
		return sdm.FilterTagsFn(ctx, filterRepoTag, filterFunc)
	}

	return []mTypes.FullImageMeta{}, nil
}

func (sdm MetaDBMock) GetRepoMeta(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
	if sdm.GetRepoMetaFn != nil {
		return sdm.GetRepoMetaFn(ctx, repo)
	}

	return mTypes.RepoMeta{}, nil
}

func (sdm MetaDBMock) GetImageMeta(digest godigest.Digest) (mTypes.ImageMeta, error) {
	if sdm.GetImageMetaFn != nil {
		return sdm.GetImageMetaFn(digest)
	}

	return mTypes.ImageMeta{}, nil
}

func (sdm MetaDBMock) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
) ([]mTypes.RepoMeta, error) {
	if sdm.GetMultipleRepoMetaFn != nil {
		return sdm.GetMultipleRepoMetaFn(ctx, filter)
	}

	return []mTypes.RepoMeta{}, nil
}

func (sdm MetaDBMock) FilterRepos(ctx context.Context, rankName mTypes.FilterRepoNameFunc,
	filterFunc mTypes.FilterFullRepoFunc,
) ([]mTypes.RepoMeta, error) {
	if sdm.FilterReposFn != nil {
		return sdm.FilterReposFn(ctx, rankName, filterFunc)
	}

	return []mTypes.RepoMeta{}, nil
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

func (sdm MetaDBMock) SetRepoMeta(repo string, repoMeta mTypes.RepoMeta) error {
	if sdm.SetRepoMetaFn != nil {
		return sdm.SetRepoMetaFn(repo, repoMeta)
	}

	return nil
}

func (sdm MetaDBMock) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	if sdm.GetReferrersInfoFn != nil {
		return sdm.GetReferrersInfoFn(repo, referredDigest, artifactTypes)
	}

	return []mTypes.ReferrerInfo{}, nil
}

func (sdm MetaDBMock) UpdateStatsOnDownload(repo string, reference string) error {
	if sdm.UpdateStatsOnDownloadFn != nil {
		return sdm.UpdateStatsOnDownloadFn(repo, reference)
	}

	return nil
}

func (sdm MetaDBMock) UpdateSignaturesValidity(ctx context.Context, repo string, manifestDigest godigest.Digest) error {
	if sdm.UpdateSignaturesValidityFn != nil {
		return sdm.UpdateSignaturesValidityFn(ctx, repo, manifestDigest)
	}

	return nil
}

func (sdm MetaDBMock) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta mTypes.SignatureMetadata,
) error {
	if sdm.AddManifestSignatureFn != nil {
		return sdm.AddManifestSignatureFn(repo, signedManifestDigest, sygMeta)
	}

	return nil
}

func (sdm MetaDBMock) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	if sdm.DeleteSignatureFn != nil {
		return sdm.DeleteSignatureFn(repo, signedManifestDigest, sigMeta)
	}

	return nil
}

func (sdm MetaDBMock) FilterImageMeta(ctx context.Context, digests []string,
) (map[string]mTypes.ImageMeta, error) {
	if sdm.FilterImageMetaFn != nil {
		return sdm.FilterImageMetaFn(ctx, digests)
	}

	return map[string]mTypes.ImageMeta{}, nil
}

func (sdm MetaDBMock) RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest) error {
	if sdm.RemoveRepoReferenceFn != nil {
		return sdm.RemoveRepoReferenceFn(repo, reference, manifestDigest)
	}

	return nil
}

func (sdm MetaDBMock) GetFullImageMeta(ctx context.Context, repo string, tag string,
) (mTypes.FullImageMeta, error) {
	if sdm.GetFullImageMetaFn != nil {
		return sdm.GetFullImageMetaFn(ctx, repo, tag)
	}

	return mTypes.FullImageMeta{}, nil
}

func (sdm MetaDBMock) ResetRepoReferences(repo string, tagsToKeep map[string]bool) error {
	if sdm.ResetRepoReferencesFn != nil {
		return sdm.ResetRepoReferencesFn(repo, tagsToKeep)
	}

	return nil
}

func (sdm MetaDBMock) Close() error {
	if sdm.CloseFn != nil {
		return sdm.CloseFn()
	}

	return nil
}
