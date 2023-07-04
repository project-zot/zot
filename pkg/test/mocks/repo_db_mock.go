package mocks

import (
	"context"

	godigest "github.com/opencontainers/go-digest"

	mTypes "zotregistry.io/zot/pkg/meta/types"
)

type MetaDBMock struct {
	SetRepoDescriptionFn func(repo, description string) error

	IncrementRepoStarsFn func(repo string) error

	DecrementRepoStarsFn func(repo string) error

	GetRepoStarsFn func(repo string) (int, error)

	SetRepoLogoFn func(repo string, logoPath string) error

	SetRepoReferenceFn func(repo string, Reference string, manifestDigest godigest.Digest, mediaType string) error

	DeleteRepoTagFn func(repo string, tag string) error

	GetRepoMetaFn func(repo string) (mTypes.RepoMetadata, error)

	GetUserRepoMetaFn func(ctx context.Context, repo string) (mTypes.RepoMetadata, error)

	SetRepoMetaFn func(repo string, repoMeta mTypes.RepoMetadata) error

	GetMultipleRepoMetaFn func(ctx context.Context, filter func(repoMeta mTypes.RepoMetadata) bool) (
		[]mTypes.RepoMetadata, error)

	GetManifestDataFn func(manifestDigest godigest.Digest) (mTypes.ManifestData, error)

	SetManifestDataFn func(manifestDigest godigest.Digest, mm mTypes.ManifestData) error

	GetManifestMetaFn func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error)

	SetManifestMetaFn func(repo string, manifestDigest godigest.Digest, mm mTypes.ManifestMetadata) error

	SetIndexDataFn func(digest godigest.Digest, indexData mTypes.IndexData) error

	GetIndexDataFn func(indexDigest godigest.Digest) (mTypes.IndexData, error)

	SetReferrerFn func(repo string, referredDigest godigest.Digest, referrer mTypes.ReferrerInfo) error

	DeleteReferrerFn func(repo string, referredDigest godigest.Digest, referrerDigest godigest.Digest) error

	GetReferrersFn func(repo string, referredDigest godigest.Digest) ([]mTypes.Descriptor, error)

	GetReferrersInfoFn func(repo string, referredDigest godigest.Digest, artifactTypes []string) (
		[]mTypes.ReferrerInfo, error)

	IncrementImageDownloadsFn func(repo string, reference string) error

	UpdateSignaturesValidityFn func(repo string, manifestDigest godigest.Digest) error

	AddManifestSignatureFn func(repo string, signedManifestDigest godigest.Digest, sm mTypes.SignatureMetadata) error

	DeleteSignatureFn func(repo string, signedManifestDigest godigest.Digest, sm mTypes.SignatureMetadata) error

	SearchReposFn func(ctx context.Context, txt string) (
		[]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
		error)

	SearchTagsFn func(ctx context.Context, txt string) (
		[]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData,
		error)

	FilterReposFn func(ctx context.Context, filter mTypes.FilterRepoFunc) (
		[]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error)

	FilterTagsFn func(ctx context.Context, filterFunc mTypes.FilterFunc) (
		[]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error)

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

	AddUserAPIKeyFn func(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error

	UpdateUserAPIKeyLastUsedFn func(ctx context.Context, hashedKey string) error

	DeleteUserAPIKeyFn func(ctx context.Context, id string) error

	PatchDBFn func() error

	SignatureStorageFn func() mTypes.SignatureStorage
}

func (sdm MetaDBMock) SignatureStorage() mTypes.SignatureStorage {
	if sdm.SignatureStorageFn != nil {
		return sdm.SignatureStorageFn()
	}

	return nil
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

func (sdm MetaDBMock) GetRepoMeta(repo string) (mTypes.RepoMetadata, error) {
	if sdm.GetRepoMetaFn != nil {
		return sdm.GetRepoMetaFn(repo)
	}

	return mTypes.RepoMetadata{}, nil
}

func (sdm MetaDBMock) GetUserRepoMeta(ctx context.Context, repo string) (mTypes.RepoMetadata, error) {
	if sdm.GetUserRepoMetaFn != nil {
		return sdm.GetUserRepoMetaFn(ctx, repo)
	}

	return mTypes.RepoMetadata{}, nil
}

func (sdm MetaDBMock) SetRepoMeta(repo string, repoMeta mTypes.RepoMetadata) error {
	if sdm.SetRepoMetaFn != nil {
		return sdm.SetRepoMetaFn(repo, repoMeta)
	}

	return nil
}

func (sdm MetaDBMock) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMetadata) bool,
) ([]mTypes.RepoMetadata, error) {
	if sdm.GetMultipleRepoMetaFn != nil {
		return sdm.GetMultipleRepoMetaFn(ctx, filter)
	}

	return []mTypes.RepoMetadata{}, nil
}

func (sdm MetaDBMock) GetManifestData(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
	if sdm.GetManifestDataFn != nil {
		return sdm.GetManifestDataFn(manifestDigest)
	}

	return mTypes.ManifestData{}, nil
}

func (sdm MetaDBMock) SetManifestData(manifestDigest godigest.Digest, md mTypes.ManifestData) error {
	if sdm.SetManifestDataFn != nil {
		return sdm.SetManifestDataFn(manifestDigest, md)
	}

	return nil
}

func (sdm MetaDBMock) GetManifestMeta(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
	if sdm.GetManifestMetaFn != nil {
		return sdm.GetManifestMetaFn(repo, manifestDigest)
	}

	return mTypes.ManifestMetadata{}, nil
}

func (sdm MetaDBMock) SetManifestMeta(repo string, manifestDigest godigest.Digest, mm mTypes.ManifestMetadata) error {
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
	sm mTypes.SignatureMetadata,
) error {
	if sdm.AddManifestSignatureFn != nil {
		return sdm.AddManifestSignatureFn(repo, signedManifestDigest, sm)
	}

	return nil
}

func (sdm MetaDBMock) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sm mTypes.SignatureMetadata,
) error {
	if sdm.DeleteSignatureFn != nil {
		return sdm.DeleteSignatureFn(repo, signedManifestDigest, sm)
	}

	return nil
}

func (sdm MetaDBMock) SearchRepos(ctx context.Context, searchText string,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	if sdm.SearchReposFn != nil {
		return sdm.SearchReposFn(ctx, searchText)
	}

	return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{},
		map[string]mTypes.IndexData{}, nil
}

func (sdm MetaDBMock) SearchTags(ctx context.Context, searchText string,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	if sdm.SearchTagsFn != nil {
		return sdm.SearchTagsFn(ctx, searchText)
	}

	return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{},
		map[string]mTypes.IndexData{}, nil
}

func (sdm MetaDBMock) FilterRepos(ctx context.Context, filter mTypes.FilterRepoFunc,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	if sdm.FilterReposFn != nil {
		return sdm.FilterReposFn(ctx, filter)
	}

	return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{},
		map[string]mTypes.IndexData{}, nil
}

func (sdm MetaDBMock) FilterTags(ctx context.Context, filterFunc mTypes.FilterFunc,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	if sdm.FilterTagsFn != nil {
		return sdm.FilterTagsFn(ctx, filterFunc)
	}

	return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{},
		map[string]mTypes.IndexData{}, nil
}

func (sdm MetaDBMock) SetIndexData(digest godigest.Digest, indexData mTypes.IndexData) error {
	if sdm.SetIndexDataFn != nil {
		return sdm.SetIndexDataFn(digest, indexData)
	}

	return nil
}

func (sdm MetaDBMock) GetIndexData(indexDigest godigest.Digest) (mTypes.IndexData, error) {
	if sdm.GetIndexDataFn != nil {
		return sdm.GetIndexDataFn(indexDigest)
	}

	return mTypes.IndexData{}, nil
}

func (sdm MetaDBMock) PatchDB() error {
	if sdm.PatchDBFn != nil {
		return sdm.PatchDBFn()
	}

	return nil
}

func (sdm MetaDBMock) SetReferrer(repo string, referredDigest godigest.Digest, referrer mTypes.ReferrerInfo) error {
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
) ([]mTypes.ReferrerInfo, error) {
	if sdm.GetReferrersInfoFn != nil {
		return sdm.GetReferrersInfoFn(repo, referredDigest, artifactTypes)
	}

	return []mTypes.ReferrerInfo{}, nil
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
