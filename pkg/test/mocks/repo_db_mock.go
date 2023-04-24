package mocks

import (
	"context"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/meta/repodb"
)

type RepoDBMock struct {
	SetRepoDescriptionFn func(repo, description string) error

	IncrementRepoStarsFn func(repo string) error

	DecrementRepoStarsFn func(repo string) error

	GetRepoStarsFn func(repo string) (int, error)

	SetRepoLogoFn func(repo string, logoPath string) error

	SetRepoReferenceFn func(repo string, Reference string, manifestDigest godigest.Digest, mediaType string) error

	DeleteRepoTagFn func(repo string, tag string) error

	GetRepoMetaFn func(repo string) (repodb.RepoMetadata, error)

	SetRepoMetaFn func(repo string, repoMeta repodb.RepoMetadata) error

	GetMultipleRepoMetaFn func(ctx context.Context, filter func(repoMeta repodb.RepoMetadata) bool,
		requestedPage repodb.PageInput) ([]repodb.RepoMetadata, error)

	GetManifestDataFn func(manifestDigest godigest.Digest) (repodb.ManifestData, error)

	SetManifestDataFn func(manifestDigest godigest.Digest, mm repodb.ManifestData) error

	GetManifestMetaFn func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error)

	SetManifestMetaFn func(repo string, manifestDigest godigest.Digest, mm repodb.ManifestMetadata) error

	SetIndexDataFn func(digest godigest.Digest, indexData repodb.IndexData) error

	GetIndexDataFn func(indexDigest godigest.Digest) (repodb.IndexData, error)

	SetArtifactDataFn func(digest godigest.Digest, artifactData repodb.ArtifactData) error

	GetArtifactDataFn func(artifactDigest godigest.Digest) (repodb.ArtifactData, error)

	SetReferrerFn func(repo string, referredDigest godigest.Digest, referrer repodb.ReferrerInfo) error

	DeleteReferrerFn func(repo string, referredDigest godigest.Digest, referrerDigest godigest.Digest) error

	GetReferrersFn func(repo string, referredDigest godigest.Digest) ([]repodb.Descriptor, error)

	GetReferrersInfoFn func(repo string, referredDigest godigest.Digest, artifactTypes []string) (
		[]repodb.ReferrerInfo, error)

	IncrementImageDownloadsFn func(repo string, reference string) error

	AddManifestSignatureFn func(repo string, signedManifestDigest godigest.Digest, sm repodb.SignatureMetadata) error

	DeleteSignatureFn func(repo string, signedManifestDigest godigest.Digest, sm repodb.SignatureMetadata) error

	SearchReposFn func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error)

	SearchTagsFn func(ctx context.Context, searchText string, filter repodb.Filter, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error)

	FilterReposFn func(ctx context.Context, filter repodb.FilterRepoFunc, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error)

	FilterTagsFn func(ctx context.Context, filter repodb.FilterFunc,
		requestedPage repodb.PageInput,
	) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error)

	SearchDigestsFn func(ctx context.Context, searchText string, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error)

	SearchLayersFn func(ctx context.Context, searchText string, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error)

	SearchForAscendantImagesFn func(ctx context.Context, searchText string, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error)

	SearchForDescendantImagesFn func(ctx context.Context, searchText string, requestedPage repodb.PageInput) (
		[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error)

	GetStarredReposFn func(ctx context.Context) ([]string, error)

	GetBookmarkedReposFn func(ctx context.Context) ([]string, error)

	ToggleStarRepoFn func(ctx context.Context, repo string) (repodb.ToggleState, error)

	ToggleBookmarkRepoFn func(ctx context.Context, repo string) (repodb.ToggleState, error)

	PatchDBFn func() error
}

func (sdm RepoDBMock) SetRepoDescription(repo, description string) error {
	if sdm.SetRepoDescriptionFn != nil {
		return sdm.SetRepoDescriptionFn(repo, description)
	}

	return nil
}

func (sdm RepoDBMock) IncrementRepoStars(repo string) error {
	if sdm.IncrementRepoStarsFn != nil {
		return sdm.IncrementRepoStarsFn(repo)
	}

	return nil
}

func (sdm RepoDBMock) DecrementRepoStars(repo string) error {
	if sdm.DecrementRepoStarsFn != nil {
		return sdm.DecrementRepoStarsFn(repo)
	}

	return nil
}

func (sdm RepoDBMock) GetRepoStars(repo string) (int, error) {
	if sdm.GetRepoStarsFn != nil {
		return sdm.GetRepoStarsFn(repo)
	}

	return 0, nil
}

func (sdm RepoDBMock) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if sdm.SetRepoReferenceFn != nil {
		return sdm.SetRepoReferenceFn(repo, reference, manifestDigest, mediaType)
	}

	return nil
}

func (sdm RepoDBMock) DeleteRepoTag(repo string, tag string) error {
	if sdm.DeleteRepoTagFn != nil {
		return sdm.DeleteRepoTagFn(repo, tag)
	}

	return nil
}

func (sdm RepoDBMock) GetRepoMeta(repo string) (repodb.RepoMetadata, error) {
	if sdm.GetRepoMetaFn != nil {
		return sdm.GetRepoMetaFn(repo)
	}

	return repodb.RepoMetadata{}, nil
}

func (sdm RepoDBMock) SetRepoMeta(repo string, repoMeta repodb.RepoMetadata) error {
	if sdm.SetRepoMetaFn != nil {
		return sdm.SetRepoMetaFn(repo, repoMeta)
	}

	return nil
}

func (sdm RepoDBMock) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta repodb.RepoMetadata) bool,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, error) {
	if sdm.GetMultipleRepoMetaFn != nil {
		return sdm.GetMultipleRepoMetaFn(ctx, filter, requestedPage)
	}

	return []repodb.RepoMetadata{}, nil
}

func (sdm RepoDBMock) GetManifestData(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
	if sdm.GetManifestDataFn != nil {
		return sdm.GetManifestDataFn(manifestDigest)
	}

	return repodb.ManifestData{}, nil
}

func (sdm RepoDBMock) SetManifestData(manifestDigest godigest.Digest, md repodb.ManifestData) error {
	if sdm.SetManifestDataFn != nil {
		return sdm.SetManifestDataFn(manifestDigest, md)
	}

	return nil
}

func (sdm RepoDBMock) GetManifestMeta(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
	if sdm.GetManifestMetaFn != nil {
		return sdm.GetManifestMetaFn(repo, manifestDigest)
	}

	return repodb.ManifestMetadata{}, nil
}

func (sdm RepoDBMock) SetManifestMeta(repo string, manifestDigest godigest.Digest, mm repodb.ManifestMetadata) error {
	if sdm.SetManifestMetaFn != nil {
		return sdm.SetManifestMetaFn(repo, manifestDigest, mm)
	}

	return nil
}

func (sdm RepoDBMock) IncrementImageDownloads(repo string, reference string) error {
	if sdm.IncrementImageDownloadsFn != nil {
		return sdm.IncrementImageDownloadsFn(repo, reference)
	}

	return nil
}

func (sdm RepoDBMock) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sm repodb.SignatureMetadata,
) error {
	if sdm.AddManifestSignatureFn != nil {
		return sdm.AddManifestSignatureFn(repo, signedManifestDigest, sm)
	}

	return nil
}

func (sdm RepoDBMock) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sm repodb.SignatureMetadata,
) error {
	if sdm.DeleteSignatureFn != nil {
		return sdm.DeleteSignatureFn(repo, signedManifestDigest, sm)
	}

	return nil
}

func (sdm RepoDBMock) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	if sdm.SearchReposFn != nil {
		return sdm.SearchReposFn(ctx, searchText, filter, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
		map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
}

func (sdm RepoDBMock) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	if sdm.SearchTagsFn != nil {
		return sdm.SearchTagsFn(ctx, searchText, filter, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
		map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
}

func (sdm RepoDBMock) FilterRepos(ctx context.Context, filter repodb.FilterRepoFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	if sdm.FilterReposFn != nil {
		return sdm.FilterReposFn(ctx, filter, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
		map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
}

func (sdm RepoDBMock) FilterTags(ctx context.Context, filter repodb.FilterFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	if sdm.FilterTagsFn != nil {
		return sdm.FilterTagsFn(ctx, filter, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
		map[string]repodb.IndexData{}, repodb.PageInfo{}, nil
}

func (sdm RepoDBMock) SearchDigests(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	if sdm.SearchDigestsFn != nil {
		return sdm.SearchDigestsFn(ctx, searchText, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, nil
}

func (sdm RepoDBMock) SearchLayers(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	if sdm.SearchLayersFn != nil {
		return sdm.SearchLayersFn(ctx, searchText, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, nil
}

func (sdm RepoDBMock) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	if sdm.SearchForAscendantImagesFn != nil {
		return sdm.SearchForAscendantImagesFn(ctx, searchText, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, nil
}

func (sdm RepoDBMock) SearchForDescendantImages(ctx context.Context, searchText string,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	if sdm.SearchForDescendantImagesFn != nil {
		return sdm.SearchForDescendantImagesFn(ctx, searchText, requestedPage)
	}

	return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, nil
}

func (sdm RepoDBMock) SetIndexData(digest godigest.Digest, indexData repodb.IndexData) error {
	if sdm.SetIndexDataFn != nil {
		return sdm.SetIndexDataFn(digest, indexData)
	}

	return nil
}

func (sdm RepoDBMock) GetIndexData(indexDigest godigest.Digest) (repodb.IndexData, error) {
	if sdm.GetIndexDataFn != nil {
		return sdm.GetIndexDataFn(indexDigest)
	}

	return repodb.IndexData{}, nil
}

func (sdm RepoDBMock) PatchDB() error {
	if sdm.PatchDBFn != nil {
		return sdm.PatchDBFn()
	}

	return nil
}

func (sdm RepoDBMock) SetArtifactData(digest godigest.Digest, artifactData repodb.ArtifactData) error {
	if sdm.SetArtifactDataFn != nil {
		return sdm.SetArtifactDataFn(digest, artifactData)
	}

	return nil
}

func (sdm RepoDBMock) GetArtifactData(artifactDigest godigest.Digest) (repodb.ArtifactData, error) {
	if sdm.GetArtifactDataFn != nil {
		return sdm.GetArtifactDataFn(artifactDigest)
	}

	return repodb.ArtifactData{}, nil
}

func (sdm RepoDBMock) SetReferrer(repo string, referredDigest godigest.Digest, referrer repodb.ReferrerInfo) error {
	if sdm.SetReferrerFn != nil {
		return sdm.SetReferrerFn(repo, referredDigest, referrer)
	}

	return nil
}

func (sdm RepoDBMock) DeleteReferrer(repo string, referredDigest godigest.Digest,
	referrerDigest godigest.Digest,
) error {
	if sdm.DeleteReferrerFn != nil {
		return sdm.DeleteReferrerFn(repo, referredDigest, referrerDigest)
	}

	return nil
}

func (sdm RepoDBMock) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]repodb.ReferrerInfo, error) {
	if sdm.GetReferrersInfoFn != nil {
		return sdm.GetReferrersInfoFn(repo, referredDigest, artifactTypes)
	}

	return []repodb.ReferrerInfo{}, nil
}

func (sdm RepoDBMock) GetStarredRepos(ctx context.Context) ([]string, error) {
	if sdm.GetStarredReposFn != nil {
		return sdm.GetStarredReposFn(ctx)
	}

	return []string{}, nil
}

func (sdm RepoDBMock) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	if sdm.GetBookmarkedReposFn != nil {
		return sdm.GetBookmarkedReposFn(ctx)
	}

	return []string{}, nil
}

func (sdm RepoDBMock) ToggleStarRepo(ctx context.Context, repo string) (repodb.ToggleState, error) {
	if sdm.ToggleStarRepoFn != nil {
		return sdm.ToggleStarRepoFn(ctx, repo)
	}

	return repodb.NotChanged, nil
}

func (sdm RepoDBMock) ToggleBookmarkRepo(ctx context.Context, repo string) (repodb.ToggleState, error) {
	if sdm.ToggleBookmarkRepoFn != nil {
		return sdm.ToggleBookmarkRepoFn(ctx, repo)
	}

	return repodb.NotChanged, nil
}
