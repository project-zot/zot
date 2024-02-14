package ociutils

import (
	"context"
	"fmt"

	zerr "zotregistry.dev/zot/errors"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
	imageUtil "zotregistry.dev/zot/pkg/test/image-utils"
)

type RepoImage struct {
	imageUtil.Image
	Reference  string
	Statistics mTypes.DescriptorStatistics
}

type RepoMultiArchImage struct {
	imageUtil.MultiarchImage
	ImageStatistics map[mTypes.ImageDigest]mTypes.DescriptorStatistics
	Reference       string
}

type Repo struct {
	Name            string
	Images          []RepoImage
	MultiArchImages []RepoMultiArchImage
	Signatures      map[string]mTypes.ManifestSignatures
	Stars           int
	IsBookmarked    bool
	IsStarred       bool
}

func InitializeTestMetaDB(ctx context.Context, metaDB mTypes.MetaDB, repos ...Repo) (context.Context, error) {
	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("test")
	uacContext := context.WithValue(ctx, reqCtx.GetContextKey(), *uac)

	err := validateRepos(repos)
	if err != nil {
		return uacContext, err
	}

	for _, repo := range repos {
		statistics := map[string]mTypes.DescriptorStatistics{"": {}}

		for _, image := range repo.Images {
			err := metaDB.SetRepoReference(ctx, repo.Name, image.Reference, image.AsImageMeta())
			if err != nil {
				return uacContext, err
			}

			statistics[image.DigestStr()] = image.Statistics
		}

		for _, multiArch := range repo.MultiArchImages {
			for _, image := range multiArch.Images {
				err := metaDB.SetRepoReference(ctx, repo.Name, image.DigestStr(), image.AsImageMeta())
				if err != nil {
					return uacContext, err
				}

				statistics[image.DigestStr()] = multiArch.ImageStatistics[image.DigestStr()]
			}

			err := metaDB.SetRepoReference(ctx, repo.Name, multiArch.Reference, multiArch.AsImageMeta())
			if err != nil {
				return uacContext, err
			}

			statistics[multiArch.DigestStr()] = multiArch.ImageStatistics[multiArch.DigestStr()]
		}

		// Update repo metadata
		repoMeta, err := metaDB.GetRepoMeta(ctx, repo.Name)
		if err != nil {
			return uacContext, err
		}

		repoMeta.StarCount = repo.Stars
		repoMeta.IsStarred = repo.IsStarred
		repoMeta.IsBookmarked = repo.IsBookmarked

		// updateStatistics
		for key, value := range statistics {
			repoMeta.Statistics[key] = value
		}

		// update signatures?
		for key, value := range repo.Signatures {
			repoMeta.Signatures[key] = value
		}

		err = metaDB.SetRepoMeta(repo.Name, repoMeta)
		if err != nil {
			return uacContext, err
		}

		// User data is set after we create the repo
		if repo.IsBookmarked {
			_, err := metaDB.ToggleBookmarkRepo(uacContext, repo.Name)
			if err != nil {
				return uacContext, err
			}
		}

		if repo.IsStarred {
			_, err := metaDB.ToggleStarRepo(uacContext, repo.Name)
			if err != nil {
				return uacContext, err
			}
		}
	}

	return uacContext, nil
}

func validateRepos(repos []Repo) error {
	repoNames := map[string]struct{}{}

	for _, repo := range repos {
		if _, found := repoNames[repo.Name]; found {
			return fmt.Errorf("%w '%s'", zerr.ErrMultipleReposSameName, repo.Name)
		}

		repoNames[repo.Name] = struct{}{}
	}

	return nil
}

func GetFakeSignatureInfo(signatureDigest string) map[string][]mTypes.SignatureInfo {
	return map[string][]mTypes.SignatureInfo{
		"fake-signature": {
			{
				SignatureManifestDigest: signatureDigest,
				LayersInfo:              []mTypes.LayerInfo{},
			},
		},
	}
}
