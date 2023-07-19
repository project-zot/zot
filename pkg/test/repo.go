package test

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	mTypes "zotregistry.io/zot/pkg/meta/types"
)

type RepoImage struct {
	Image
	Tag string
}

type RepoMultiArchImage struct {
	MultiarchImage
	Tag string
}

type Repo struct {
	Name            string
	Images          []RepoImage
	MultiArchImages []RepoMultiArchImage
	IsBookmarked    bool
	IsStarred       bool
}

func GetMetadataForRepos(repos ...Repo) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata,
	map[string]mTypes.IndexData,
) {
	var (
		reposMetadata       = []mTypes.RepoMetadata{}
		manifestMetadataMap = map[string]mTypes.ManifestMetadata{}
		indexDataMap        = map[string]mTypes.IndexData{}
	)

	for _, repo := range repos {
		repoMeta := mTypes.RepoMetadata{
			Name:         repo.Name,
			Tags:         map[string]mTypes.Descriptor{},
			Signatures:   map[string]mTypes.ManifestSignatures{},
			IsStarred:    repo.IsStarred,
			IsBookmarked: repo.IsBookmarked,
		}

		for _, image := range repo.Images {
			if image.Tag != "" {
				repoMeta.Tags[image.Tag] = mTypes.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    image.DigestStr(),
				}
			}
			// here we can do many more checks about the images like check for referrers, signatures but it's not needed yet
			// I need just the tags for now and the fake signature.

			// This is done just to mark a manifest as signed in the resulted RepoMeta
			if image.Manifest.ArtifactType == TestFakeSignatureArtType && image.Manifest.Subject != nil {
				signedManifestDig := image.Manifest.Subject.Digest.String()
				repoMeta.Signatures[signedManifestDig] = mTypes.ManifestSignatures{
					"fakeSignature": []mTypes.SignatureInfo{{SignatureManifestDigest: image.ManifestDescriptor.Digest.String()}},
				}
			}

			manifestMetadataMap[image.ManifestDescriptor.Digest.String()] = mTypes.ManifestMetadata{
				ManifestBlob: image.ManifestDescriptor.Data,
				ConfigBlob:   image.ConfigDescriptor.Data,
			}
		}

		for _, multiArch := range repo.MultiArchImages {
			repoMeta.Tags[multiArch.Tag] = mTypes.Descriptor{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    multiArch.DigestStr(),
			}

			for _, image := range multiArch.Images {
				manifestMetadataMap[image.ManifestDescriptor.Digest.String()] = mTypes.ManifestMetadata{
					ManifestBlob: image.ManifestDescriptor.Data,
					ConfigBlob:   image.ConfigDescriptor.Data,
				}
			}

			indexDataMap[multiArch.indexDescriptor.Digest.String()] = mTypes.IndexData{
				IndexBlob: multiArch.indexDescriptor.Data,
			}
		}

		reposMetadata = append(reposMetadata, repoMeta)
	}

	return reposMetadata, manifestMetadataMap, indexDataMap
}
